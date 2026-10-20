# Building a Production-Grade Detection Engineering Lab: From Threat Intel to CI/CD & Purple-Team Hardening

*Published on Oct 19, 2026 · By Omar Riadd · 10 min read*

---

## Introduction: Why Most Detections Fail in the Real World

If you work in a Security Operations Center (SOC), you are likely familiar with the two extremes of detection engineering:
1. **The Alarm That Never Stops:** A rule written so broadly that it fires thousands of times a day on SCCM scans, developers running curl, or IT update scripts—until an analyst eventually silences it.
2. **The Fragile Regex:** A rule written to catch a specific malware filename like `mimikatz.exe` or `beacon.ps1`. The attacker renames the file to `svchost.exe`, and the entire security stack is blind.

When I set out to build an end-to-end Detection Engineering portfolio, my goal was to avoid theoretical exercises and build an enterprise-grade, **threat-informed Detection-as-Code (DaC)** lifecycle. Grounded in CISA advisories (**AA21-116A** for Active Directory intrusions and **AA23-075A** for ransomware precursors), I wanted to take detections all the way from virtualized lab provisioning to automated CI/CD regression testing and purple-team adversarial evasion hardening.

Here is what I built, the challenges I solved, and the metrics that proved the detections actually work.

---

## 1. The Threat-Informed Architecture

Rather than picking ATT&CK techniques at random, every detection in this project was anchored in real intrusion chains documented by CISA, Mandiant, and The DFIR Report:
- **Scenario A (Active Directory Intrusion Chain - APT29):** Initial staging in Downloads (`T1566.001`), user execution (`T1204.002`), PowerShell download cradles (`T1059.001`), Rundll32 proxy execution (`T1218.011`), process hollowing (`T1055.012`), LSASS credential dumping (`T1003.001`), DCSync (`T1003.006`), and SMB lateral movement (`T1021.002`).
- **Scenario B (Ransomware Precursor Chain - Conti / Black Basta / LockBit):** Inbound RDP access (`T1021.001`), Scheduled Task and Run key persistence (`T1053.005`, `T1547.001`), disabling Windows Defender (`T1562.001`), volume shadow copy deletion via `vssadmin` (`T1490`), and rapid ransomware mass file encryption (`T1486`).
- **Scenario C (Multi-Platform Enterprise Intrusion - Windows & Linux):** LOLBin credential access via Comsvcs (`T1003.001`), spearphishing Office child execution (`T1566.001` / `T1204.002`), remote WebClient staging cradles (`T1059.001`), Linux interactive reverse shells (`T1059.004`), and persistence via user/system cron tabs (`T1053.003`).

To collect telemetry across these chains, I built a 4-VM enterprise environment using **Vagrant and Ansible**, deployable from scratch with a single command:
```bash
vagrant up
```
The lab provisions:
- **Wazuh All-In-One (SIEM/Manager):** Ingests and correlates multi-channel telemetry.
- **Windows Server 2022 Domain Controller:** Active Directory DS with Directory Service and Kerberos auditing.
- **Windows 10 Enterprise Endpoint:** Configured with Sysmon (Olaf Hartong modular config) and PowerShell Script Block Logging (Event ID 4104).
- **Ubuntu Server:** Configured with `auditd` for syscall-level process and socket inspection.

---

## 2. Solving the Sigma-to-Wazuh Conversion Problem

In modern detection engineering, **Sigma** is the gold standard for vendor-neutral detection authoring. But when deploying to production SIEMs, you face a major roadblock:

> **There is no official, maintained pySigma backend for Wazuh XML.**

Unlike Splunk or Microsoft Sentinel, which evaluate query languages (SPL and KQL), Wazuh evaluates structured XML rules in its C-based `analysisd` engine. Standard conversion utilities cannot automatically map Sigma field names to Wazuh decoded JSON paths or assign the appropriate `<if_sid>` parent rules.

To solve this, I engineered a custom Python transpiler (`scripts/convert_sigma.py`) utilizing **Jinja2 templating**:
1. **Deterministic Field Mapping:** Maps generic Sigma fields to decoded JSON paths:
   - `CommandLine` $\rightarrow$ `win.eventdata.commandLine`
   - `Image` $\rightarrow$ `win.eventdata.image`
   - `TargetFilename` $\rightarrow$ `win.eventdata.targetFilename`
2. **Dynamic Parent SID Scoping:** Automatically scopes rules to the correct decoder:
   - Sysmon Process Creation $\rightarrow$ `<if_sid>60103</if_sid>`
   - Sysmon Network Connections $\rightarrow$ `<if_sid>60105</if_sid>`
   - PowerShell Script Blocks $\rightarrow$ `<if_sid>91800</if_sid>`
3. **Multi-SIEM Output:** Simultaneously outputs Microsoft Sentinel KQL and Splunk SPL queries, ensuring complete multi-cloud portability.

---

## 3. The Detection-as-Code CI/CD Pipeline

To ensure detection quality, no rule is deployed to production without passing an automated 6-stage GitHub Actions pipeline:

```
[Push / Pull Request]
        │
        ▼
Stage 1: YAML Linting (Fail if YAML is malformed)
        │
        ▼
Stage 2: Sigma CLI Schema Check (sigma check)
        │
        ▼
Stage 3: Transpiler (Convert to Wazuh XML, KQL, SPL)
        │
        ▼
Stage 4: Positive Regression Tests (Attack fixtures MUST alert)
        │
        ▼
Stage 5: Negative Regression Tests (Benign fixtures MUST NOT alert)
        │
        ▼
Stage 6: Artifact Packaging & Release Upload
```

If a detection engineer introduces a typo or an overzealous condition that breaks alert firing on an attack fixture, or creates a regression on a benign baseline, **the build breaks and the PR cannot merge.**

---

## 4. Purple-Team Hardening: Attacking My Own Detections

A detection that only works against default lab commands is useless. In Week 7, I played the adversary and attacked my own rules using 7 evasion techniques. Here are three highlights:

### Evasion 1: The Renamed Binary LSASS Dump
- **The Attack:** I renamed `mimikatz.exe` to `svchost.exe` and ran it from `C:\Users\Public\svchost.exe` to dump LSASS memory (`T1003.001`).
- **The Gap:** The original rule had an exclusion filter: `SourceImage|endswith: '\svchost.exe'`. Because `C:\Users\Public\svchost.exe` ended with `\svchost.exe`, the exclusion suppressed the alert!
- **The Fix:** I tightened the filter to require the exact canonical path `C:\Windows\System32\svchost.exe`. Any process named `svchost.exe` executing outside `System32` and requesting `0x1010` memory access to LSASS is flagged as critical credential dumping.

### Evasion 2: In-Memory AMSI Bypass via Reflection
- **The Attack:** Before executing an encoded download cradle, the attacker runs reflection memory patching:
  `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`
- **The Gap:** The PowerShell script block rule required both a download cradle (`Net.WebClient`) and an execution primitive (`IEX`). An in-memory AMSI patch does neither, slipping through completely undetected.
- **The Fix:** Added explicit AMSI tampering signatures (`AmsiUtils`, `amsiInitFailed`, `AmsiScanBuffer`) directly into the script block detection rule.

### Evasion 3: The `if_sid` Scoping Gap
- **The Attack:** The attacker unloads the Sysmon driver or executes in an environment logging via Windows Security Event ID 4688 instead of Sysmon Event ID 1.
- **The Gap:** The Wazuh rule had `<if_sid>60103</if_sid>` (Sysmon EID 1 only). When the command ran under Security EID 4688, Wazuh never evaluated the rule.
- **The Fix:** Updated the transpiler to generate multi-parent SIDs (`<if_sid>60103, 18100</if_sid>`) and added field fallback mappings (`NewProcessName` vs `Image`).

---

## 5. The Metrics That Matter

A detection portfolio is only as credible as its verified metrics:

| Metric | Target | Result Achieved | Evaluation Method |
|---|---|---|---|
| **True Positive Rate** | > 90% | **100.00%** (32/32) | Pytest regression on attack fixtures |
| **False Positive Rate** | < 2% | **0.00%** (0 / 1,207) | 4-hour enterprise baseline replay |
| **Mean Time to Detect (MTTD)** | < 60s | **6.78 seconds** | End-to-end execution to SIEM alert |
| **Adversarial Bypasses Mitigated** | 100% | **100.00%** (7/7) | Purple-team retest & fixture validation |
| **D3FEND Countermeasures Mapped** | 100% | **100.00%** (25/25) | Mapped in documentation & runbooks |

---

## Conclusion & Key Takeaways

1. **Detection is Software Engineering:** Treat detection rules like code. Lint them, transpile them, unit-test them, and protect your branches with CI/CD.
2. **Behavior Over Artifacts:** Never alert on static filenames or hashes. Alert on behavioral traits: granted memory access rights, parent-child anomalies, and script block reflection calls.
3. **Always Purple-Team Your Detections:** The moment you think a rule is complete, try to bypass it with LOLBins, base64 encoding, or process spoofing. The gaps you find in the lab are the ones threat actors won't be able to exploit in production.

*Check out the full open-source repository, Sigma rules, runbooks, and transpiler on GitHub: [github.com/omar-riadd/detection-engineering-lab](https://github.com/omar-riadd/detection-engineering-lab).*
