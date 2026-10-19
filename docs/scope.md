# Threat Intelligence Scope & Attack Scenarios

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-10-19  
> **Status:** Approved Baseline  
> **Classification:** Detection Engineering Lab Reference

---

## 1. Threat Intelligence Grounding

Detection engineering must never rely on arbitrary technique selection. Every technique included in this portfolio is grounded in published threat intelligence reports, real-world intrusion post-mortems, and prevalent threat telemetry. Grounding detections in concrete threat actor behaviors ensures high operational fidelity, realistic telemetry reproduction, and robust defensive relevance.

### 1.1 Primary Threat Intelligence Citations

| Reference ID | Source Organization | Document Title / Publication | Threat Actor / Campaign | Key TTPs & Telemetry Focus |
|---|---|---|---|---|
| **TI-01** | **CISA / FBI / NSA** | [Advisory AA21-116A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a): Russian SVR Targets COVID-19 Research and Defense Networks | APT29 (Cozy Bear, Midnight Blizzard) | Spearphishing attachments, Rundll32 proxy execution, LSASS dumping, DCSync, Admin share lateral movement |
| **TI-02** | **Red Canary** | [2023 & 2024 Threat Detection Report](https://redcanary.com/threat-detection-report/) | Global Prevalent Threat Trends | PowerShell (T1059.001), Scheduled Tasks (T1053.005), Rundll32 (T1218.011), LSASS dumping (T1003.001), Inhibit Recovery (T1490) |
| **TI-03** | **The DFIR Report** | [A Case of Active Directory Domination (2022)](https://thedfirreport.com/) | Initial Broker to Domain Admin | User execution of malicious archives, process injection/hollowing, domain discovery (`nltest`, `net`), DCSync replication |
| **TI-04** | **CISA / MS-ISAC** | [Advisory AA23-075A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a): #StopRansomware: LockBit 3.0 | LockBit Ransomware Affiliates | RDP credential misuse, Defender impairment via PowerShell, VSS deletion via `vssadmin` / `bcdedit`, C2 exfiltration, mass encryption |
| **TI-05** | **The DFIR Report** | [Conti Ransomware in 32 Hours (2021) & From Qbot to Black Basta (2022)](https://thedfirreport.com/) | Conti / Black Basta Affiliates | Valid accounts, Scheduled tasks, Registry Run keys, WMI command execution (`wmic`), defense impairment, high-frequency file modifications |
| **TI-06** | **SigmaHQ** | [Sigma Community Rules Repository](https://github.com/SigmaHQ/sigma) | Industry Detection Standards | Reference log patterns, field normalization, process creation lineage, false-positive exclusions |

---

## 2. Attack Scenario Architecture

The portfolio models two realistic, multi-stage intrusion chains reflecting the modern enterprise threat landscape.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 SCENARIO A: Active Directory Intrusion Chain                │
│                         (Inspired by APT29 / SVR)                           │
├───────────────┬─────────────────┬──────────────────┬────────────────────────┤
│ Initial Access│ Execution &     │ Credential Access│ Discovery &            │
│ & Delivery    │ Defense Evasion │ & Privilege Esc. │ Lateral Movement       │
├───────────────┼─────────────────┼──────────────────┼────────────────────────┤
│ T1566.001     │ T1204.002       │ T1003.001        │ T1087.002              │
│ (Spearphish)  │ (User Exec)     │ (LSASS Dump)     │ (Domain Accounts)      │
│      │        │      │          │      │           │      │                 │
│      ▼        │      ▼          │      ▼           │      ▼                 │
│ Drop payload  │ PowerShell      │ T1003.006        │ T1482                  │
│ in Downloads  │ (T1059.001)     │ (DCSync)         │ (Domain Trust)         │
│               │ Rundll32        │                  │      │                 │
│               │ (T1218.011)     │                  │      ▼                 │
│               │ Process Hollow  │                  │ T1021.002              │
│               │ (T1055.012)     │                  │ (Admin Shares)         │
└───────────────┴─────────────────┴──────────────────┴────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                 SCENARIO B: Ransomware Precursor Chain                      │
│                  (Inspired by Conti / Black Basta / LockBit)                │
├───────────────┬─────────────────┬──────────────────┬────────────────────────┤
│ Initial Access│ Persistence &   │ Defense          │ Exfiltration &         │
│ & Exposure    │ Execution       │ Impairment       │ Impact                 │
├───────────────┼─────────────────┼──────────────────┼────────────────────────┤
│ T1078.002     │ T1053.005       │ T1562.001        │ T1041                  │
│ (Valid Accts) │ (Sched Tasks)   │ (Disable AV)     │ (C2 Exfiltration)      │
│      │        │      │          │      │           │      │                 │
│      ▼        │      ▼          │      ▼           │      ▼                 │
│ T1021.001     │ T1547.001       │ T1490            │ T1486                  │
│ (RDP Ingress) │ (Registry Run)  │ (Inhibit Recov)  │ (Mass Encryption)      │
│               │ T1047 (WMI)     │ T1027            │                        │
│               │                 │ (Obfuscation)    │                        │
└───────────────┴─────────────────┴──────────────────┴────────────────────────┘
```

---

## 3. Detailed Technique Selection & Rationale

### Scenario A — Active Directory Intrusion Chain (APT29 / CISA AA21-116A)

| # | Technique Name | ATT&CK ID | Telemetry Source | Primary Event IDs | Detection Logic Focus | TI Reference |
|---|---|---|---|---|---|---|
| 1 | Spearphishing Attachment | **T1566.001** | Sysmon | EID 1 (Process Create), EID 11 (File Create) | Executable/script drops in user directories from email/browser parents | TI-01, TI-03 |
| 2 | User Execution: Malicious File | **T1204.002** | Sysmon | EID 1 (Process Create) | Office / browser / archive utility launching untrusted script interpreters | TI-01, TI-02 |
| 3 | Command and Scripting Interpreter: PowerShell | **T1059.001** | PowerShell Operational | EID 4104 (ScriptBlock Logging) | Suspicious API calls (e.g., `VirtualAlloc`, `DownloadString`, reflection) | TI-02, TI-03 |
| 4 | Signed Binary Proxy Execution: Rundll32 | **T1218.011** | Sysmon | EID 1 (Process Create) | `rundll32.exe` executed with ordinal/no arguments, or from writable user directories | TI-01, TI-02 |
| 5 | Process Injection: Process Hollowing | **T1055.012** | Sysmon | EID 8 (CreateRemoteThread), EID 10 (ProcessAccess) | Cross-process memory manipulation targeting standard system binaries (`svchost`, `explorer`) | TI-01, TI-03 |
| 6 | OS Credential Dumping: LSASS Memory | **T1003.001** | Sysmon | EID 10 (ProcessAccess) | Access rights `0x1010`, `0x1F0FFF` requested against `lsass.exe` by non-system processes | TI-01, TI-02 |
| 7 | OS Credential Dumping: DCSync | **T1003.006** | Windows Security | EID 4662 (Directory Service Access) | DS-Replication-Get-Changes (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) requested by non-DC accounts | TI-01, TI-03 |
| 8 | Remote Services: SMB/Windows Admin Shares | **T1021.002** | Windows Security | EID 5140 (Network Share Access) | Access to administrative shares (`C$`, `ADMIN$`, `IPC$`) from abnormal workstation IPs | TI-01, TI-03 |
| 9 | Account Discovery: Domain Account | **T1087.002** | Windows Security / Sysmon | EID 4661, EID 1 | Execution of `net user /domain`, `net group`, or LDAP domain enumeration scripts | TI-01, TI-03 |
| 10 | Domain Trust Discovery | **T1482** | Windows Security / Sysmon | EID 4661, EID 1 | `nltest /domain_trusts`, `Get-ADTrust`, or `dsquery` calls from unauthorized accounts | TI-01, TI-03 |

---

### Scenario B — Ransomware Precursor Chain (Conti / Black Basta / LockBit)

| # | Technique Name | ATT&CK ID | Telemetry Source | Primary Event IDs | Detection Logic Focus | TI Reference |
|---|---|---|---|---|---|---|
| 1 | Valid Accounts: Domain Accounts | **T1078.002** | Windows Security | EID 4624 (Logon Type 3/10) | Abnormal logon times, rapid multi-host logons, or dormant privileged account activity | TI-04, TI-05 |
| 2 | Remote Services: Remote Desktop Protocol (RDP) | **T1021.001** | Windows Security | EID 4624 (Logon Type 10), EID 4625 | Inbound RDP connection surges, anomalous source IPs, lateral RDP pivoting | TI-04, TI-05 |
| 3 | Scheduled Task/Job: Scheduled Task | **T1053.005** | Windows Security / Sysmon | EID 4698 (Task Created), EID 1 | Task creation with command-lines referencing script interpreters or staging paths | TI-02, TI-05 |
| 4 | Boot or Logon Autostart: Registry Run Keys | **T1547.001** | Sysmon | EID 13 (RegistryValue Change) | Modifications to `CurrentVersion\Run` and `RunOnce` keys pointing to non-standard paths | TI-02, TI-05 |
| 5 | Inhibit System Recovery | **T1490** | Sysmon | EID 1 (Process Create) | Execution of `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set ... recoveryenabled No` | TI-02, TI-04 |
| 6 | Impair Defenses: Disable Windows Defender | **T1562.001** | PowerShell / Sysmon | EID 4104, EID 1, EID 13 | `Set-MpPreference -DisableRealtimeMonitoring $true`, service stop commands, tamper registry keys | TI-04, TI-05 |
| 7 | Data Encrypted for Impact | **T1486** | Sysmon / Windows Security | Sysmon EID 11, Security EID 4663 | Rapid creation of encrypted file extensions (EID 11) + high-frequency file write/delete operations (EID 4663) | TI-04, TI-05 |
| 8 | Exfiltration Over C2 Channel | **T1041** | Sysmon | EID 3 (Network Connection) | High-volume egress or persistent outbound connections from non-standard binaries (`rundll32`, `powershell`, `curl`) | TI-04, TI-05 |
| 9 | Obfuscated Files or Information | **T1027** | PowerShell Operational | EID 4104 (ScriptBlock Logging) | Base64-encoded command invocations (`-EncodedCommand`, `-enc`), `FromBase64String`, string manipulation tricks | TI-02, TI-05 |
| 10 | Windows Management Instrumentation (WMI) | **T1047** | Sysmon | EID 19, 20, 21 (WMI Events), EID 1 | Execution of `wmic.exe process call create` or persistence via WMI event filters and consumers | TI-02, TI-05 |

---

## 4. Laboratory Limitations & Technical Constraints

In keeping with Rule 2 (*Always verify, don't assume*), all laboratory boundaries, telemetry limitations, and engineering compensations are explicitly cataloged below:

### 4.1 T1566.001 (Spearphishing Attachment) Simulation Boundary
- **Limitation:** Atomic Red Team and isolated VirtualBox lab environments do not deploy a full Exchange/Postfix SMTP MTA infrastructure. Live email transmission over SMTP is omitted.
- **Simulation Approach:** The post-delivery phase is emulated directly. Mock weaponized attachments (e.g., LNK file inside ZIP, malicious HTA/macro document) are written to the target user's `%USERPROFILE%\Downloads` or Outlook temp directories. Execution is initiated from this location, accurately capturing:
  1. Sysmon EID 11 (File creation in download paths with mark-of-the-web / zone identifier).
  2. Sysmon EID 1 (Process creation lineage where parent is `explorer.exe` or an archive utility).
- **Interview / CV Relevance:** Demonstrates practical testing acumen by isolating telemetry-generating actions (process lineage, child spawns) from infrastructural overhead.

### 4.2 T1490 (Inhibit System Recovery) Technique Hierarchy
- **Specification:** T1490 is a **top-level technique** with no designated sub-techniques in MITRE ATT&CK.
- **Detection Architecture:** Rather than splitting detections artificially, a unified detection rule evaluates command-line invocations matching `vssadmin` shadow deletion, `wbadmin` backup clearing, and `bcdedit` boot status tampering within a single high-fidelity Sigma rule.

### 4.3 T1486 (Data Encrypted for Impact) Telemetry Engine Constraints
- **Limitation:** Sysmon does **not** provide a native file-rename event. Sysmon EID 14 tracks exclusively registry key and value renames. Relying on Sysmon alone for ransomware file-renaming causes a blind spot.
- **Detection & Telemetry Compensation:**
  1. **Sysmon EID 11 (FileCreate):** Triggers on high-velocity creation of known ransomware extensions or newly generated encrypted files.
  2. **Windows Security EID 4663 (Audit File System):** Enabled via Advanced Audit Policy (`Object Access -> Audit File System`) to capture high-rate `WriteData` and `Delete` handles.
  3. **Sysmon EID 1 (ProcessCreate):** Precursor command detection (inhibiting recovery, stopping database/hypervisor services).
  4. **Sysmon EID 23/26 (FileDelete):** Enabled in the Olaf Hartong modular config as supplemental telemetry.

---

## 5. Scope Sign-Off & Lifecycle

This document serves as the governing scope for:
- Sigma rule authoring (`rules/sigma/`)
- Atomic Red Team emulation plans (`emulation/`)
- Log fixture generation (`tests/fixtures/`)
- D3FEND countermeasure alignment (`docs/d3fend_mapping.md`)
- CI/CD automated validation (`.github/workflows/ci.yml`)
