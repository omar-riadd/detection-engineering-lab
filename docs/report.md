# Detection Engineering Project Final Report: Threat-Informed Detection-as-Code Lifecycle

> **Author:** Detection Engineering Team  
> **Date:** 2026-10-20  
> **Version:** 1.1  
> **Status:** Final Executive Report  
> **Project Repository:** [detection-engineering-lab](https://github.com/omar-riadd/detection-engineering-lab)  
> **Project Plan Reference:** [PROJECT_PLAN.md](../PROJECT_PLAN.md) — Section 5 (Week 8)  

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Laboratory Architecture & Telemetry Pipeline](#2-laboratory-architecture--telemetry-pipeline)
3. [MITRE ATT&CK Technique Coverage Table](#3-mitre-attck-technique-coverage-table)
4. [Detection Quality Metrics: False Positive & True Positive Analysis](#4-detection-quality-metrics-false-positive--true-positive-analysis)
5. [Mean Time to Detect (MTTD) Metrics](#5-mean-time-to-detect-mttd-metrics)
6. [Purple-Team Adversarial Bypass Summary](#6-purple-team-adversarial-bypass-summary)
7. [MITRE D3FEND Defensive Countermeasure Coverage](#7-mitre-d3fend-defensive-countermeasure-coverage)
8. [Key Findings, Engineering Innovations & Lessons Learned](#8-key-findings-engineering-innovations--lessons-learned)
9. [Conclusion & Operational Readiness](#9-conclusion--operational-readiness)

---

## 1. Executive Summary

Modern enterprise security operations face a dual crisis: alert fatigue driven by poorly scoped heuristic rules, and blind spots resulting from detections that rely on static artifacts rather than behavioral adversary tradecraft. 

To resolve these challenges, this portfolio project engineered an end-to-end, production-grade **Detection-as-Code (DaC)** lifecycle grounded strictly in real-world cyber threat intelligence (CISA Advisories AA21-116A and AA23-075A, the Red Canary Threat Detection Report, and The DFIR Report). 

Over an 8-week structured engineering cycle with multi-platform expansion, the project delivered:
- **Reproducible Infrastructure-as-Code Lab:** A 4-VM enterprise Active Directory environment provisioned with Vagrant and Ansible, featuring Wazuh SIEM, Windows Server 2022 Domain Controller, Windows 10 endpoint with Sysmon and advanced script block auditing, and Ubuntu Linux with `auditd`.
- **26 Production Sigma Rules:** Authored vendor-neutrally in YAML, covering 22 MITRE ATT&CK sub-techniques across three intrusion chains: **Scenario A (Active Directory Intrusion)**, **Scenario B (Ransomware Precursor)**, and **Scenario C (Multi-Platform Enterprise Intrusion)**.
- **Automated CI/CD Validation Pipeline:** A 6-stage GitHub Actions pipeline that lints YAML syntax, validates schema with `sigma-cli`, transpiles Sigma to **Wazuh XML**, **Microsoft Sentinel KQL**, and **Splunk SPL**, and executes unit regression tests against positive attack fixtures and benign baselines.
- **Interactive CQRS Operations UI:** A modern Svelte 5 + Tailwind CSS SPA backed by a FastAPI CQRS engine with SQLite WAL persistence and real-time WebSocket log replay.
- **Exceptional Operational Metrics:**
  - **True Positive (TP) Rate:** **100.00%** (32/32 attack and evasion fixtures firing)
  - **False Positive (FP) Rate:** **0.00%** across 1,207 benign baseline events (exceeding the < 2% target)
  - **Mean Time to Detect (MTTD):** **6.78 seconds** (well within the < 60-second enterprise SLA)
  - **Adversarial Hardening:** 7 distinct evasion classes emulated and mitigated (100% bypass remediation rate)
  - **Defensive Engineering:** 25 detections mapped to MITRE D3FEND countermeasures across 22 comprehensive SOC runbooks.

---

## 2. Laboratory Architecture & Telemetry Pipeline

The lab was built to provide high-fidelity, multi-source telemetry while remaining reproducible on any workstation with 16 GB of RAM using a single command: `vagrant up`.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        VIRTUALBOX HOST-ONLY NETWORK (192.168.56.0/24)                  │
├─────────────────────┬─────────────────────┬─────────────────────┬──────────────────────┤
│ Wazuh All-In-One    │ Windows Server 2022 │ Windows 10/11       │ Ubuntu Server 22.04  │
│ 192.168.56.10       │ 192.168.56.30       │ 192.168.56.20       │ 192.168.56.40        │
├─────────────────────┼─────────────────────┼─────────────────────┼──────────────────────┤
│ - Wazuh Manager     │ - Active Directory  │ - Windows 10 Ent    │ - Auditd daemon      │
│ - Wazuh Indexer     │ - DNS & Kerberos    │ - Sysmon (modular)  │ - Syscall rules      │
│ - Wazuh Dashboard   │ - Advanced Auditing │ - PowerShell EID4104│ - Wazuh Agent        │
│   (HTTPS 8443)      │ - Wazuh Agent       │ - Wazuh Agent       │                      │
└─────────────────────┴─────────────────────┴─────────────────────┴──────────────────────┘
                                ▲                     ▲                     ▲
                                │ Events (Port 1514)  │ Events (Port 1514)  │ Events (Port 1514)
                                └─────────────────────┴─────────────────────┘
```

### Telemetry Stack Configuration:
1. **Windows Endpoints:** Sysmon v15 deployed with Olaf Hartong's modular configuration enabling EIDs 1, 3, 7, 8, 10, 11, 13, 19, 20, 21, 22, 23, and 26.
2. **PowerShell Auditing:** Group Policy configured for Script Block Logging (EID 4104), Module Logging (EID 4103), and Transcription.
3. **Advanced Security Auditing:** Detailed process command-line auditing (EID 4688), Directory Service Access (EID 4662 for DCSync), File Share Access (EID 5140), Logon events (EID 4624/4625), and Advanced File System Auditing (EID 4663 for mass file encryption).
4. **Linux Endpoint:** `auditd` configured to capture privileged execution (`execve`), user privilege manipulation (`setuid`), and raw network socket creations.

---

## 3. MITRE ATT&CK Technique Coverage Table

The portfolio spans 22 ATT&CK sub-techniques across three intrusion scenarios (26 detection rules total):

| # | Scenario | Sub-Technique | ATT&CK ID | Tactic | Primary Telemetry | Author Rule File |
|---|---|---|---|---|---|---|
| 1 | A | Spearphishing Attachment | T1566.001 | Initial Access | Sysmon EID 11 | `win_file_susp_download_file_drop.yml` |
| 2 | A | User Execution: Malicious File | T1204.002 | Execution | Sysmon EID 1 | `win_proc_user_exec_untrusted_parent.yml` |
| 3 | A | PowerShell Execution | T1059.001 | Execution | PowerShell EID 4104 | `posh_pm_susp_script_block.yml` |
| 4 | A | Signed Binary Proxy: Rundll32 | T1218.011 | Defense Evasion | Sysmon EID 1 | `win_proc_rundll32_susp_execution.yml` |
| 5 | A | Process Hollowing: Remote Thread | T1055.012 | Defense Evasion | Sysmon EID 8 | `win_proc_hollowing_remote_thread.yml` |
| 6 | A | OS Credential Dumping: LSASS | T1003.001 | Credential Access | Sysmon EID 10 | `win_proc_access_lsass_memory.yml` |
| 7 | A | Credential Dumping: DCSync | T1003.006 | Credential Access | Security EID 4662 | `win_sec_dc_replication_access.yml` |
| 8 | A | Remote Service: Admin Shares | T1021.002 | Lateral Movement | Security EID 5140 | `win_sec_net_lateral_smb_admin_share.yml` |
| 9 | A | Account Discovery: Domain Account | T1087.002 | Discovery | Security EID 4661 / Sysmon 1 | `win_proc_domain_account_recon.yml` |
| 10 | A | Domain Trust Discovery | T1482 | Discovery | Sysmon EID 1 | `win_proc_domain_trust_discovery.yml` |
| 11 | B | Valid Accounts: Domain Accounts | T1078.002 | Defense Evasion | Security EID 4624 | `win_sec_anomalous_domain_logon.yml` |
| 12 | B | Remote Services: RDP Inbound | T1021.001 | Lateral Movement | Security EID 4624 (LogonType 10)| `win_sec_susp_rdp_lateral_logon.yml` |
| 13 | B | Scheduled Task Creation | T1053.005 | Persistence | Security EID 4698 / Sysmon 1 | `win_schtask_suspicious_creation.yml` |
| 14 | B | Registry Run Keys Persistence | T1547.001 | Persistence | Sysmon EID 13 | `win_registry_run_keys_persistence.yml` |
| 15 | B | Inhibit System Recovery (VSS) | T1490 | Impact | Sysmon EID 1 / Security 4688 | `win_proc_inhibit_system_recovery.yml` |
| 16 | B | Inhibit Recovery (Resize Storage) | T1490 | Impact | Sysmon EID 1 | `win_proc_vssadmin_resize_shadowstorage.yml` |
| 17 | B | Impair Defenses: Disable Defender | T1562.001 | Defense Evasion | PowerShell EID 4104 / Sysmon 1 | `posh_tamper_defender_mp_preference.yml` |
| 18 | B | Data Encrypted for Impact | T1486 | Impact | Sysmon EID 11 / Security 4663 | `win_file_mass_ransomware_activity.yml` |
| 19 | B | Exfiltration Over C2 Channel | T1041 | Command & Control | Sysmon EID 3 | `win_sysmon_net_susp_c2_exfil.yml` |
| 20 | B | Obfuscated Script Block: Base64 | T1027 | Defense Evasion | PowerShell EID 4104 | `posh_pm_obfuscated_script_block.yml` |
| 21 | B | WMI Process Command Execution | T1047 | Execution | Sysmon EID 19, 20 / Sysmon 1 | `win_proc_wmi_susp_command_exec.yml` |
| 22 | C | OS Credential Dumping: Comsvcs LSASS | T1003.001 | Credential Access | Sysmon EID 1 | `win_proc_comsvcs_lsass_dump.yml` |
| 23 | C | Malicious File: Office Child Spawn | T1566.001 / T1204.002 | Initial Access / Execution | Sysmon EID 1 | `win_proc_office_spawn_child.yml` |
| 24 | C | PowerShell Download Cradle | T1059.001 | Execution | Sysmon EID 1 / Posh 4104 | `win_proc_powershell_download_cradle.yml` |
| 25 | C | Linux Interactive Reverse Shell | T1059.004 | Execution | Linux auditd / Sysmon | `lnx_proc_reverse_shell.yml` |
| 26 | C | Linux Cron Persistence | T1053.003 | Persistence | Linux auditd / Sysmon | `lnx_auditd_susp_cron_job.yml` |

---

## 4. Detection Quality Metrics: False Positive & True Positive Analysis

Detections were measured continuously against two distinct corpora:
1. **Attack Corpus:** 25 standard positive attack fixtures and 7 evasion-variant attack fixtures (32 total positive fixtures) generated via Atomic Red Team, Scenario C multi-platform automation, and custom evasion harnesses.
2. **Benign Baseline Corpus:** 22 negative control fixtures and 1,207 benign events captured over 4 hours of normal administrative, user, and enterprise workload activity (web browsing, Chocolatey package updates, GPO sync, SCCM inventory queries, local RDP).

### Results:
- **Total Positive Fixtures Replayed:** 32
- **True Positive Alerts Fired:** 32 (**100.00% Sensitivity**)
- **Negative Fixtures Replayed:** 22
- **True Negative Ignored:** 22 (**100.00% Specificity**)
- **Baseline Events Replayed:** 1,207
- **False Positives Generated:** 0 (**0.00% False Positive Rate**)

All rules satisfied the portfolio requirement of maintaining an **FP rate < 2%**. Detailed tuning methodologies and baseline measurements are archived in [docs/fp_report.md](fp_report.md).

---

## 5. Mean Time to Detect (MTTD) Metrics

End-to-end detection latency was measured from the moment attack commands were executed on endpoints to the instant alert records were committed in the Wazuh indexer.

```
┌────────────────────────────────────────────────────────┐
│               PORTFOLIO MTTD BENCHMARK                 │
├────────────────────────────────┬───────────────────────┤
│ SLA Benchmark Target           │ < 60.00 seconds       │
│ Fastest Detection              │ 4.20 seconds (T1055)  │
│ Slowest Detection              │ 18.60 seconds (T1486) │
│ Mean Portfolio MTTD            │ 6.78 seconds          │
│ Median MTTD                    │ 5.60 seconds          │
│ SLA Compliance Rate            │ 100.00% (22/22)       │
└────────────────────────────────┴───────────────────────┘
```

The 6.96-second average MTTD confirms that behavioral Sigma detections coupled with Wazuh in-memory `analysisd` stream processing can alert SOC analysts in near real-time, long before adversaries achieve lateral spread or encryption execution. Detailed technique-by-technique benchmarks are documented in [docs/mttd_metrics.md](mttd_metrics.md).

---

## 6. Purple-Team Adversarial Bypass Summary

In Week 7, the engineering team executed purple-team adversarial simulations attacking our own rules across 7 distinct evasion classes. All 7 bypasses were logged, analyzed, and mitigated with hardened detection logic:

| # | Technique | Evasion Technique | Initial Result | Root Cause Analysis | Remediation Fix | Hardened Status |
|---|---|---|---|---|---|---|
| 1 | T1059.001 | Base64 EncodedCommand / `iwr` cradle | Bypass | Rule looked only for `Net.WebClient` | Added `Invoke-WebRequest`, `iwr`, and base64 decode primitives | **Hardened (PASS)** |
| 2 | T1041 | LOLBin C2 via `certutil` over HTTPS 443 | Bypass | Rule filtered out destination port 443 | LOLBin external connections are flagged regardless of destination port | **Hardened (PASS)** |
| 3 | T1003.001 | Renamed binary (`svchost.exe` in `C:\Users\Public`) | Bypass | Rule checked caller suffix `\svchost.exe` | Restricted exclusions strictly to `C:\Windows\System32\` canonical path | **Hardened (PASS)** |
| 4 | T1204.002 | PPID spoofing via `spoolsv.exe` | Bypass | Rule checked only interactive shell parents | Added system background services spawning scripts in Downloads | **Hardened (PASS)** |
| 5 | T1059.001 | In-memory AMSI bypass reflection | Bypass | Rule required both download cradle and IEX | Added explicit AMSI tampering signatures (`amsiInitFailed`) | **Hardened (PASS)** |
| 6 | T1566.001 | Dropper disguise via double extensions (`.pdf.exe`) | Bypass | Rule only monitored browser image creations | Added CLI/script droppers (`powershell.exe`) and double extensions | **Hardened (PASS)** |
| 7 | T1490 | `if_sid` scoping gap via Security EID 4688 | Bypass | Wazuh rule scoped only to Sysmon EID 1 (60103) | Multi-parent scoping (`60103, 18100`) with field fallback | **Hardened (PASS)** |

Full case studies, commands, and diffs are documented in [docs/bypass_log.md](bypass_log.md).

---

## 7. MITRE D3FEND Defensive Countermeasure Coverage

To ground detection engineering in architectural defense-in-depth, every detection rule was mapped to a [MITRE D3FEND](https://d3fend.mitre.org/) countermeasure:

| ATT&CK Sub-Technique | Authored Rule | D3FEND Countermeasure | D3FEND ID |
|---|---|---|---|
| T1566.001 (Spearphishing Attachment) | `win_file_susp_download_file_drop.yml` | File System Analysis | D3-FSA |
| T1204.002 (Malicious File Exec) | `win_proc_user_exec_untrusted_parent.yml` | Process Modification Analysis | D3-PMA |
| T1059.001 (PowerShell Execution) | `posh_pm_susp_script_block.yml` | Script Execution Analysis | D3-SEA |
| T1218.011 (Rundll32 Proxy) | `win_proc_rundll32_susp_execution.yml` | Process Binary Analysis | D3-PBA |
| T1055.012 (Process Hollowing) | `win_proc_hollowing_remote_thread.yml` | Process Spawn Analysis | D3-PSA |
| T1003.001 (LSASS Memory Dump) | `win_proc_access_lsass_memory.yml` | Credential Access Interception | D3-CAI |
| T1003.006 (DCSync Replication) | `win_sec_dc_replication_access.yml` | Credential Access Interception | D3-CAI |
| T1021.002 (SMB Admin Shares) | `win_sec_net_lateral_smb_admin_share.yml` | Lateral Movement Analysis | D3-LMA |
| T1087.002 (Domain Account Recon) | `win_proc_domain_account_recon.yml` | Domain Account Access Analysis | D3-DAA |
| T1482 (Domain Trust Discovery) | `win_proc_domain_trust_discovery.yml` | Domain Trust Analysis | D3-DTA |
| T1078.002 (Domain Account Logon) | `win_sec_anomalous_domain_logon.yml` | Logon Authentication Analysis | D3-LAA |
| T1021.001 (RDP Lateral Movement) | `win_sec_susp_rdp_lateral_logon.yml` | Lateral Movement Analysis | D3-LMA |
| T1053.005 (Scheduled Task) | `win_schtask_suspicious_creation.yml` | Scheduled Job Analysis | D3-SJA |
| T1547.001 (Registry Run Keys) | `win_registry_run_keys_persistence.yml` | Boot Record Analysis | D3-BRA |
| T1490 (Inhibit System Recovery) | `win_proc_inhibit_system_recovery.yml` | File System Analysis | D3-FSA |
| T1562.001 (Disable Defender) | `posh_tamper_defender_mp_preference.yml` | Security Policy Analysis | D3-SPA |
| T1486 (Ransomware Mass Encrypt) | `win_file_mass_ransomware_activity.yml` | File System Analysis | D3-FSA |
| T1041 (C2 Data Exfiltration) | `win_sysmon_net_susp_c2_exfil.yml` | Network Traffic Analysis | D3-NTA |
| T1027 (Obfuscated Script Block) | `posh_pm_obfuscated_script_block.yml` | Script Execution Analysis | D3-SEA |
| T1047 (WMI Command Execution) | `win_proc_wmi_susp_command_exec.yml` | Process Modification Analysis | D3-PMA |
| T1003.001 (LSASS Memory Dump via Comsvcs) | `win_proc_comsvcs_lsass_dump.yml` | Credential Access Interception | D3-CAI |
| T1566.001 / T1204.002 (Office Child Spawn) | `win_proc_office_spawn_child.yml` | Process Spawn Analysis | D3-PSA |
| T1059.001 (PowerShell Download Cradle) | `win_proc_powershell_download_cradle.yml` | Script Execution Analysis | D3-SEA |
| T1059.004 (Unix Interactive Shell) | `lnx_proc_reverse_shell.yml` | Process Modification Analysis | D3-PMA |
| T1053.003 (Cron Persistence) | `lnx_auditd_susp_cron_job.yml` | Scheduled Job Analysis | D3-SJA |

Full matrix with direct links to SOC runbooks is archived in [docs/d3fend_mapping.md](d3fend_mapping.md).

---

## 8. Key Findings, Engineering Innovations & Lessons Learned

1. **The Custom Sigma-to-Wazuh Transpiler:**
   Because no official pySigma backend exists for Wazuh XML, we engineered a custom Jinja2 template transpiler (`scripts/convert_sigma.py`). The transpiler maps vendor-neutral Sigma fields to Wazuh decoded JSON fields (`win.eventdata.*`), dynamically computes parent `<if_sid>` scoping rules, and supports shadow-mode promotion ladders (`level: 3` -> `6` -> `10/12`).
2. **Solving the `if_sid` Scoping Vulnerability:**
   A critical discovery during adversarial testing was that single-parent Wazuh rules (`<if_sid>60103</if_sid>`) are vulnerable to telemetry suppression when an attacker disables Sysmon or when endpoints log via Windows Security EID 4688. By updating the transpiler to generate multi-parent SIDs (`<if_sid>60103, 18100</if_sid>`) and adding field alias fallbacks (`NewProcessName` vs `Image`), the detections became resilient against EDR/Sysmon blind spots.
3. **Behavioral vs. Artifact-Based Detections:**
   Detections relying on static process names (e.g. `mimikatz.exe`) were immediately bypassed via simple renaming. Shifting detection focus to behavioral attributes—such as `GrantedAccess: 0x1010` requested against `lsass.exe` by non-System32 callers—rendered binary renaming completely ineffective.
4. **Automated Detection-as-Code CI/CD Harness:**
   Treating detection rules as software artifacts with unit regression tests fundamentally changes detection engineering quality. Broken rules fail the GitHub Actions build before ever reaching production SIEM environments.

---

## 9. Conclusion & Operational Readiness

This project demonstrates a complete, mature, and measurable Detection Engineering lifecycle. Every alert in this repository has been threat-informed, lab-validated, transpiled across multi-SIEM architectures, tuned against benign noise, and purple-team hardened against active evasion.

The repository stands ready for public presentation, recruiter evaluation, and enterprise SOC operational deployment.
