# 3-Minute Detection Engineering Demo Walkthrough & Video Script

> **Document Status:** Complete Storyboard & Video Production Script (v2.0 Release Ready)  
> **Last Updated:** 2026-10-21  
> **Target Video Duration:** 3 Minutes (180 seconds)  

---

## Storyboard & Timing Overview

```
[00:00 - 00:30] Segment 1: Threat Intel Scoping & Vagrant/Ansible Infrastructure
[00:30 - 01:10] Segment 2: Attack Emulation & Multi-Event Correlation (LSASS Dump, DCSync, Sequence)
[01:10 - 01:45] Segment 3: Live SIEM Push, Multi-Format Ingestion & Wazuh Alert Firing
[01:45 - 02:25] Segment 4: Svelte 5 Analyst Workbench, CQRS API & Automated CI/CD
[02:25 - 03:00] Segment 5: Purple-Team Evasion Hardening & Production Metrics
```

---

## Detailed Scene-by-Scene Script

### Segment 1: Threat Intel Scoping & Infrastructure-as-Code [00:00 - 00:30]
- **Visual On Screen:**
  - Split screen: Terminal showing `vagrant status` with 4 running VMs (`wazuh-server`, `win10-client`, `win-dc`, `ubuntu-target`) alongside the Mermaid architecture diagram from the repository `README.md`.
- **Audio Voiceover Narration:**
  > *"Welcome. In this walkthrough, I’m demonstrating an end-to-end, production-grade Detection Engineering portfolio built from cyber threat intelligence to automated CI/CD regression testing and full-stack operational tooling. 
  > The lab environment is completely reproducible through Infrastructure-as-Code using Vagrant and Ansible. In a single command, we provision an Active Directory domain controller, a Windows 10 endpoint equipped with modular Sysmon and advanced PowerShell logging, an Ubuntu server running auditd, and an all-in-one Wazuh SIEM manager and indexer."*

---

### Segment 2: Attack Emulation & Multi-Event Correlation [00:30 - 01:10]
- **Visual On Screen:**
  - Kali terminal connecting via SSH/WinRM to `win10-client`.
  - Executing Scenario A attack chain (`emulation/scenarios/scenario_a_ad_intrusion.sh`):
    1. Dumping LSASS memory via ProcDump/Mimikatz.
    2. Executing Active Directory DCSync directory replication via Mimikatz RPC call to the Domain Controller.
    3. Simulating stateful attack chain: credential dumping followed by rapid administrative SMB share access within a 300-second window.
- **Audio Voiceover Narration:**
  > *"Rather than testing generic tools, our emulation is grounded in CISA Advisory AA21-116A, modeling APT29 tradecraft. 
  > Here, I execute the credential access phase on our Windows 10 client. The attack first opens a handle to the Local Security Authority process—LSASS—requesting memory read rights 0x1010. 
  > Furthermore, our laboratory incorporates stateful multi-event correlation: tracking when credential dumping is followed by rapid lateral movement over SMB administrative shares within a sliding 5-minute time window."*

---

### Segment 3: Live SIEM Push, Multi-Format Ingestion & Alert Firing [01:10 - 01:45]
- **Visual On Screen:**
  - Browser showing Wazuh Dashboard (HTTPS `192.168.56.10:8443`).
  - The "Detection Engineering Operations Center" dashboard updates live.
  - Alerts fire in real time with enriched fields: `win.eventdata.grantedAccess: 0x1010`, `win.eventdata.targetImage: C:\Windows\System32\lsass.exe`, and ATT&CK / D3FEND tags.
  - Terminal showing live deployment API push: `curl -X POST http://localhost:8001/api/deploy/win_proc_access_lsass_memory?target=wazuh`.
- **Audio Voiceover Narration:**
  > *"Switching over to the Wazuh SIEM dashboard, our detections fire in real time. Within 4.4 seconds of execution, our detection engine intercepts the handle request. 
  > Notice the enrichment: we capture the exact GrantedAccess mask, caller image, call trace, and map the alert directly to MITRE ATT&CK T1003.001 and MITRE D3FEND D3-CAI for Credential Access Interception. 
  > With our live SIEM deployment API, detections authored in vendor-neutral Sigma can be pushed directly to Wazuh, Sentinel, or Splunk with automated syntax validation."*

---

### Segment 4: Svelte 5 Analyst Workbench & Automated CI/CD [01:45 - 02:25]
- **Visual On Screen:**
  - Browser opening the local Svelte 5 Field Manual UI (`http://localhost:5173`).
  - Showing Workspace 02 (Rules Catalog & Live YAML Editor) and Workspace 05 (Continuous Verification Console).
  - Terminal executing `make ci` showing all 4 stages passing (pytest detections, pytest API, replay harness with 65 fixtures, and Vite build).
- **Audio Voiceover Narration:**
  > *"To provide SOC analysts with full operational visibility, I engineered a high-performance Field Manual UI built with Svelte 5 runes, FastAPI, and SQLite in WAL mode under a CQRS pattern. 
  > Every detection is authored in vendor-neutral Sigma YAML. A custom Jinja2 transpiler converts rules simultaneously into Wazuh XML, Sentinel KQL, and Splunk SPL.
  > Our automated CI/CD pipeline tests every rule against positive attack fixtures, discriminative negative fixtures, and multi-format log exports including Sysmon XML, CEF, and NDJSON streams."*

---

### Segment 5: Purple-Team Evasion Hardening & Production Metrics [02:25 - 03:00]
- **Visual On Screen:**
  - Displaying Workspace 06 (Purple Team Evasion Ledger) and `docs/coverage/navigator_layer.json` in the ATT&CK Navigator web application.
  - Displaying the final project metrics summary table:
    - 33 Sigma Rules | 27 Sub-Techniques | 100% TP Rate (38/38) | 0.00% FP Rate (0/1,207) | 6.32s MTTD | 7/7 Bypasses Mitigated | 3 Threat Hunting Playbooks | 25+ Runbooks.
- **Audio Voiceover Narration:**
  > *"Finally, we don't assume our detections work; we attack them. We purple-teamed our rules across 7 evasion classes—including binary renaming, PPID spoofing, and in-memory AMSI reflection bypasses. We hardened every bypassed rule and proved resilience with regression fixtures.
  > The result is a battle-tested detection suite of 33 production rules, 27 ATT&CK sub-techniques, a 100% true-positive rate, zero false positives across 1,200 baseline events, and an average MTTD of 6.32 seconds.
  > Thank you for watching—the entire open-source project and full documentation are available at the GitHub link below."*
