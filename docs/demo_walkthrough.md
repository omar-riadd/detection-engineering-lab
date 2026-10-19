# 3-Minute Detection Engineering Demo Walkthrough & Video Script

> **Document Status:** Complete Storyboard & Video Production Script  
> **Last Updated:** 2026-10-19  
> **Project Plan Reference:** [PROJECT_PLAN.md](../PROJECT_PLAN.md) — Section 5 (Week 8)  
> **Target Video Duration:** 3 Minutes (180 seconds)  

---

## Storyboard & Timing Overview

```
[00:00 - 00:30] Segment 1: Lab Architecture & Vagrant/Ansible Infrastructure
[00:30 - 01:10] Segment 2: Attack Emulation (Scenario A: LSASS Memory Dumping & DCSync)
[01:10 - 01:50] Segment 3: Real-Time SIEM Ingestion & Wazuh Alert Firing
[01:50 - 02:30] Segment 4: Detection-as-Code in GitHub & Transpiler Engine
[02:30 - 03:00] Segment 5: Purple-Team Evasion Hardening & Closing Metrics
```

---

## Detailed Scene-by-Scene Script

### Segment 1: Lab Architecture & Infrastructure-as-Code [00:00 - 00:30]
- **Visual On Screen:**
  - Split screen: Terminal showing `vagrant status` with 4 running VMs (`wazuh-server`, `win10-client`, `win-dc`, `ubuntu-target`) alongside the Mermaid architecture diagram from the repository `README.md`.
- **Audio Voiceover Narration:**
  > *"Welcome. In this walkthrough, I’m demonstrating an end-to-end, production-grade Detection Engineering lifecycle built from threat intelligence to CI/CD regression testing. 
  > The lab environment is completely reproducible through Infrastructure-as-Code using Vagrant and Ansible. In a single command, we spin up an Active Directory domain controller, a Windows 10 endpoint equipped with modular Sysmon and advanced PowerShell logging, an Ubuntu target running auditd, and an all-in-one Wazuh SIEM manager and indexer."*

---

### Segment 2: Attack Emulation [00:30 - 01:10]
- **Visual On Screen:**
  - Kali terminal connecting via SSH/WinRM to `win10-client`.
  - Executing Scenario A attack chain (`emulation/scenarios/scenario_a_ad_intrusion.sh`):
    1. Dumping LSASS memory via ProcDump/Mimikatz.
    2. Executing Active Directory DCSync directory replication via Mimikatz RPC call to the Domain Controller.
- **Audio Voiceover Narration:**
  > *"Rather than testing generic tools, our emulation is grounded in CISA Advisory AA21-116A, modeling APT29 tradecraft. 
  > Here, I execute the credential access phase on our Windows 10 client. The attack first opens a handle to the Local Security Authority process—LSASS—requesting memory read rights 0x1010. Immediately following, the adversary uses replicated credentials to query the Domain Controller for DCSync user replication objects over Directory Service Access Event ID 4662."*

---

### Segment 3: Real-Time SIEM Ingestion & Alert Firing [01:10 - 01:50]
- **Visual On Screen:**
  - Browser showing Wazuh Dashboard (HTTPS `192.168.56.10:8443`).
  - The "Detection Engineering Operations Center" dashboard updates live.
  - Two Level 12 Critical alerts appear:
    - `Suspicious Process Access Request Targeting LSASS Memory [T1003.001]`
    - `Active Directory DCSync Credential Replication Request [T1003.006]`
  - Expanding the alert reveals enriched fields: `win.eventdata.grantedAccess: 0x1010`, `win.eventdata.targetImage: C:\Windows\System32\lsass.exe`, and ATT&CK / D3FEND tags.
  - MTTD gauge indicates **4.4 seconds** latency.
- **Audio Voiceover Narration:**
  > *"Switching over to the Wazuh SIEM dashboard, our detections fire in real time. Within 4.4 seconds of execution, our detection engine intercepts the handle request. 
  > Notice the enrichment: we capture the exact GrantedAccess mask, caller image, call trace, and map the alert directly to MITRE ATT&CK T1003.001 and MITRE D3FEND D3-CAI for Credential Access Interception. Our alert routing policy automatically classifies this as a Critical Level 12 event, routing it to our priority index and paging Tier 2 responders."*

---

### Segment 4: Detection-as-Code in GitHub & Transpiler Engine [01:50 - 02:30]
- **Visual On Screen:**
  - VS Code and GitHub repository showing `rules/sigma/windows/proc_creation/win_proc_access_lsass_memory.yml`.
  - Terminal executing `python scripts/convert_sigma.py` showing conversion into Wazuh XML, Microsoft Sentinel KQL, and Splunk SPL.
  - Showing GitHub Actions CI workflow tab with all 6 green checkmarks.
- **Audio Voiceover Narration:**
  > *"Every detection in this portfolio is managed strictly as code. Rules are authored vendor-neutrally in Sigma YAML. 
  > Because there is no official pySigma backend for Wazuh XML, I engineered a custom Jinja2-based transpiler in Python. It maps Sigma fields to Wazuh decoded JSON paths, assigns multi-parent SID scoping, and simultaneously outputs native KQL for Sentinel and SPL for Splunk. 
  > Every commit triggers our automated GitHub Actions pipeline, which validates syntax, transpiles rules, and runs positive and negative regression tests against our attack log fixtures and benign baselines."*

---

### Segment 5: Purple-Team Evasion Hardening & Closing Metrics [02:30 - 03:00]
- **Visual On Screen:**
  - Displaying `docs/bypass_log.md` and `docs/coverage/navigator_layer.json` in the ATT&CK Navigator web application.
  - Displaying the final project metrics summary table:
    - 21 Sigma Rules | 20 Sub-Techniques | 100% TP Rate | 0.00% FP Rate | 6.96s MTTD | 7/7 Bypasses Fixed.
- **Audio Voiceover Narration:**
  > *"Finally, we don't assume our detections work; we attack them. During Week 7, we purple-teamed our rules across 7 evasion classes—including binary renaming, PPID spoofing, and in-memory AMSI reflection bypasses. We hardened every bypassed rule and added new regression fixtures to CI.
  > The result is a battle-tested detection suite with a 100% true-positive rate, zero false positives across 1,200 baseline events, and an average Mean Time to Detect under 7 seconds. 
  > Thank you for watching—the entire open-source project is available at the GitHub link below."*
