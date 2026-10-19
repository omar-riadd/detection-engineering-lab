# Detection Engineering Portfolio Project Plan
> **Status:** Active Reference Document  
> **Last Updated:** 2026-10-19  
> **Goal:** Build a public, metrics-driven detection engineering portfolio that demonstrates a full threat-informed lifecycle — from lab to CI/CD to purple-team hardening.

---

## Table of Contents
1. [Threat Intelligence & Scenario Scope](#1-threat-intelligence--scenario-scope)
2. [Repository Structure](#2-repository-structure)
3. [Infrastructure](#3-infrastructure)
4. [Methodology](#4-methodology)
5. [Week-by-Week Plan](#5-week-by-week-plan)
6. [Programming Languages](#6-programming-languages)
7. [Detection-as-Code Pipeline](#7-detection-as-code-pipeline)
8. [Git Workflow](#8-git-workflow)
9. [Metrics & CV Targets](#9-metrics--cv-targets)
10. [CV Bullet Point Templates](#10-cv-bullet-point-templates)

---

## 1. Threat Intelligence & Scenario Scope

### 1.1 Why Threat Intel First
Never pick techniques at random from ATT&CK. Ground every technique selection in real-world threat reporting. This makes your scenario realistic, and lets you say in interviews: *"My detections were based on TTPs documented in CISA Advisory AA23-xxx"* — a major differentiator.

### 1.2 Primary Threat Intel Sources

| Source | URL | Use |
|---|---|---|
| CISA Advisories & KEV Catalog | https://www.cisa.gov/news-events/cybersecurity-advisories | Real threat actor TTP chains |
| Red Canary Threat Detection Report | https://redcanary.com/threat-detection-report/ | Most prevalent techniques by year — prioritise these |
| MITRE ATT&CK Groups | https://attack.mitre.org/groups/ | Map scenario to a real threat actor (e.g., APT29, Lazarus) |
| The DFIR Report | https://thedfirreport.com/ | Detailed post-mortems of real intrusions — sets telemetry expectations |
| Mandiant / Google Threat Intelligence | https://cloud.google.com/blog/topics/threat-intelligence | Real intrusion chains and malware analysis |
| Sigma community rules (SigmaHQ) | https://github.com/SigmaHQ/sigma | Reference implementations and gap analysis |

### 1.3 Attack Scenarios

Choose **2 realistic chains** anchored in published threat reporting:

#### Scenario A — Active Directory Intrusion Chain
Inspired by APT29 / CISA AA21-116A:

> **Note on T1566.001 (Spearphishing Attachment):** Atomic Red Team does **not** simulate SMTP delivery — it has no email server to test against. In the lab, simulate the **post-delivery phase** only: manually place a mock attachment in the user's `Downloads` or Outlook temp folder and trigger execution from there. This tests what actually generates telemetry (process lineage, MOTW, child process spawn) without requiring a mail relay. Document this limitation explicitly in `docs/scope.md`.

| # | Sub-Technique | ATT&CK ID | Data Source | Emulation Approach |
|---|---|---|---|---|
| 1 | Spearphishing Attachment | T1566.001 | Sysmon EID 1, 11 | Manual drop to simulate post-delivery; note lab limitation |
| 2 | User Execution: Malicious File | T1204.002 | Sysmon EID 1 | Atomic Test #1 / manual script execution |
| 3 | PowerShell Execution | T1059.001 | PowerShell Script Block Log (EID 4104) | Atomic / custom PS scripts |
| 4 | Signed Binary Proxy: Rundll32 | T1218.011 | Sysmon EID 1 | Atomic Test #1 |
| 5 | Process Injection: Process Hollowing | T1055.012 | Sysmon EID 8, 10 | Atomic / manual |
| 6 | OS Credential Dumping: LSASS Memory | T1003.001 | Sysmon EID 10 | Atomic Test #1 (Mimikatz / ProcDump) |
| 7 | Credential Dumping: DCSync | T1003.006 | Windows Security EID 4662 | Atomic / manual Mimikatz dcsync |
| 8 | Remote Service: SMB/Windows Admin Shares | T1021.002 | Windows Security EID 5140 | Atomic / manual |
| 9 | Account Discovery: Domain Account | T1087.002 | Windows Security EID 4661 | Atomic / net commands |
| 10 | Domain Trust Discovery | T1482 | PowerShell / LDAP logs | Atomic / nltest commands |

#### Scenario B — Ransomware Precursor Chain
Inspired by common initial access broker + ransomware affiliate patterns (Conti, Black Basta):

> **Note on T1490 (Inhibit System Recovery):** This is a **top-level technique** with no sub-technique — T1490 is the correct and final ID. It covers VSS deletion (`vssadmin`), backup catalog clearing (`wbadmin`), and BCD modification (`bcdedit`). Write one rule covering all three command patterns.
>
> **Note on T1486 (Data Encrypted for Impact):** Sysmon has **no native file-rename event**. Sysmon EID 14 tracks only registry renames. Detect ransomware encryption via: (1) **Sysmon EID 11** for rapid file creation with suspicious extensions, (2) **Sysmon EID 1** for precursor commands (vssadmin, wbadmin, service stops), and (3) **Windows Security EID 4663** (File System auditing) for mass file access. Update your Sysmon config to enable EID 23/26 (FileDelete) as supplemental data.

| # | Sub-Technique | ATT&CK ID | Data Source | Emulation Approach |
|---|---|---|---|---|
| 1 | Valid Accounts: Domain Accounts | T1078.002 | Windows Security EID 4624 | Manual credential use |
| 2 | Remote Services: RDP | T1021.001 | Windows Security EID 4624, 4625 | xfreerdp from Kali |
| 3 | Scheduled Task / Job: Scheduled Task | T1053.005 | Windows Security EID 4698 | Atomic / schtasks |
| 4 | Boot/Logon Autostart: Registry Run Keys | T1547.001 | Sysmon EID 13 | Atomic Test #1 |
| 5 | Inhibit System Recovery | T1490 | Sysmon EID 1 (vssadmin/wbadmin/bcdedit) | Atomic / manual commands |
| 6 | Impair Defenses: Disable Windows Defender | T1562.001 | Windows Security / Sysmon EID 13 | Atomic / PowerShell Set-MpPreference |
| 7 | Data Encrypted for Impact | T1486 | Sysmon EID 1, 11; Windows Security EID 4663 | Atomic / simulated encryptor script |
| 8 | Exfiltration Over C2 Channel | T1041 | Sysmon EID 3 (network connection) | Atomic / manual curl/C2 beaconing |
| 9 | Obfuscated Files or Information | T1027 | PowerShell Script Block Log (EID 4104) | Atomic / base64-encoded PS commands |
| 10 | Windows Management Instrumentation | T1047 | Sysmon EID 19, 20, 21 | Atomic / wmic commands |

**Total: 20 sub-techniques across 2 chains. Target 25–30 Sigma rules total (some techniques need multiple rules).**

### 1.4 D3FEND Countermeasure Mapping

Map each detection to a [MITRE D3FEND](https://d3fend.mitre.org/) countermeasure. This is a strong differentiator — it shows you understand the defensive architecture behind each alert, not just the attack behaviour.

Document this in `docs/d3fend_mapping.md`:

| ATT&CK Sub-Technique | Detection Rule | D3FEND Countermeasure | D3FEND ID |
|---|---|---|---|
| T1003.001 (LSASS Dump) | proc_access_lsass_memory.yml | Credential Access Interception / Process Self-Modification Analysis | D3-CAI |
| T1059.001 (PowerShell) | ps_script_block_suspicious.yml | Script Execution Analysis | D3-SEA |
| T1021.002 (Admin Shares) | net_lateral_smb_admin_share.yml | Lateral Movement Analysis | D3-LMA |
| T1053.005 (Scheduled Task) | win_schtask_suspicious_creation.yml | Scheduled Job Analysis | D3-SJA |
| *... (add all techniques)* | | | |

> Mention D3FEND in your README and interviews: *"I mapped each detection to its D3FEND countermeasure to evaluate whether the alert was my only defensive layer or whether I could also harden the technique away."*

---

## 2. Repository Structure

A well-organised repo is half the impression on a hiring manager. Use this layout from day one.

```
detection-engineering-lab/
│
├── README.md                          # Overview, architecture diagram, metrics table
├── CHANGELOG.md                       # Rule history, promotions, deprecations
├── PROJECT_PLAN.md                    # This file
│
├── infra/                             # Lab provisioning (reproducible from scratch)
│   ├── Vagrantfile
│   ├── ansible/
│   │   ├── playbooks/
│   │   │   ├── wazuh.yml
│   │   │   ├── windows_endpoint.yml
│   │   │   ├── domain_controller.yml
│   │   │   └── linux_target.yml
│   │   └── roles/
│   └── scripts/
│       ├── install_sysmon.ps1
│       ├── configure_auditd.sh
│       └── enable_pslogging.ps1
│
├── rules/
│   ├── sigma/                         # Source of truth — author rules here only
│   │   ├── windows/
│   │   │   ├── proc_creation/
│   │   │   ├── registry/
│   │   │   ├── file_event/
│   │   │   └── network/
│   │   └── linux/
│   └── wazuh/                         # Auto-generated from CI — do NOT edit manually
│
├── converted/                         # Auto-generated multi-SIEM outputs from CI
│   ├── kql/                           # Microsoft Sentinel / Defender
│   └── splunk/                        # Splunk SPL
│
├── tests/
│   ├── fixtures/                      # Labelled JSON log samples per technique
│   │   ├── T1003.001_positive.json    # Log that MUST trigger the rule
│   │   ├── T1003.001_negative.json    # Log that MUST NOT trigger the rule
│   │   └── baseline/                  # 2-4h benign baseline corpus (Week 2)
│   └── test_detections.py             # pytest regression harness
│
├── runbooks/                          # SOC analyst triage guides (1 per detection)
│   ├── T1003.001-lsass-dump.md
│   ├── T1059.001-powershell-exec.md
│   └── ...
│
├── playbooks/                         # Threat hunting playbooks (hypothesis-driven)
│   ├── hunt_lateral_movement.md
│   ├── hunt_credential_access.md
│   └── ...
│
├── emulation/                         # Attack simulation
│   ├── atomic_mappings.md             # Maps Atomic Red Team test IDs to your rules
│   └── scenarios/
│       ├── scenario_a_ad_intrusion.sh
│       └── scenario_b_ransomware_precursor.sh
│
├── docs/
│   ├── scope.md                       # Threat model and technique selection with intel citations
│   ├── bypass_log.md                  # Evasion attempts, outcomes, fixes (structured)
│   ├── fp_report.md                   # False positive analysis per rule
│   ├── mttd_metrics.md                # Mean Time to Detect per technique
│   ├── d3fend_mapping.md              # ATT&CK → D3FEND countermeasure mapping
│   ├── sigma_to_wazuh_notes.md        # Conversion limitations and manual adjustments
│   └── coverage/
│       └── navigator_layer.json       # ATT&CK Navigator export
│
├── scripts/
│   ├── convert_sigma.py               # Sigma → Wazuh XML (custom) + KQL + SPL (pySigma)
│   ├── replay_logs.py                 # Replay fixture logs against rules for regression tests
│   └── generate_baseline.py          # Simulate benign activity for FP measurement
│
└── .github/
    └── workflows/
        └── ci.yml                     # GitHub Actions: lint → validate → convert → test
```

---

## 3. Infrastructure

### 3.1 Components

| Component | Choice | Rationale |
|---|---|---|
| **SIEM** | Wazuh all-in-one (manager + indexer + dashboard) | Free, industry-recognised, lighter than full ELK |
| **Windows Endpoint** | Windows 10/11 Evaluation VM | Sysmon with Olaf Hartong's modular config for granular telemetry |
| **Domain Controller** | Windows Server Evaluation VM | Essential for realistic AD attacks (Kerberoasting, DCSync, lateral movement) |
| **Linux Target** | Ubuntu Server VM | `auditd` for syscall-level telemetry |
| **Attacker** | Your Kali host | Saves a VM; runs Atomic Red Team and manual attack scripts |
| **Network** | VirtualBox host-only network | Isolated lab traffic; NAT enabled only for updates |

### 3.2 Provisioning (Reproducibility = CV Point)

Use **Vagrant + Ansible** so anyone can rebuild the entire lab with:
```bash
vagrant up
```
This demonstrates infrastructure-as-code skills on top of detection engineering — a strong signal for any senior role.

### 3.3 RAM Budget

| Component | Minimum | Comfortable |
|---|---|---|
| Kali host (attacker) | 3 GB | 4 GB |
| Wazuh all-in-one | 4 GB | 6 GB |
| Windows 10/11 endpoint | 3 GB | 4 GB |
| Windows Server DC | 2 GB | 3 GB |
| Ubuntu Server | 1 GB | 2 GB |
| **Total** | **~13 GB** | **~19 GB** |

> **With 8 GB RAM:** Drop the DC. Run Wazuh + one Windows VM at a time using snapshots to swap.  
> **With 16 GB RAM:** Run all VMs simultaneously — the optimal setup for this project.

### 3.4 Snapshot Strategy
- Take a **clean snapshot** of every VM before each attack run.
- Name snapshots clearly: `dc-pre-dcsync-attack`, `win10-pre-lsass-dump`.
- Roll back after each run to maintain a clean baseline.

### 3.5 Telemetry Checklist

**Windows:**
- [ ] Sysmon installed with Olaf Hartong modular config (enables EID 1, 3, 7, 8, 10, 11, 13, 19, 20, 21, 22, 23, 26)
- [ ] PowerShell Script Block Logging enabled — EID 4104 (GPO or registry)
- [ ] Process command-line auditing enabled — EID 4688
- [ ] Windows Security event logging configured: EID 4624, 4625, 4662, 4663, 4698, 4688, 4103, 4104, 5140
- [ ] Advanced Audit Policy: **Audit File System** enabled (required for T1486 file access EID 4663)
- [ ] Wazuh agent installed and reporting
- [ ] Wazuh agent configured to collect: Security, System, PowerShell/Operational channels

**Linux:**
- [ ] `auditd` installed and configured
- [ ] Audit rules for privileged command execution, file access, network connections
- [ ] Wazuh agent installed and reporting

---

## 4. Methodology

A **threat-informed detection engineering lifecycle** inside a purple-team loop:

```
┌─────────────┐
│   SELECT    │  Pick sub-techniques from real threat intel reports
└──────┬──────┘
       │
┌──────▼──────┐
│   EMULATE   │  Atomic Red Team / manual; capture raw logs; label fixtures
└──────┬──────┘
       │
┌──────▼──────┐
│   ANALYSE   │  Find distinguishing artifacts (process lineage, CLI args, registry/file changes)
└──────┬──────┘
       │
┌──────▼──────┐
│    WRITE    │  Author Sigma rule (sub-technique, UUID, full metadata, runbook)
│             │  Map to D3FEND countermeasure
└──────┬──────┘
       │
┌──────▼──────┐
│  VALIDATE   │  Confirm true positive; run positive regression test in CI
└──────┬──────┘
       │
┌──────▼──────┐
│    TUNE     │  Run against benign baseline; measure FP rate; run negative regression test
└──────┬──────┘
       │
┌──────▼──────┐
│SHADOW DEPLOY│  Deploy at low severity for 7 days; monitor for noise before promotion
└──────┬──────┘
       │
┌──────▼──────┐
│   EVADE &   │  Red-team your own rule; obfuscation, LOLBins, parent-process tricks
│   RETEST    │  Log every bypass; fix; retest; record MTTD
└──────┬──────┘
       │
┌──────▼──────┐
│  DOCUMENT   │  Detection spec + runbook in Git; update CHANGELOG; ATT&CK Navigator layer
└──────┬──────┘
       │
┌──────▼──────┐
│   MEASURE   │  TP rate, FP rate, MTTD, evasion resistance, ATT&CK coverage %
└──────┬──────┘
       │
┌──────▼──────┐
│MANAGE DEBT  │  Retire stale rules; flag noisy ones; document in detection debt register
└─────────────┘
```

### Detection Spec Template (per rule)

Every Sigma rule must have a corresponding spec entry in `docs/` with:

| Field | Description |
|---|---|
| `id` | UUID (auto-generated) |
| `title` | Short, descriptive name |
| `status` | `experimental` / `test` / `stable` |
| `description` | What behaviour this detects and why it matters |
| `references` | Links to threat reports, ATT&CK pages, malware analysis |
| `tags` | ATT&CK sub-technique (e.g., `attack.t1003.001`) |
| `logsource` | Product, service, category |
| `falsepositives` | Known benign triggers (e.g., "SCCM credential harvest") |
| `severity` | `informational` / `low` / `medium` / `high` / `critical` |
| `data_source` | Sysmon EID, Windows Security EID, auditd, etc. |
| `response_steps` | Links to runbook |
| `d3fend` | Corresponding D3FEND countermeasure ID |

---

## 5. Week-by-Week Plan

### Week 1 — Scope, Threat Intel & Repo Setup
**Focus:** Ground the project in real threat reporting and set up the foundation.

**Tasks:**
- [ ] Read and annotate at least 2 threat intel sources per scenario (CISA, Red Canary, DFIR Report)
- [ ] Finalise the 20 sub-techniques across 2 scenarios (see Section 1.3)
- [ ] Write `docs/scope.md` — document technique selection rationale with intel citations; note lab limitations (e.g., T1566.001 email delivery)
- [ ] Initialise GitHub repo with the full folder structure (Section 2)
- [ ] Write `README.md` skeleton with architecture diagram placeholder
- [ ] Configure branch protection: require PR + passing CI before merge to `main`
- [ ] Set up `CHANGELOG.md` with initial entry
- [ ] Create `docs/d3fend_mapping.md` skeleton — fill in as rules are written

**Deliverable:** `docs/scope.md` with cited techniques and lab limitations documented, empty repo with enforced structure, branch protection active.

---

### Week 2 — Lab Build & Telemetry
**Focus:** Provision the lab and capture a benign baseline dataset.

**Tasks:**
- [ ] Write `Vagrantfile` and Ansible playbooks for all VMs
- [ ] Provision Wazuh all-in-one; verify indexer + dashboard are accessible
- [ ] Deploy Sysmon on Windows VMs with Olaf Hartong modular config
- [ ] Configure auditd on Ubuntu with appropriate ruleset
- [ ] Enable PowerShell Script Block Logging and process command-line auditing
- [ ] Enable **Advanced Audit Policy: Audit File System** (required for T1486 telemetry via EID 4663)
- [ ] Verify all agents are reporting to Wazuh
- [ ] **Capture 2–4 hours of benign baseline activity** (normal user logins, file access, browser use, admin tasks) and save to `tests/fixtures/baseline/`
- [ ] Verify log flow for every event ID in the telemetry checklist (Section 3.5)

**Deliverable:** All agents reporting; provisioning scripts committed; labelled benign baseline corpus saved.

---

### Week 3 — Attack Emulation Harness & Log Corpus
**Focus:** Build a replayable, labelled attack dataset.

**Tasks:**
- [ ] Install and configure Atomic Red Team on Kali
- [ ] Write `emulation/atomic_mappings.md` — map each technique to its Atomic test ID
- [ ] Run each of the 20 sub-techniques in isolation (one per snapshot rollback)
- [ ] For **T1566.001**: place mock attachment in `%USERPROFILE%\Downloads`, trigger execution, capture the process spawn — document the lab simulation approach in `docs/scope.md`
- [ ] For **T1486**: verify you are capturing EID 11 (mass file creation) AND EID 4663 (file access audit) — not just EID 1
- [ ] For each technique:
  - [ ] Save raw attack logs as `tests/fixtures/T<ID>_positive.json`
  - [ ] Save a benign log for the same data source as `tests/fixtures/T<ID>_negative.json`
  - [ ] Note key observable artifacts (process lineage, CLI args, registry/file changes)
- [ ] Script the full Scenario A and Scenario B chains as end-to-end emulation scripts
- [ ] Commit everything to `emulation/scenarios/`

**Deliverable:** 20 positive + 20 negative log fixtures; two replayable scenario scripts; `atomic_mappings.md`.

---

### Week 4 — Detections v1 (First 10 Rules + Runbooks)
**Focus:** Author the first 10 Sigma rules with full metadata, triage runbooks, and D3FEND mapping.

**Tasks:**
- [ ] Write 10 Sigma rules in `rules/sigma/` — one per sub-technique
  - Map to **sub-techniques** (e.g., `T1003.001`, not just `T1003`)
  - Include: UUID `id`, `title`, `status: experimental`, `description`, `references`, `tags`, `logsource`, `detection`, `falsepositives`, `level`
  - Focus on **behaviour, not artifacts** (process lineage, CLI patterns, not static hashes or file names)
- [ ] Deploy each rule to Wazuh and confirm it fires against the positive log fixture
- [ ] Manually adjust Wazuh XML output where `convert_sigma.py` cannot auto-map field names (see Section 7 — the conversion limitation)
- [ ] Write a triage **runbook** in `runbooks/` for each of the 10 rules using this template:

```markdown
# Runbook: [Rule Title] — [ATT&CK ID]

## Alert Summary
What this alert means and why it matters.

## Immediate Triage Steps
1. Check process parent/child tree
2. Verify user context and source host
3. Check for correlated alerts in the last 24h
...

## Investigation Queries
```kql
// KQL query to pivot on the alerted host
```

## Escalation Criteria
Escalate to Tier 2 if: ...

## Known False Positives
- Software X triggers this during update cycle

## MITRE ATT&CK Reference
- Sub-technique: T1003.001
- Tactic: Credential Access

## D3FEND Countermeasure
- Countermeasure: Credential Access Interception
- D3FEND ID: D3-CAI
- Link: https://d3fend.mitre.org/technique/d3f:CredentialAccessInterception/
```

- [ ] Update `docs/d3fend_mapping.md` for each new rule

**Deliverable:** 10 Sigma rules (full metadata), 10 runbooks with D3FEND references, all rules verified true-positive against fixtures.

---

### Week 4.5 (Parallel) — Write Threat Hunting Playbooks
**Focus:** Write 2 hypothesis-driven threat hunting playbooks — one per scenario. This elevates the project from reactive detection to proactive hunting.

**Tasks:**
- [ ] Write `playbooks/hunt_credential_access.md` covering Scenario A
- [ ] Write `playbooks/hunt_ransomware_precursor.md` covering Scenario B
- [ ] Each playbook must follow this structure:

```markdown
# Threat Hunting Playbook: [Name]

## Hypothesis
Adversaries are using [behaviour] to achieve [goal] while evading [control].

## ATT&CK Techniques Covered
- T1003.001, T1059.001, ...

## Data Source Requirements
| Source | Event IDs | Must-Have Field |
|--------|-----------|-----------------|

## Hunt Queries
```kql
// Broad hypothesis query — cast wide first
```
```sigma
# Narrower, high-confidence variant
```

## Triage Decision Tree
1. If [condition A] → investigate further (step 2)
2. If [condition B] → escalate
3. If [condition C] → likely benign (document and close)

## Known Blind Spots
- This hunt does not cover [gap] because [reason]
```

**Deliverable:** 2 threat hunting playbooks committed to `playbooks/`.

---

### Week 5 — Detection-as-Code CI/CD Pipeline
**Focus:** Automate validation, conversion, and regression testing in GitHub Actions.

**Pipeline stages (in order):**

```
push / PR
    │
    ▼
[1] YAML Lint          → Fail if any Sigma YAML is malformed
    │
    ▼
[2] Sigma Validation   → sigma-cli check on all rules
    │
    ▼
[3] Conversion         → Custom script: Sigma → Wazuh XML
                         pySigma: Sigma → KQL + SPL (multi-SIEM portability)
    │
    ▼
[4] Positive Tests     → Attack log fixtures MUST trigger the rule  (fail = broken detection)
    │
    ▼
[5] Negative Tests     → Benign log fixtures MUST NOT trigger rule  (fail = false positive regression)
    │
    ▼
[6] Artifact Upload    → Store converted KQL/SPL/XML as release artifacts
```

**Tasks:**
- [ ] Write `scripts/convert_sigma.py`:
  - Use **pySigma** for KQL and SPL outputs (well-supported)
  - Use a **custom Jinja2 template approach** for Wazuh XML — do NOT rely on an unofficial pySigma Wazuh backend; the official one does not exist. Map Sigma fields → Wazuh decoded field names manually (e.g., `CommandLine` → `win.eventdata.commandLine`)
- [ ] Write `scripts/replay_logs.py` — feeds JSON fixtures into rule evaluation; returns pass/fail
- [ ] Write `tests/test_detections.py` — pytest wrapper for positive and negative cases
- [ ] Write `.github/workflows/ci.yml` implementing all 6 stages above
- [ ] Document your Sigma→Wazuh field mapping table in `docs/sigma_to_wazuh_notes.md`
- [ ] Confirm a broken rule fails the build; a passing rule merges cleanly

**Deliverable:** Green pipeline on all 10 existing rules; a deliberately bad rule demonstrably breaks the build; field mapping documented.

---

### Week 6 — Tuning, Expansion & Shadow Deployment
**Focus:** Cut false positives systematically and expand to 20+ detections.

**Tasks:**
- [ ] Run all 10 rules against the full benign baseline corpus from Week 2
- [ ] Record FP rate per rule in `docs/fp_report.md` using this table:

```markdown
| Rule | ATT&CK ID | TP Count | FP Count | FP Rate | Tuning Action |
|------|-----------|----------|----------|---------|---------------|
```

- [ ] Tune any rule with FP rate > 5% — tighten conditions, add exclusions for known-good paths
- [ ] Introduce **shadow/experimental mode**: new rules deploy at `level: 3` (informational) in Wazuh for 7 days before being promoted to active alerting — add this to the deployment workflow
- [ ] Write the remaining 10–15 rules to reach 20–25 total (covering remaining sub-techniques)
- [ ] Update all runbooks, D3FEND mappings, and fixtures for new rules
- [ ] Run `scripts/generate_baseline.py` to simulate additional benign edge cases

**Deliverable:** FP report, shadow-mode deployment workflow, 20+ rules all in CI with positive + negative tests.

---

### Week 7 — Purple-Team Iterations & MTTD Measurement
**Focus:** Attack your own detections, harden bypassed rules, and compute MTTD.

**Evasion Techniques to Test:**
| Evasion | Target Rules | Example |
|---|---|---|
| String obfuscation / encoding | PowerShell rules | Base64-encoded commands |
| LOLBins substitution | Process creation rules | Use `certutil` instead of `curl` |
| Renamed binaries | Binary name–based rules | Rename `mimikatz.exe` to `svchost.exe` |
| Parent process spoofing | Parent-child lineage rules | Use `SelectMyParent` or similar |
| AMSI bypass | Script execution rules | `[Ref].Assembly.GetType(...)` patterns |
| Timestomping | File creation rules | Modified timestamps on dropped tools |
| `if_sid` scoping gap abuse | Wazuh XML rules | Events that bypass parent rule matching |

**Tasks:**
- [ ] Attempt every evasion in the table above against your rules
- [ ] Log every attempt in `docs/bypass_log.md` using this structure:

```markdown
| # | Technique | Evasion Method | Rule Bypassed | Outcome | Fix Applied | Date |
|---|-----------|----------------|---------------|---------|-------------|------|
```

- [ ] For each bypass: fix the rule, retest, add a new positive fixture for the evasion variant
- [ ] Measure **MTTD** (time from attack execution to Wazuh alert) for each technique; log in `docs/mttd_metrics.md`
- [ ] Export ATT&CK Navigator layer showing coverage, gap, and evasion-tested status
- [ ] Update CI with new evasion-variant fixtures

**Deliverable:** Structured bypass log, hardened rules, ATT&CK Navigator layer, MTTD metrics per technique.

---

### Week 8 — Polish, Metrics & Publication
**Focus:** Make the project presentation-ready for recruiters and hiring managers.

**Tasks:**
- [ ] Build Wazuh dashboards: alert volume over time, technique coverage heatmap, FP vs TP trend
- [ ] Configure Wazuh alert routing: route `high`/`critical` alerts to a dedicated index or email notification
- [ ] Write the project final report (PDF or `docs/report.md`):
  - Executive summary
  - Lab architecture
  - Technique coverage table
  - FP/TP metrics
  - MTTD metrics
  - Bypass log summary
  - D3FEND countermeasure coverage
  - Key findings and lessons learned
- [ ] Write a blog post (publish on Medium, Substack, or personal site)
- [ ] Record a 3-minute demo video: lab overview → attack emulation → alert firing → rule in GitHub
- [ ] Add **detection debt register** to `CHANGELOG.md`: rules marked for review, retirement, or improvement
- [ ] Polish `README.md`:
  - Architecture diagram
  - Metrics summary table (detections, sub-techniques, TP rate, FP rate, MTTD)
  - Quick-start instructions (lab build + CI run)
  - Links to blog post and demo video
- [ ] Tag release `v1.0` on GitHub
- [ ] Push all converted KQL/SPL rules as versioned release artifacts

**Deliverable:** Public repo (v1.0 tagged), blog post live, demo video published, README with metrics table.

---

## 6. Programming Languages

| Language | Role | Where |
|---|---|---|
| **Python** | Primary: automation, test harness, custom Sigma→Wazuh conversion, pySigma for KQL/SPL, Wazuh API integration, report generation | `scripts/`, `tests/` |
| **YAML (Sigma)** | Detection source of truth — all rules authored here | `rules/sigma/` |
| **XML (Wazuh)** | Auto-generated native Wazuh rule format — manually adjusted post-conversion due to field mapping gaps | `rules/wazuh/` |
| **PowerShell** | Windows telemetry setup, Atomic Red Team (`Invoke-AtomicRedTeam`), Windows attack scripts | `infra/scripts/`, `emulation/` |
| **Bash** | Linux provisioning, auditd config, glue scripts | `infra/scripts/` |
| **JSON** | Log fixtures for regression testing (positive + negative per technique) | `tests/fixtures/` |
| **KQL** | Multi-SIEM output (Microsoft Sentinel / Defender) — auto-generated by CI via pySigma | `converted/kql/` |
| **SPL** | Multi-SIEM output (Splunk) — auto-generated by CI via pySigma | `converted/splunk/` |
| **Jinja2** | Wazuh XML rule templates used by the custom conversion script | `scripts/` |
| **HCL (optional)** | Terraform for cloud-based lab variant — stronger signal for cloud-native roles | `infra/terraform/` |

---

## 7. Detection-as-Code Pipeline

### 7.1 The Sigma → Wazuh Conversion Challenge

> **Critical note — read this before writing `convert_sigma.py`:**
>
> There is **no official, fully maintained pySigma backend for Wazuh**. Unlike Splunk or Elastic, Wazuh uses structured XML rules evaluated by its own `analysisd` engine — not a query language. This means:
>
> - You **cannot** use a standard `sigma-cli` backend to produce working Wazuh XML
> - Sigma field names (`CommandLine`, `ParentImage`) must be **manually mapped** to Wazuh decoded field paths (e.g., `win.eventdata.commandLine`)
> - Complex Sigma logic (`near`, temporal correlation) cannot be auto-translated — these require **multi-rule Wazuh correlation** using `<if_matched_sids>`
> - Each Wazuh rule must have a correct `<if_sid>` parent rule to scope it to the right decoder — generic conversion scripts miss this
>
> **Recommended approach:** Use pySigma to parse Sigma YAML into an AST, then use a custom **Jinja2 template** to render Wazuh XML with a manually maintained field mapping table. Document all mapping decisions and manual adjustments in `docs/sigma_to_wazuh_notes.md`.
>
> This limitation is itself a portfolio talking point: *"I discovered that no official pySigma Wazuh backend exists, so I built a custom Jinja2-based transpiler with a maintained field-mapping table."*

### 7.2 Full CI Workflow (`ci.yml`)

```yaml
name: Detection Engineering CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  validate-convert-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install pysigma sigma-cli pyyaml pytest jinja2

      - name: 1 - YAML lint
        run: |
          python -c "
          import yaml, glob, sys
          errors = []
          for f in glob.glob('rules/sigma/**/*.yml', recursive=True):
              try: yaml.safe_load(open(f))
              except Exception as e: errors.append(f'{f}: {e}')
          if errors: print('\n'.join(errors)); sys.exit(1)
          print('YAML lint passed')
          "

      - name: 2 - Sigma validation
        run: sigma check rules/sigma/

      - name: 3 - Convert to Wazuh XML + KQL + SPL
        run: |
          mkdir -p rules/wazuh converted/kql converted/splunk
          python scripts/convert_sigma.py \
            --input rules/sigma/ \
            --wazuh rules/wazuh/ \
            --kql converted/kql/ \
            --splunk converted/splunk/

      - name: 4 - Positive regression tests (attack logs MUST fire)
        run: pytest tests/ -k "positive" -v

      - name: 5 - Negative regression tests (benign logs MUST NOT fire)
        run: pytest tests/ -k "negative" -v

      - name: 6 - Upload converted rules as artifacts
        uses: actions/upload-artifact@v4
        with:
          name: converted-rules-${{ github.sha }}
          path: |
            rules/wazuh/
            converted/kql/
            converted/splunk/
```

### 7.3 Shadow / Experimental Deployment Mode

New rules are **never** deployed directly at production severity. Follow this promotion ladder:

| Stage | Wazuh Level | Duration | Condition to Promote |
|---|---|---|---|
| `experimental` | 3 (informational) | 7 days | Zero FPs in production traffic |
| `test` | 6 (low) | 7 days | TP rate confirmed on next attack run |
| `stable` | 10–12 (high/critical) | Permanent | Passes purple-team evasion test |

---

## 8. Git Workflow

Treat this repo as a professional engineering project. This demonstrates team-readiness to any hiring manager.

### Branch Strategy

| Branch | Purpose |
|---|---|
| `main` | Protected. No direct pushes. CI must pass. Requires PR review. |
| `feature/rule-T<ID>` | New detection rule (e.g., `feature/rule-T1003.001`) |
| `fix/bypass-<number>` | Evasion fix (e.g., `fix/bypass-003`) |
| `infra/week-<N>` | Lab provisioning changes |
| `docs/update-<topic>` | Documentation-only changes |

### Commit Convention

Use **Conventional Commits** format:

```
feat(sigma): add T1003.001 LSASS memory dump detection
fix(sigma): harden T1059.001 to catch base64-encoded commands
test(fixtures): add negative fixture for T1003.001
docs(runbook): add triage runbook for T1021.002
docs(d3fend): add D3FEND mapping for T1059.001
ci: add negative regression test stage to pipeline
infra: add Ansible playbook for Windows DC provisioning
```

### Release Tagging

| Tag | When |
|---|---|
| `v0.1` | CI pipeline is green with first 10 rules |
| `v1.0` | 20+ detections, FP report complete, ATT&CK Navigator layer published |
| `v1.1` | Purple-team hardening complete, bypass log finalised |
| `v2.0` | Blog post live, demo video published, README polished |

---

## 9. Metrics & CV Targets

Track these metrics throughout the project. These are what go on your CV.

| Metric | Target | Where Tracked |
|---|---|---|
| Total Sigma rules | 25–30 | `rules/sigma/` count |
| ATT&CK sub-techniques covered | 20+ | `docs/coverage/navigator_layer.json` |
| True Positive rate | > 90% | `docs/fp_report.md` |
| False Positive rate | < 2% | `docs/fp_report.md` |
| Mean Time to Detect (MTTD) | < 60 seconds | `docs/mttd_metrics.md` |
| Evasion bypasses found | 5–10 | `docs/bypass_log.md` |
| Evasion bypasses fixed | 100% of found | `docs/bypass_log.md` |
| CI pipeline: positive test pass rate | 100% | GitHub Actions |
| CI pipeline: negative test pass rate | 100% | GitHub Actions |
| Multi-SIEM outputs | KQL + SPL + Wazuh XML | `converted/` |
| D3FEND countermeasures mapped | 1 per detection | `docs/d3fend_mapping.md` |
| Threat hunting playbooks | 2 (one per scenario) | `playbooks/` |

---

## 10. CV Bullet Point Templates

Use **Action → Metric → Impact** format. Fill in your actual numbers at the end of the project.

> - Engineered a full detection engineering lab using **Vagrant + Ansible**, deploying Wazuh SIEM, Sysmon, and auditd across a 4-VM AD environment reproducible from a single `vagrant up` command.
>
> - Authored **28 Sigma rules** covering **22 ATT&CK sub-techniques** across Active Directory intrusion and ransomware precursor scenarios, grounded in CISA advisories and the Red Canary Threat Detection Report.
>
> - Built a **Detection-as-Code CI/CD pipeline** (GitHub Actions) that lints, validates, converts rules to Wazuh XML, KQL, and SPL, and runs positive + negative regression tests — breaking the build on any false-negative or false-positive regression.
>
> - Developed a custom **Sigma-to-Wazuh transpiler** in Python (Jinja2 templates + field-mapping table) after identifying the absence of an official pySigma Wazuh backend, enabling automated rule deployment while maintaining Sigma as the vendor-neutral source of truth.
>
> - Conducted purple-team adversarial testing, identifying **6 detection bypasses** via LOLBin substitution, base64 obfuscation, AMSI bypass, and parent-process spoofing; hardened all rules and documented findings in a structured bypass log.
>
> - Maintained a **< 2% false positive rate** and **MTTD < 60 seconds** across all covered techniques, measured against a 4-hour benign baseline dataset using a custom Python log-replay harness.
>
> - Authored SOC analyst **triage runbooks** and **threat hunting playbooks** for all detections, including D3FEND countermeasure mappings, investigation queries (KQL/SPL), escalation criteria, and known false positives.

---

## Appendix — Useful References

| Resource | URL |
|---|---|
| Sigma Rule Specification | https://github.com/SigmaHQ/sigma-specification |
| pySigma Documentation | https://github.com/SigmaHQ/pySigma |
| Atomic Red Team Tests | https://github.com/redcanaryco/atomic-red-team |
| Olaf Hartong Sysmon Config | https://github.com/olafhartong/sysmon-modular |
| Wazuh Documentation | https://documentation.wazuh.com |
| ATT&CK Navigator | https://mitre-attack.github.io/attack-navigator/ |
| MITRE D3FEND Matrix | https://d3fend.mitre.org/ |
| MITRE Caldera | https://github.com/mitre/caldera |
| SigmaHQ Community Rules | https://github.com/SigmaHQ/sigma/tree/master/rules |
| The DFIR Report | https://thedfirreport.com/ |
| SwiftOnSecurity Sysmon Config | https://github.com/SwiftOnSecurity/sysmon-config |
| Wazuh Sysmon Field Mapping Reference | https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/sysmon.html |
