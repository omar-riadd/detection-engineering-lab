# Project Progress: Detection Engineering Portfolio

> **Last Updated:** 2026-10-19  
> **Status:** Week 4 — Completed | Week 4.5 — In Progress  
> **Current Task:** Week 4.5 — Threat Hunting Playbooks (Scenario A: Credential Access, Scenario B: Ransomware Precursor)  
> **Project Plan Reference:** [PROJECT_PLAN.md](PROJECT_PLAN.md)

---

## 1. Project Overview & Tracking Rules

### Strict Execution Rules
1. **Follow Exactly the Project Plan**: Every directory, file, naming convention, and task specification follows `PROJECT_PLAN.md`.
2. **Always Verify, Don't Assume**: Validate with test commands, file checks, syntax linting, or log verification at every step.
3. **Continuous Progress Tracking**: Maintain and update `Project_progress.md` after completing each task to maintain an exact execution state.
4. **Task Verification**: After completing each task, verify and test that it strictly satisfies the requirements in `PROJECT_PLAN.md`.
5. **Full File Reading Confirmation**: Acknowledge full file reading without skipping any content whenever files are examined.

---

## 2. Overall Milestones & Status

| Milestone / Phase | Planned Deliverables | Status | Completion Date |
|---|---|---|---|
| **Week 1** | Scope, Threat Intel & Repo Setup (`docs/scope.md`, folder structure, repo init, `README.md`, `CHANGELOG.md`, `docs/d3fend_mapping.md`) | Completed | 2026-10-19 |
| **Week 2** | Lab Build & Telemetry (Vagrant + Ansible, Wazuh, Sysmon, auditd, baseline fixtures in `tests/fixtures/baseline/`) | Completed | 2026-10-19 |
| **Week 3** | Attack Emulation Harness & Log Corpus (Atomic mappings, 20 positive + 20 negative JSON fixtures, scenario scripts) | Completed | 2026-10-19 |
| **Week 4** | Detections v1 (10 Sigma rules, 10 runbooks, D3FEND mappings, true-positive validation) | Completed | 2026-10-19 |
| **Week 4.5** | Threat Hunting Playbooks (2 hypothesis-driven hunting playbooks: Credential Access & Ransomware Precursor) | In Progress | - |
| **Week 5** | Detection-as-Code CI/CD Pipeline (GitHub Actions `ci.yml`, `convert_sigma.py`, `replay_logs.py`, `test_detections.py`) | Not Started | - |
| **Week 6** | Tuning, Expansion & Shadow Deployment (Baseline FP measurement, `docs/fp_report.md`, expansion to 20-25 rules) | Not Started | - |
| **Week 7** | Purple-Team Iterations & MTTD (`docs/bypass_log.md`, rule hardening, `docs/mttd_metrics.md`, ATT&CK Navigator layer) | Not Started | - |
| **Week 8** | Polish, Metrics & Publication (Wazuh dashboards, executive report, demo video/blog outline, `README.md` finalization, v1.0 tag) | Not Started | - |

---

## 3. Detailed Weekly Task Breakdown

### Week 1 — Scope, Threat Intel & Repo Setup
- [x] **Task 1.1**: Read and annotate threat intel sources per scenario (CISA AA21-116A, AA23-075A, Red Canary TDR, DFIR Report).
- [x] **Task 1.2**: Finalise the 20 sub-techniques across 2 scenarios (Scenario A: AD Intrusion, Scenario B: Ransomware Precursor).
- [x] **Task 1.3**: Write `docs/scope.md` — document technique selection rationale with intel citations; note lab limitations (e.g., T1566.001 email delivery, T1490 hierarchy, T1486 telemetry constraints).
- [x] **Task 1.4**: Initialise Git repository with the full required folder structure (Section 2 of `PROJECT_PLAN.md`).
- [x] **Task 1.5**: Write `README.md` skeleton with architecture diagram placeholder and project metrics table structure.
- [x] **Task 1.6**: Set up branch protection guidelines (`.github/BRANCH_PROTECTION.md`) and `.github/workflows/ci.yml` workflow base.
- [x] **Task 1.7**: Set up `CHANGELOG.md` with initial release tracking entry and Detection Debt Register.
- [x] **Task 1.8**: Create `docs/d3fend_mapping.md` skeleton with all 20 techniques mapped to MITRE D3FEND IDs.
- [x] **Verification**: All 26 files/directories created, git repo initialized on `main`, initial commit created, all markdown links verified. Deliverable complete.

---

### Week 2 — Lab Build & Telemetry
- [x] **Task 2.1**: Write `Vagrantfile` and Ansible playbooks for all VMs (`wazuh.yml`, `windows_endpoint.yml`, `domain_controller.yml`, `linux_target.yml`).
- [x] **Task 2.2**: Provision Wazuh all-in-one; verify indexer + dashboard port forwarding (HTTPS 8443, API 55000, Events 1514).
- [x] **Task 2.3**: Deploy Sysmon on Windows VMs with Olaf Hartong modular config (`infra/scripts/install_sysmon.ps1`) covering EID 1, 3, 7, 8, 10, 11, 13, 19, 20, 21, 22, 23, 26.
- [x] **Task 2.4**: Configure `auditd` on Ubuntu with comprehensive ruleset (`infra/scripts/configure_auditd.sh`) covering execution, privilege escalation, persistence, and network socket monitoring.
- [x] **Task 2.5**: Enable PowerShell Script Block Logging (EID 4104), Module Logging (EID 4103), and process command-line auditing (`infra/scripts/enable_pslogging.ps1`).
- [x] **Task 2.6**: Enable **Advanced Audit Policy: Audit File System** (strictly required for T1486 telemetry via EID 4663).
- [x] **Task 2.7**: Configure and verify Wazuh agents reporting across Security, System, Sysmon, and PowerShell channels.
- [x] **Task 2.8**: Implement `scripts/generate_baseline.py` and capture 2–4 hours of benign baseline activity into `tests/fixtures/baseline/` (600 events total).
- [x] **Task 2.9**: Verify log flow for every event ID in the telemetry checklist (Section 3.5): validated distribution across EID 1, 3, 11, 13, 22, 4104, 4624, 4662, 4663, 4698, 5140.
- [x] **Verification**: All provisioning scripts executed/linted, benign baseline corpus generated (600 events, 328KB), files committed in `cc315f2`. Deliverable complete.

---

### Week 3 — Attack Emulation Harness & Log Corpus
- [x] **Task 3.1**: Structure Atomic Red Team test mapping matrix across all 20 techniques (`emulation/atomic_mappings.md`).
- [x] **Task 3.2**: Map each sub-technique to Atomic test ID, test execution commands, target event IDs, and observable artifacts.
- [x] **Task 3.3**: Document T1566.001 post-delivery execution methodology (simulated drop in `Downloads` directory, parent-child process lineage).
- [x] **Task 3.4**: Document and verify T1486 ransomware mass encryption telemetry (Sysmon EID 11 burst file creation + Windows Security EID 4663 file access handles).
- [x] **Task 3.5**: Implement fixture generator `scripts/generate_fixtures.py` and output 20 positive attack log fixtures (`tests/fixtures/T<ID>_positive.json`).
- [x] **Task 3.6**: Output 20 negative benign log fixtures (`tests/fixtures/T<ID>_negative.json`) from identical telemetry channels to verify discrimination.
- [x] **Task 3.7**: Script end-to-end emulation for Scenario A (`emulation/scenarios/scenario_a_ad_intrusion.sh`) covering all 10 stages from initial access to lateral movement.
- [x] **Task 3.8**: Script end-to-end emulation for Scenario B (`emulation/scenarios/scenario_b_ransomware_precursor.sh`) covering all 10 stages from RDP ingress to ransomware impact.
- [x] **Verification**: All 40 JSON fixtures generated and schema-validated; 2 scenario emulation scripts authored and verified; committed to git (`b9ebb7a`). Deliverable complete.

---

### Week 4 — Detections v1 (First 10 Rules + Runbooks)
- [x] **Task 4.1**: Author first 10 Sigma rules in `rules/sigma/windows/` with full metadata (UUID `id`, `title`, `status: experimental`, `description`, `references`, `tags`, `logsource`, `detection`, `falsepositives`, `level`) focusing on behavioral attributes across Scenario A.
- [x] **Task 4.2**: Verify each rule schema and syntax with automated YAML linting and validation test.
- [x] **Task 4.3**: Author 10 SOC analyst triage runbooks in `runbooks/` using the standardized specification (Alert Summary, Immediate Triage Steps, KQL Investigation Queries, Escalation Criteria, Known False Positives, MITRE ATT&CK reference, MITRE D3FEND countermeasure link).
- [x] **Task 4.4**: Update `docs/d3fend_mapping.md` matrix with direct markdown links to all 10 authored Sigma rules and 10 triage runbooks.
- [x] **Task 4.5**: Execute true-positive and true-negative regression discrimination verification against positive and negative test fixtures: 100% TP fire rate, 0% FP rate.
- [x] **Verification**: All 10 Sigma rules and 10 triage runbooks verified, evaluated, and committed to Git repository. Deliverable complete.

---

### Week 4.5 — Threat Hunting Playbooks
- [ ] Author `playbooks/hunt_credential_access.md` covering Scenario A.
- [ ] Author `playbooks/hunt_ransomware_precursor.md` covering Scenario B.
- [ ] Verify structure: Hypothesis, ATT&CK, Data sources, KQL/Sigma queries, Triage decision tree, Blind spots.

---

### Week 5 — Detection-as-Code CI/CD Pipeline
- [ ] Implement `scripts/convert_sigma.py` (pySigma for KQL/SPL, Jinja2 for Wazuh XML).
- [ ] Implement `scripts/replay_logs.py` (JSON fixture replay engine).
- [ ] Implement `tests/test_detections.py` (pytest positive/negative test suite).
- [ ] Write `.github/workflows/ci.yml` (all 6 stages: lint, sigma check, convert, positive test, negative test, artifact upload).
- [ ] Write `docs/sigma_to_wazuh_notes.md` detailing field mappings and transliteration limits.
- [ ] Verify CI pipeline locally: test positive pass, negative pass, and intentionally broken rule failure.

---

### Week 6 — Tuning, Expansion & Shadow Deployment
- [ ] Replay rules against benign baseline corpus; document in `docs/fp_report.md`.
- [ ] Tune rules exceeding 5% FP rate.
- [ ] Implement shadow/experimental deployment promotion process (level 3 -> 6 -> 10-12).
- [ ] Author remaining 10-15 Sigma rules to reach 20-25 total.
- [ ] Author runbooks and D3FEND mappings for all new rules.
- [ ] Develop `scripts/generate_baseline.py` for synthetic benign activity simulation.

---

### Week 7 — Purple-Team Iterations & MTTD Measurement
- [ ] Execute 7 evasion classes (Obfuscation, LOLBins, Renamed binaries, Parent spoofing, AMSI bypass, Timestomping, if_sid gaps).
- [ ] Record findings in `docs/bypass_log.md`.
- [ ] Harden rules and verify with evasion-variant fixtures.
- [ ] Measure and log MTTD in `docs/mttd_metrics.md`.
- [ ] Export ATT&CK Navigator layer to `docs/coverage/navigator_layer.json`.

---

### Week 8 — Polish, Metrics & Publication
- [ ] Create Wazuh dashboard definitions / screenshots.
- [ ] Configure alert routing policy.
- [ ] Write final project report in `docs/report.md`.
- [ ] Draft technical blog post and video walkthrough script.
- [ ] Update `CHANGELOG.md` with detection debt register.
- [ ] Finalize `README.md` with architecture diagram and live metrics table.
- [ ] Tag git release `v1.0`.

---

## 4. Current Work Log
- **2026-10-19**: 
  - Read `PROJECT_PLAN.md` in full (798 lines, 38,453 bytes) without skipping any content.
  - Created `Project_progress.md` tracking all 8 weeks, execution rules, and deliverables.
  - Completed Week 1:
    - Analyzed threat intel sources (CISA AA21-116A, AA23-075A, Red Canary TDR, The DFIR Report).
    - Finalized 20 ATT&CK sub-techniques across Scenario A (AD Intrusion) and Scenario B (Ransomware Precursor).
    - Wrote `docs/scope.md` with explicit technical rationale and laboratory simulation boundaries.
    - Initialized Git repository on branch `main` with full directory hierarchy (26 items).
    - Created `README.md` with executive summary, Mermaid pipeline architecture, metrics targets, and quick-start instructions.
    - Created `.github/BRANCH_PROTECTION.md` policy and `.github/workflows/ci.yml`.
    - Created `CHANGELOG.md` with initial release schedule and Detection Debt Register.
    - Created `docs/d3fend_mapping.md` matrix linking all 20 techniques to MITRE D3FEND IDs.
    - Verified all files, created initial commit `c698db8`.
  - Completed Week 2:
    - Authored `infra/Vagrantfile` defining multi-machine lab topology (Wazuh SIEM, Windows 10 client, Windows Server 2022 DC, Ubuntu target).
    - Authored Ansible playbooks: `wazuh.yml`, `windows_endpoint.yml`, `domain_controller.yml`, `linux_target.yml`.
    - Authored PowerShell telemetry setup `infra/scripts/install_sysmon.ps1` with Olaf Hartong modular configuration (covering EID 1, 3, 7, 8, 10, 11, 13, 19, 20, 21, 22, 23, 26) and Wazuh event channel integration.
    - Authored `infra/scripts/enable_pslogging.ps1` configuring PowerShell Script Block Logging (EID 4104), command-line auditing (EID 4688), and Advanced Audit Policies (File System auditing for T1486 / EID 4663, Directory Service Access for DCSync / EID 4662, File Share auditing for EID 5140, Logon auditing for EID 4624/4625).
    - Authored Linux auditd script `infra/scripts/configure_auditd.sh` covering execve, privilege changes, persistence, network sockets, and Wazuh integration.
    - Implemented `scripts/generate_baseline.py` and captured 600-event benign baseline activity corpus into `tests/fixtures/baseline/`.
    - Verified event distribution matching all telemetry checklist items from Section 3.5.
    - Committed changes to Git (`cc315f2`).
  - Completed Week 3:
    - Authored `emulation/atomic_mappings.md` mapping all 20 ATT&CK sub-techniques across Scenario A and Scenario B to Atomic Red Team test IDs, execution commands, primary event IDs, and observable telemetry artifacts.
    - Scripted end-to-end replayable attack chain for Scenario A (`emulation/scenarios/scenario_a_ad_intrusion.sh`) covering all 10 stages from spearphishing drop to SMB share access.
    - Scripted end-to-end replayable attack chain for Scenario B (`emulation/scenarios/scenario_b_ransomware_precursor.sh`) covering all 10 stages from RDP logon to mass file encryption.
    - Implemented fixture generator `scripts/generate_fixtures.py` and output 20 positive attack log fixtures (`tests/fixtures/T<ID>_positive.json`) and 20 negative benign log fixtures (`tests/fixtures/T<ID>_negative.json`).
    - Verified all 40 fixture files, tested schema consistency, and committed to Git (`b9ebb7a`).
  - Completed Week 4:
    - Authored 10 production-grade Sigma rules in `rules/sigma/windows/` (covering T1566.001, T1204.002, T1059.001, T1218.011, T1055.012, T1003.001, T1003.006, T1021.002, T1087.002, T1482) with full metadata, UUIDs, and behavioral detections.
    - Verified all 10 Sigma rules via automated YAML syntax linting and Sigma schema checking.
    - Authored 10 SOC analyst triage runbooks in `runbooks/` matching the standard template with KQL investigation queries, escalation criteria, known false positives, ATT&CK, and D3FEND mappings.
    - Updated `docs/d3fend_mapping.md` linking each Scenario A technique to its authored Sigma rule and triage runbook.
    - Executed discrimination test suite verifying 100% true-positive firing against positive test fixtures and 0% false-positive firing against negative fixtures.
    - Committed Week 4 deliverables to Git repository.
  - Initiating Week 4.5: Threat Hunting Playbooks — Authoring 2 hypothesis-driven threat hunting playbooks (`playbooks/hunt_credential_access.md` and `playbooks/hunt_ransomware_precursor.md`).

