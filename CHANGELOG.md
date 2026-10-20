# Changelog & Detection Debt Register

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [v1.1] - 2026-10-21

### Added
- **feat(rules)**: Expanded Sigma detection catalog from 21 to 26 rules (fulfilling Section 1.3 requirement of 25–30 rules) and introduced multi-platform Linux coverage (`rules/sigma/linux/`):
  - `win_proc_comsvcs_lsass_dump.yml` (T1003.001 - LSASS Process Memory MiniDump via Comsvcs DLL)
  - `win_proc_office_spawn_child.yml` (T1566.001 / T1204.002 - Suspicious Child Process Spawning from Microsoft Office Application)
  - `win_proc_powershell_download_cradle.yml` (T1059.001 - PowerShell CLI Download Cradle Execution)
  - `lnx_proc_reverse_shell.yml` (T1059.004 - Interactive Reverse Shell Execution via Common Utilities on Linux)
  - `lnx_auditd_susp_cron_job.yml` (T1053.003 - Persistence via Scheduled Cron Job Modification on Linux)
- **feat(transpiler)**: Multi-SIEM transpilation of all 26 rules into Wazuh XML (with dynamic Linux SID 80700 support), Microsoft Sentinel KQL, and Splunk SPL.
- **feat(fixtures)**: Added positive and negative test fixtures for all new techniques; regression harness expanded to 54 fixtures and 69 automated tests passing with 100% accuracy.
- **feat(ui)**: Svelte 5 (Runes) Field Manual single-page operational application featuring 7 workspaces: Overview (`01`), Rules Catalog (`02`), ATT&CK Matrix (`03`), D3FEND Countermeasures (`04`), Subprocess Replay Engine (`05`), Purple Team Evasions (`06`), and Executive Security Report (`07`).
- **feat(cqrs)**: Hybrid CQRS architecture pairing Git-tracked Sigma YAML as the single source of truth with a disposable SQLite WAL read model, Watchdog file watching, and a full two-way write path (`PUT /api/rules/{id}/save`).
- **feat(api-tests)**: Comprehensive FastAPI backend integration and unit test suite in `tests/test_api.py` validating all REST endpoints, validation errors (HTTP 422), and multi-format exports.
- **feat(streaming)**: Asynchronous non-blocking subprocess streaming over WebSockets (`/ws/replay` and `/ws/test-runner`) persisting execution telemetry to SQLite.
- **feat(reports)**: Dynamic SOC Executive Security Report generator (`GET /api/reports/summary`, `/markdown`) with `@media print` formatting and instant Markdown export.
- **feat(offline)**: Air-gapped typography resilience resolving TD-01 with a zero-latency system monospace fallback chain.
- **feat(ci)**: Upgraded local and remote CI pipeline (`make ci` and `.github/workflows/ci.yml`) enforcing 100% pass across detections, API tests, log replay, and frontend TypeScript build.

---

## [v1.0] - 2026-10-19

### Added
- **feat(detections)**: 21 production-grade Sigma detection rules authored in `rules/sigma/windows/` covering 20 MITRE ATT&CK sub-techniques across Scenario A (Active Directory Intrusion) and Scenario B (Ransomware Precursor).
- **feat(runbooks)**: 20 SOC analyst triage runbooks in `runbooks/` with immediate response steps, KQL investigation queries, escalation criteria, and MITRE D3FEND countermeasure mappings.
- **feat(transpiler)**: Custom Jinja2 transpiler in `scripts/convert_sigma.py` converting Sigma YAML into native Wazuh XML rules, Microsoft Sentinel KQL, and Splunk SPL.
- **feat(ci)**: Automated 6-stage Detection-as-Code CI/CD pipeline in `.github/workflows/ci.yml` running YAML linting, `sigma-cli` validation, transpilation, and regression testing.
- **feat(purple-team)**: Adversarial evasion testing across 7 classes documented in `docs/bypass_log.md` with 100% bypass mitigation rate.
- **feat(fixtures)**: 27 positive attack/evasion fixtures and 20 negative benign fixtures in `tests/fixtures/`.
- **feat(dashboards)**: Wazuh & OpenSearch saved objects dashboard definition in `infra/dashboards/wazuh_detection_dashboard.ndjson` with alert volume, ATT&CK heatmap, FP vs TP trend, and MTTD gauge.
- **feat(routing)**: Wazuh alert routing policy in `infra/wazuh/ossec_alert_routing.conf` prioritizing Level >= 10/12 alerts to dedicated indices and email/webhook dispatch.
- **feat(playbooks)**: 2 hypothesis-driven threat hunting playbooks (`playbooks/hunt_credential_access.md` and `playbooks/hunt_ransomware_precursor.md`).
- **feat(metrics)**: ATT&CK Navigator layer (`docs/coverage/navigator_layer.json`), MTTD benchmarks (`docs/mttd_metrics.md`), and False Positive report (`docs/fp_report.md`).
- **docs(report)**: Executive project final report in `docs/report.md`, technical blog post draft in `docs/blog_post.md`, and 3-minute demo script in `docs/demo_walkthrough.md`.

---

## [v0.1] - 2026-10-19

### Added
- Initial 10 Sigma rules for Scenario A Active Directory intrusion chain.
- 10 triage runbooks for Scenario A detections.
- Automated CI regression harness with initial positive and negative log fixtures.
- Custom Sigma-to-Wazuh transpiler base with field mapping table and documentation in `docs/sigma_to_wazuh_notes.md`.
- Infrastructure-as-Code multi-machine Vagrantfile and Ansible playbooks in `infra/`.

---

## Detection Debt Register

The Detection Debt Register tracks rules requiring maintenance, telemetry review, known tuning opportunities, or potential deprecation.

| Rule ID | Rule Title | Sub-Technique | Identified Date | Debt Type | Description / Remediation Plan | Status |
|---|---|---|---|---|---|---|
| `DEBT-001` | `win_file_mass_ransomware_activity.yml` | T1486 | 2026-10-19 | Telemetry Dependency | Sysmon lacks native file-rename events; mass encryption relies on EID 11 burst file creation and Security EID 4663 handles. Plan to evaluate Windows Minifilter driver or ETW `Microsoft-Windows-Kernel-File` for high-performance I/O rate monitoring. | Active Review |
| `DEBT-002` | `posh_pm_susp_script_block.yml` | T1059.001 | 2026-10-19 | Evasion Resilience | Relies on userland Script Block Logging (EID 4104). Sophisticated loaders could attempt unhooking or memory patching `EtwEventWrite`. Plan to complement with kernel-level ETW Threat Intelligence provider (`Microsoft-Windows-Threat-Intelligence`). | Monitored |
| `DEBT-003` | `win_sec_susp_rdp_lateral_logon.yml` | T1021.001 | 2026-10-19 | Behavioral Profiling | Relies on Security EID 4624 LogonType 10. While baseline tuning achieved 0 FP in the lab, enterprise deployment requires pairing with User & Entity Behavior Analytics (UEBA) to model anomalous source-workstation pairing. | In Backlog |
| `DEBT-004` | `win_sysmon_net_susp_c2_exfil.yml` | T1041 | 2026-10-19 | Threat Intel Integration | Flags non-browser LOLBins connecting externally. Plan to enrich with automated C2 threat intelligence feed IP reputation matching via Wazuh CDB lists. | Planned (v1.1) |
| `DEBT-005` | `win_registry_run_keys_persistence.yml` | T1547.001 | 2026-10-19 | Maintenance / Whitelisting | Third-party auto-updaters (Google Update, Edge Update) periodically refresh Run keys. Requires recurring quarterly review of signed vendor exclusions. | Recurring |

---

## Version Release Milestones

- **v0.1**: Initial green CI/CD pipeline with 10 production-grade Sigma rules, triage runbooks, and test fixtures.
- **v1.0**: Complete portfolio with 21 Sigma rules, 20 ATT&CK sub-techniques, 20 runbooks, 2 threat hunting playbooks, purple-team hardening (7 evasions fixed), MTTD metrics (< 7s avg), 0% FP rate, Wazuh dashboards, alert routing, and final executive report.
- **v1.1**: Integration of Wazuh CDB threat intelligence lists and external ETW kernel telemetry providers.
- **v2.0**: Cloud-native Terraform deployment for AWS/Azure Sentinel and container security telemetry expansion.
