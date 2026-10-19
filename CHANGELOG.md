# Changelog & Detection Debt Register

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

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
