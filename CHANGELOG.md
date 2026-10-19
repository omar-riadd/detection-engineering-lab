# Changelog & Detection Debt Register

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

### Planned for v0.1 (Week 4/5)
- First 10 Sigma rules in `rules/sigma/windows/`
- Triage runbooks in `runbooks/`
- Custom Jinja2-based Sigma to Wazuh XML transpiler in `scripts/convert_sigma.py`
- Automated CI pipeline passing positive and negative regression tests

### Added
- **docs(scope)**: Initial threat intelligence scope, technique selection, and laboratory limitations documentation (`docs/scope.md`) covering 20 ATT&CK sub-techniques across Scenario A (Active Directory Intrusion) and Scenario B (Ransomware Precursor).
- **infra(repo)**: Full project repository layout initialized matching Section 2 of `PROJECT_PLAN.md`.
- **docs(d3fend)**: Initialized MITRE D3FEND countermeasure mapping matrix skeleton (`docs/d3fend_mapping.md`).
- **docs(readme)**: Project overview, telemetry flow architecture diagram, engineering metrics table, and local run instructions (`README.md`).
- **project(tracking)**: Comprehensive multi-phase progress ledger initialized (`Project_progress.md`).

---

## Detection Debt Register

The Detection Debt Register tracks rules requiring maintenance, telemetry review, known tuning opportunities, or potential deprecation.

| Rule ID | Rule Title | Sub-Technique | Identified Date | Debt Type | Description / Remediation Plan | Status |
|---|---|---|---|---|---|---|
| *TBD* | *None active* | - | 2026-10-19 | Tracking | Initial register established during Week 1 setup. | Open |

---

## Version Release Milestones

- **v0.1**: Initial green CI/CD pipeline with 10 production-grade Sigma rules, triage runbooks, and test fixtures.
- **v1.0**: 20+ detections deployed, baseline false positive analysis complete (< 2% FP rate), ATT&CK Navigator layer published.
- **v1.1**: Purple-team adversarial hardening cycle completed, bypass log finalized, evasion variants tested.
- **v2.0**: Presentation-ready release with Wazuh dashboards, project executive report, demo video, and publication.
