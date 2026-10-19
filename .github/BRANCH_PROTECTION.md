# Branch Protection & Pull Request Policy

> **Governing Plan:** [PROJECT_PLAN.md](../PROJECT_PLAN.md) — Section 8 (Git Workflow)

---

## 1. Protected Branch: `main`

The `main` branch serves as the production-ready source of truth. All changes entering `main` must adhere to these policies:

### Policy Rules
1. **No Direct Pushes**: Direct pushes to `main` are disallowed. All changes must be proposed via feature or fix branches.
2. **Pull Request Required**: Every change must enter `main` via a Pull Request (PR) merged with a merge commit or squash commit following Conventional Commits.
3. **Mandatory CI Status Check**: The GitHub Actions workflow `Detection Engineering CI` (`validate-convert-test`) must pass 100% cleanly before merge authorization.
   - Stage 1: YAML Lint
   - Stage 2: Sigma CLI Validation (`sigma check`)
   - Stage 3: Conversion to Wazuh XML, KQL, and SPL
   - Stage 4: Positive Regression Tests (all positive fixtures must trigger detections)
   - Stage 5: Negative Regression Tests (no baseline/benign fixtures may trigger detections)
4. **Up-to-Date Branches**: Branches must be rebased or merged with latest `main` prior to merging.

---

## 2. Branch Naming Scheme

| Branch Type | Convention | Example |
|---|---|---|
| New Detection Rule | `feature/rule-T<ID>` | `feature/rule-T1003.001` |
| Purple-Team Evasion Fix | `fix/bypass-<number>` | `fix/bypass-003` |
| Lab Infrastructure | `infra/week-<N>` | `infra/week-2-wazuh` |
| Documentation Updates | `docs/update-<topic>` | `docs/update-d3fend-matrix` |

---

## 3. Commit Message Standards

Conventional Commits format is strictly enforced:
- `feat(sigma): ...`
- `fix(sigma): ...`
- `test(fixtures): ...`
- `docs(runbook): ...`
- `docs(d3fend): ...`
- `ci: ...`
- `infra: ...`
