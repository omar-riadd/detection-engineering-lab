# ADR 0001: CQRS-Lite Hybrid Architecture (YAML Files as Source of Truth, SQLite as Derived Read Model)

## Status
Accepted

## Context
Detection engineering workflows require Git-tracked, vendor-neutral rule specifications (Sigma YAML) that undergo rigorous code review, pull request validation, and CI/CD testing. However, modern web user interfaces and SOC dashboards require low-latency indexing, multi-field filtering, full-text searching, aggregated statistics, and real-time event updates.

Treating a traditional SQL database as the primary source of truth introduces "save-to-database" footguns, schema migration debt, drift between Git and runtime environments, and complicates offline detection authoring.

## Decision
We implemented a **CQRS-lite (Command Query Responsibility Segregation) hybrid architecture**:
1. **Source of Truth (Write Side)**: All detection rules are strictly stored as Sigma YAML files in `rules/sigma/windows/` and Git-tracked. Changes are introduced via files or Git.
2. **Derived Read Model (Read Side)**: A local SQLite database running in WAL (Write-Ahead Logging) mode (`api/detection_lab.db`) acts as a disposable read cache.
3. **Reconciliation Engine**:
   - On cold start, the FastAPI lifespan executes a non-blocking reconciliation pass that parses all YAML rules and upserts them into SQLite in < 1 second.
   - At runtime, a `watchdog` file observer detects file modifications and triggers debounced incremental reconciliation, broadcasting `rule_changed` events over WebSockets.
4. **Disposability**: The database can be deleted and reconstructed at any time via `make reset-db` without data loss.

This mirrors proven enterprise architectures:
- **Grafana Alerting**: Provisioned alerting files synchronized to internal SQL stores.
- **Elastic detection-rules**: Git-tracked TOML detection rules synced to Elasticsearch clusters.
- **Argo CD**: Git repository state reconciled to cluster cache.

## Consequences
- **Positive**: Git remains the absolute single source of truth. Offline editing in IDEs is immediately reflected in the UI within 300ms.
- **Positive**: Blazing-fast read queries for filtering, statistics, and dashboards without parsing dozens of YAML files on every HTTP request.
- **Positive**: Zero database migration friction; schema evolutions are resolved by dropping and regenerating the database from YAML.
- **Negative**: Edits must be reconciled through file writes or targeted API endpoints rather than direct DB updates.
