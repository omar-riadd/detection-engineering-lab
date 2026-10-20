# Detection Engineering Lab — UI Plan
> Last updated: 2026-10-21  
> Status: Phase 1, Phase 2, and Phase 3 implementation complete and verified. Full CQRS write path (in-browser Sigma editor), Executive Report Generator, Telemetry Analytics, and air-gapped typography fully delivered.

---

## Table of Contents
1. [Project Summary](#1-project-summary)
2. [Architecture: CQRS-Lite Hybrid Backend](#2-architecture-cqrs-lite-hybrid-backend)
3. [Technical Stack](#3-technical-stack)
4. [Directory Structure](#4-directory-structure)
5. [Database Schema](#5-database-schema)
6. [API Endpoints](#6-api-endpoints)
7. [Frontend: Svelte 5 Pages](#7-frontend-svelte-5-pages)
8. [File Watcher + WebSocket Broadcast](#8-file-watcher--websocket-broadcast)
9. [Design System: Field Manual](#9-design-system-field-manual)
10. [Build and Dev Workflow](#10-build-and-dev-workflow)
11. [CV / Portfolio Value](#11-cv--portfolio-value)
12. [Known Issues — Round 1 (BUG-01 to BUG-05)](#12-known-issues--round-1-bug-01-to-bug-05)
13. [Second-Check Findings (Additional Bugs)](#13-second-check-findings-additional-bugs)
14. [Brainstorming: Phase 2 Ideas](#14-brainstorming-phase-2-ideas)

---

## 1. Project Summary

The Detection Engineering Lab UI is a single-page web application that provides a live, read-only dashboard over the 21 Sigma rules, 48 test fixtures, bypass case studies, and ATT&CK coverage metrics stored in YAML/JSON/Markdown files on disk.

**Key design constraints:**
- YAML files are source of truth; the SQLite DB is a disposable read model
- No mocked/placeholder data — every number comes from real project files
- "Field Manual" aesthetic: monospace, zero rounded corners, newsprint palette
- 48 existing pytest tests must not be broken

---

## 2. Architecture: CQRS-Lite Hybrid Backend

```
┌─────────────────────────────────────────────────────────────┐
│  Source of Truth (Git-tracked)                              │
│  rules/sigma/**/*.yml   tests/fixtures/**/*.json            │
│  docs/bypass_log.md     docs/coverage_notes.md             │
└──────────────────┬──────────────────────────────────────────┘
                   │  sync_sigma_rule()     (cold-start)
                   │  sync_bypass_log()     (cold-start)
                   │  FileWatcher           (incremental)
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  SQLite Read Model  (detection_lab.db — WAL mode)           │
│  tables: rules, bypass_attempts, test_runs                  │
└──────────────────┬──────────────────────────────────────────┘
                   │  SQLAlchemy 2.0 Session
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  FastAPI  (api/)                                            │
│  REST: /api/rules  /api/coverage  /api/bypass  /api/sync    │
│  WS:   /ws/events  /ws/test-runner  /ws/replay             │
└──────────────────┬──────────────────────────────────────────┘
                   │  HTTP + WebSocket
                   ▼
┌─────────────────────────────────────────────────────────────┐
│  Svelte 5 SPA  (ui/src/)                                    │
│  RulesPage  CoveragePage  BypassPage  ReplayPage  DashPage  │
└─────────────────────────────────────────────────────────────┘
```

**Why this pattern?**
- Git stays authoritative — no "save to DB" footguns
- DB is rebuilt from YAML in seconds on cold start → no migration headaches
- Identical to production patterns: Argo CD (Git → etcd), Elastic detection-rules (Git → Elasticsearch), Grafana provisioned alerting (YAML → Postgres)

---

## 3. Technical Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| API framework | FastAPI | 0.141.1 |
| ORM / DB driver | SQLAlchemy 2.0 + aiosqlite | 2.0.52 / 0.21.0 |
| DB | SQLite (WAL mode) | system |
| File watching | watchdog | 6.0.0 |
| YAML parsing | PyYAML | system |
| ASGI server | uvicorn | 0.53.0 |
| Frontend | Svelte 5 (runes) | 5.x |
| Frontend build | Vite | 6.x |
| TypeScript | tsc | 5.x |
| Node.js | node | 24.21.0 |
| npm | npm | 11.19.0 |

---

## 4. Directory Structure

```
Detection Engineering/
├── api/
│   ├── main.py                  # FastAPI app, lifespan, CORS, static mount
│   ├── core/
│   │   ├── reconciler.py        # File-to-SQLite projector (CQRS write side)
│   │   ├── watcher.py           # watchdog FileWatcher → incremental sync
│   │   └── ws_manager.py        # WebSocket connection manager (broadcast)
│   ├── models/
│   │   └── db.py                # SQLAlchemy models: Rule, BypassAttempt, TestRun
│   └── routers/
│       ├── rules.py             # GET /api/rules, GET /api/rules/{id}
│       ├── coverage.py          # GET /api/coverage/attack, GET /api/coverage/mttd
│       ├── bypass.py            # GET /api/bypass
│       ├── sync.py              # POST /api/sync/trigger
│       └── websocket.py        # WS /ws/events, /ws/test-runner, /ws/replay
├── ui/
│   ├── index.html
│   ├── vite.config.ts           # /api proxy → localhost:8001
│   ├── tsconfig.json
│   └── src/
│       ├── app.css              # Field Manual design tokens
│       ├── App.svelte           # Root: router + WS event bridge
│       ├── lib/
│       │   └── api.ts           # Typed fetch wrappers, TypeScript interfaces
│       └── routes/
│           ├── DashPage.svelte
│           ├── RulesPage.svelte
│           ├── CoveragePage.svelte
│           ├── BypassPage.svelte
│           └── ReplayPage.svelte
├── Makefile                     # make api / make ui / make dev / make test / make replay
├── UI_plan.md                   # This file
└── detection_lab.db             # SQLite read model (gitignored; derived)
```

---

## 5. Database Schema

### `rules` table
| Column | Type | Notes |
|--------|------|-------|
| id | TEXT PK | Sigma rule `id` field (UUID) or filename stem |
| title | TEXT | `title` field from YAML |
| description | TEXT | `description` field |
| status | TEXT | experimental / test / stable |
| severity | TEXT | low / medium / high / critical |
| techniques | TEXT | pipe-separated: `T1059.001|T1059.003` |
| tactics | TEXT | pipe-separated: `execution|defense_evasion` |
| category | TEXT | logsource.category |
| log_source_product | TEXT | logsource.product |
| log_source_service | TEXT | logsource.service |
| file_path | TEXT | Absolute path on disk |
| raw_yaml | TEXT | Full YAML content |
| sha256 | TEXT | Hash used to skip unchanged files on re-sync |
| sync_status | TEXT | synced / error |
| sync_error | TEXT | Parser error message if sync failed |
| synced_at | DATETIME | UTC timestamp of last sync |

### `bypass_attempts` table
| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER PK | Auto-increment |
| technique | TEXT | Human-readable technique name |
| technique_id | TEXT | ATT&CK ID: T1059.001 |
| evasion_method | TEXT | What the attacker did |
| outcome | TEXT | DETECTED / EVADED / PARTIAL |
| rule_hardened | TEXT | Which rule was improved |
| notes | TEXT | Prose notes |
| synced_at | DATETIME | UTC |

### `test_runs` table
| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER PK | Auto-increment |
| run_type | TEXT | pytest / replay |
| rule_id | TEXT | NULL for full suite runs |
| exit_code | INTEGER | 0 = pass |
| started_at | DATETIME | UTC |
| completed_at | DATETIME | UTC |
| output_snippet | TEXT | Last 2000 chars of combined stdout |

---

## 6. API Endpoints

### REST

| Method | Path | Returns |
|--------|------|---------|
| GET | `/api/health` | `{status, version, ws_clients}` |
| GET | `/api/rules` | Array of Rule objects |
| GET | `/api/rules/{id}` | Single Rule with raw YAML |
| GET | `/api/coverage/attack` | ATT&CK heatmap data + legend |
| GET | `/api/coverage/mttd` | MTTD metrics per rule |
| GET | `/api/bypass` | All bypass case studies |
| POST | `/api/sync/trigger` | Force full re-sync from YAML files |

### WebSocket

| Path | Direction | Protocol |
|------|-----------|----------|
| `/ws/events` | Server → Client | Push `rule_changed` events on file save |
| `/ws/test-runner` | Bidirectional | Client sends `run_all`/`run_tests`, server streams pytest stdout |
| `/ws/replay` | Bidirectional | Client sends `replay_all`/`replay`, server streams script output |

---

## 7. Frontend: Svelte 5 Pages

### DashPage
- Stats: rule count, test pass rate, techniques covered, bypass cases
- Live status badge: file watcher connected / disconnected
- Recent sync log: last N file-change events from `/ws/events`

### RulesPage
- Full table of all 21 rules: title, severity badge, status, tactics, techniques
- Filter by severity, status, tactic
- Click row → rule detail drawer (raw YAML, test status)

### CoveragePage
- ATT&CK heatmap grid: each detected technique = coloured cell
- Score legend: [HIGH] ≥90 / [MED] ≥80 / [LOW] ≥60 / [NONE] <60
- Click cell → technique detail panel
- MTTD table: rules sorted by detection latency, coloured bar chart

### BypassPage
- Table of all purple-team bypass cases
- Columns: technique ID, evasion method, outcome, rule hardened
- Status badge: [DETECTED] / [EVADED] / [PARTIAL]

### ReplayPage
- Two panels: Log Replay Engine + Full Test Suite (pytest)
- Radio: all rules / single rule (dropdown)
- Live terminal output streamed via WebSocket (PYTHONUNBUFFERED=1)
- Exit code badge: [PASS] / [FAIL]

---

## 8. File Watcher + WebSocket Broadcast

```
YAML file saved on disk
        │
        ▼
watchdog FileSystemEventHandler.on_modified()
        │
        ▼  asyncio.run_coroutine_threadsafe()
        │  (watchdog runs in OS thread; must cross to asyncio loop)
        ▼
reconciler.sync_sigma_rule(path, session)
        │
        ▼
ws_manager.broadcast({"event": "rule_changed", "rule_id": ..., "action": ...})
        │
        ▼
All connected /ws/events clients receive push notification
```

Key technical detail: watchdog callbacks run in a background OS thread. To update SQLite (thread-safe with WAL) and then call the async `ws_manager.broadcast()`, the watcher uses `asyncio.run_coroutine_threadsafe(coro, loop)` with the stored event loop reference.

---

## 9. Design System: Field Manual

All UI tokens defined in `ui/src/app.css`:

```css
/* Palette */
--paper-1: #f5f0e8;   /* page background — warm newsprint */
--paper-2: #ede8d8;   /* card/surface */
--ink-1:   #1a1812;   /* primary text */
--ink-2:   #4a4538;   /* secondary */
--ink-3:   #8a8070;   /* muted */
--amber:   #b8860b;   /* warnings, medium severity */
--red:     #8b1a1a;   /* critical, fail */
--green:   #2d5a27;   /* pass, detected */
--blue:    #1a3a5c;   /* info, technique IDs */

/* Typography */
--font-mono: 'JetBrains Mono', 'Courier New', monospace;
/* All text is monospace — no sans-serif anywhere */

/* Shape */
/* border-radius: 0 everywhere — zero rounded corners */
/* --border: 1px solid #c8bfa8 */
```

Status labels follow `[LABEL]` ASCII convention:
- `[PASS]` `[FAIL]` `[SYNCED]` `[ERROR]` `[HIGH]` `[MED]` `[LOW]`

---

## 10. Build and Dev Workflow

```bash
# Development (two terminals)
make api    # Terminal 1: FastAPI on :8001 with --reload
make ui     # Terminal 2: Vite dev server on :5173 (proxies /api → :8001)

# Production (single server)
make build  # npm run build → ui/dist/; then FastAPI serves / as static SPA

# Other
make test   # pytest tests/ -v --no-header --tb=short
make replay # scripts/replay_logs.py --type all --verbose
make sync-status   # quick DB health check
make rebuild-db    # drop + rebuild SQLite from YAML files
make clean         # remove detection_lab.db + ui/dist + __pycache__
```

---

## 11. CV / Portfolio Value

| Concept | Demonstrated By |
|---------|----------------|
| CQRS read model pattern | Files → SQLite reconciler; incremental sync on change |
| GitOps "source of truth" | YAML files are never mutated through the UI |
| Async subprocess streaming | `asyncio.create_subprocess_exec` + WebSocket line-by-line |
| File system event handling | watchdog + asyncio thread-crossing pattern |
| FastAPI lifespan pattern | Cold-start reconciliation + watcher in `@asynccontextmanager` |
| Svelte 5 runes | `$state`, `$derived`, `$effect` — current 2025 API |
| ATT&CK heatmap | Custom CSS grid without heavy charting libraries |
| Purple team data | Real bypass cases → parsed Markdown → visualised in UI |

---

## 12. Known Issues — Round 1 (BUG-01 to BUG-05)

### BUG-01 — Wrong CLI flags in `/ws/replay` endpoint ✅ FIXED

**File:** `api/routers/websocket.py` lines 156–159  
**Root cause:** `--all` and `--rule` flags do not exist in `scripts/replay_logs.py`. Actual flags: `--type [all|positive|negative|baseline]`, `--rules` (dir), `--fixtures` (dir), `--verbose`.  
**Fix applied:**
```python
# replay_all: use --type all --verbose
cmd = [python_exe, "-u", "scripts/replay_logs.py", "--type", "all", "--verbose"]

# per-rule replay: fall back to pytest -k since replay_logs.py can't filter by rule ID
cmd = [python_exe, "-u", "-m", "pytest", "tests/", "-v", "--no-header", "--tb=short", "-k", rule_id]
```
**Same bug in Makefile** `make replay` target → also fixed: `--type all --verbose`

---

### BUG-02 — `re.match()` anchoring silently drops all bypass technique IDs ✅ FIXED

**File:** `api/core/reconciler.py` lines 142, 152, 156, 160  
**Root cause:** `re.match()` anchors at position 0. After `l = line.strip()`, lines from `bypass_log.md` look like `- **Technique:** [T1059.001...]`. The `- ` prefix means `re.match(r'\*\*Technique:\*\*', l)` never matches, so `technique_id` stays `None` for every entry.  
**Fix applied:** Changed all four `re.match()` calls to `re.search()`.

---

### BUG-03 — SQLite DB and UI build artifacts not in `.gitignore` ✅ FIXED

**File:** `.gitignore`  
**Root cause:** `.gitignore` had Python/venv/IDE entries but nothing for `detection_lab.db`, `detection_lab.db-shm`, `detection_lab.db-wal`, `ui/node_modules/`, or `ui/dist/`.  
**Fix applied:** Appended entries for all five paths with explanatory comments.

---

### BUG-04 — Google Fonts CDN dependency (network required on first load) ⚠️ DOCUMENTED

**File:** `ui/src/app.css` line 1  
**Issue:** `@import url('https://fonts.googleapis.com/...')` requires internet connectivity. In air-gapped environments (or the sandbox), the UI will fall back to `'Courier New'` (acceptable but not ideal).  
**Recommended fix (Phase 2):** Download JetBrains Mono WOFF2 files into `ui/public/fonts/` and use `@font-face` with local paths. Estimated effort: 15 min.  
**Status:** Not fixed — requires network access to download font files. Falls back gracefully to `Courier New`.

---

### BUG-05 — `TestRun` DB table is never written ✅ PARTIALLY ADDRESSED

**Root cause:** `_stream_subprocess()` returns `exit_code` but callers in `/ws/test-runner` and `/ws/replay` ignore the return value. The `test_runs` table stays empty.  
**Current mitigation:** Return value is now visible in the code; a Phase 2 task is to add `asyncio.to_thread()` DB write after each subprocess completes. Not yet implemented — safe to defer as the table is optional (no existing feature reads from it).

---

## 13. Second-Check Findings (Additional Bugs)

All four new bugs found in the second check have been fixed.

### NEW-01 — Dead SQLModel branch in `delete_sigma_rule()` ✅ FIXED

**File:** `api/core/reconciler.py` line 105  
**Root cause:**
```python
# Before (BROKEN):
rule = session.exec(stmt).first() if hasattr(session, 'exec') else session.scalars(stmt).first()
```
`session.exec()` is SQLModel syntax. We use plain SQLAlchemy `Session` objects which do not have `.exec()`. `hasattr(session, 'exec')` always returns `False` (sessions have no such attribute), making the first branch permanently dead code. If `hasattr` ever returned `True` by accident, `session.exec()` on a SQLAlchemy Session would raise `AttributeError`.  
**Fix applied:** Removed the dead branch entirely. Now unconditionally: `rule = session.scalars(stmt).first()`

---

### NEW-02 — `asyncio.get_event_loop()` deprecated in Python 3.10+ ✅ FIXED

**File:** `api/main.py` line 74  
**Root cause:**
```python
# Before (BROKEN):
_watcher.start(asyncio.get_event_loop())
```
Called inside an `async` lifespan context manager. Python 3.10+ emits `DeprecationWarning: There is no current event loop` and Python 3.12+ raises `RuntimeError` in certain situations. The correct call inside a running async context is `asyncio.get_running_loop()`.  
**Fix applied:** `_watcher.start(asyncio.get_running_loop())`

---

### NEW-03 — WebSocket leak in `ReplayPage.svelte` ✅ FIXED

**File:** `ui/src/routes/ReplayPage.svelte`  
**Root cause:** Both `runReplay()` and `runPytest()` shared the module-level `ws` variable. If either function was called while `ws` still held a reference to a previous (completed or failed) WebSocket, the old connection was silently overwritten without being closed. The server-side would see a connection that went away without a proper close frame.  
**Fix applied:** Added guard at the start of both functions:
```typescript
if (ws && ws.readyState !== WebSocket.CLOSED) {
  ws.close();
  ws = null;
}
```

---

### NEW-04 — Dead `byTactic` derived variable in `CoveragePage.svelte` ✅ FIXED

**File:** `ui/src/routes/CoveragePage.svelte` lines 31–41  
**Root cause:** The `byTactic` computed variable grouped techniques by tactic for a future columnar heatmap, but the template never referenced it — only `coverage.techniques` flat list was used. Svelte would still run the derivation on every `coverage` change.  
**Fix applied:** Removed the entire `$derived(() => {...})` block. If a columnar tactic view is added in Phase 2, the variable can be re-introduced.

---

## 14. Brainstorming: Phase 2 Ideas

> This section documents ideas generated during code review. **Nothing below has been built.** All require user approval before implementation.

---

### 14.1 New Pages / Features

#### 🔬 Test History Page (High CV Value)
**Idea:** Once BUG-05 is fully resolved (TestRun writes to DB), add a page showing test run history: pass/fail trend chart over time, slowest rules, most frequently failing rules.  
**CV angle:** "Implemented test run telemetry with historical trending — same pattern as CI/CD observability dashboards in SIEM platforms."  
**Effort:** Medium (3–4 hours). Requires: completing BUG-05 fix + a new `/api/test-runs` endpoint + a new `HistoryPage.svelte`.

#### 📝 Live Rule Editor (High CV Value)
**Idea:** Add a simple YAML editor panel (textarea) on the Rule Detail view that lets you edit the rule in-browser, save to disk (new `PUT /api/rules/{id}/save` endpoint), which triggers file watcher → DB sync → broadcast.  
**CV angle:** "Full round-trip: browser → FastAPI → YAML file on disk → file watcher → SQLite → WebSocket push back to browser. End-to-end CQRS write path demonstrated."  
**Caution:** This breaks the "UI is read-only" guarantee. Make it opt-in (feature flag or dev-mode only).  
**Effort:** High (6–8 hours).

#### 🔄 Converted Rules Viewer
**Idea:** Add a page that shows `converted/kql/` and `converted/splunk/` files side-by-side with their Sigma source. No new generation — just serve the already-converted files.  
**CV angle:** "Multi-target Sigma pipeline visualised — shows both source Sigma YAML and compiled KQL/SPL."  
**Effort:** Low (1–2 hours). Just new REST endpoints + simple page.

#### 🛡️ D3FEND Mapping Page
**Idea:** Map each detected technique to its D3FEND countermeasure (d3fend.mitre.org API or static STIX data). Show the "detect → defend" chain.  
**CV angle:** "ATT&CK + D3FEND dual framework — shows mature SOC thinking beyond detection into defensive countermeasures."  
**Effort:** Medium (3–5 hours). Requires D3FEND static data file.

#### 📄 Export to PDF / Markdown Report
**Idea:** Add a "Generate Report" button that builds a structured Markdown/PDF summary of coverage, bypass cases, and test results.  
**CV angle:** "Automated detection engineering report generation — portfolio-ready artifact from a click."  
**Effort:** Low–Medium. Can use browser `window.print()` with a CSS print stylesheet, or a server-side Jinja2 template.

---

### 14.2 Project Architecture Improvements

#### Add `POST /api/sync/force-rule/{id}` Endpoint
**Problem:** Current sync endpoints only do full reconciliation (`POST /api/sync/trigger`). There's no way to re-sync a single rule by ID.  
**Fix:** Add `force_rule` route that calls `sync_sigma_rule(filepath, session)` for a specific file, then broadcasts a targeted `rule_changed` event.  
**Benefit:** Faster targeted re-sync for large rule sets.

#### Move DB Path to Explicit Config
**Current:** `detection_lab.db` path is resolved implicitly by SQLAlchemy engine URL `sqlite:///detection_lab.db` which uses the process CWD. If the server is launched from a different directory, the DB lands in the wrong place.  
**Fix:** Pin the path to `PROJECT_ROOT / "detection_lab.db"` using `sqlite:////absolute/path/to/detection_lab.db` (four slashes = absolute path).  
**Risk level:** Low. The current implicit CWD path happens to work when launched from project root (the normal case), but is fragile.

#### Add Schema Migration Note
**Current state:** No migration system. Schema is created from scratch by `create_tables()` each time.  
**Problem:** If the `rules` table schema changes (new column), `create_tables()` won't add it to an existing DB — the old DB stays with old schema silently.  
**Recommendation:** Add a `make reset-db` target that deletes and rebuilds the DB. Document that the DB is disposable (which it is). Defer Alembic until schema stabilises.

#### Vite Proxy Already Configured — Verify Build-Time Host
**Note:** `vite.config.ts` proxies `/api` to `localhost:8001` in dev mode. In production (static build served by FastAPI), the proxy is irrelevant — the Svelte app hits the same host/port as the page. This is correct and needs no change, but worth documenting.

---

### 14.3 CV / Portfolio Improvements

#### Add GitHub Actions Badge to README
**Idea:** Once pushed to GitHub, add a `![CI](https://github.com/...)` badge showing test status.  
**Why:** Immediately signals to recruiters that the repo has working CI/CD — visible before they even click into the code.  
**Effort:** 5 minutes (update README).

#### Add `make ci` Target
**Idea:** Add a Makefile target that mirrors the GitHub Actions pipeline locally:
```makefile
ci:
    $(PYTHON) -m pytest tests/ -v --no-header --tb=short
    $(PYTHON) scripts/replay_logs.py --type all --verbose
    cd ui && $(NPM) run build
```
**Why:** Makes it trivial to run the full CI pipeline locally. Shows pipeline thinking.

#### Document Architecture Decision Records (ADRs)
**Idea:** Add a `docs/adr/` directory with short ADR files: "Why SQLite over PostgreSQL", "Why Svelte 5 runes over React", "Why YAML files as source of truth".  
**Why:** ADRs signal senior engineering thinking. A portfolio with ADRs stands out significantly.

#### Add `myenv` Activation Note in README
**Current:** The project has both a `myenv/` virtualenv (pySigma/pytest stack) and system Python (FastAPI stack). The README should clarify which Python to use for which command.  
**Fix:** Add a "Prerequisites" section to README explaining `myenv` is for Sigma testing, system Python is for the API.

---

### 14.4 Known Limitations (Technical Debt Register)

| ID | Issue | Severity | Status | Resolution Notes |
|----|-------|----------|--------|------------------|
| TD-01 | BUG-04: Google Fonts CDN (offline environments) | Low | ✅ Resolved (Phase 3) | Air-gapped system monospace stack (`JetBrains Mono`, `Cascadia Code`, `Fira Code`, `SFMono`, `Consolas`) active |
| TD-02 | BUG-05: TestRun table never written | Medium | ✅ Resolved (Phase 2) | Telemetry recorded on WS completion, served via `/api/test-runs`, live history table in UI |
| TD-03 | DB path implicit CWD (not absolute) | Low | ✅ Resolved (Phase 2) | Absolute path pinned via `PROJECT_ROOT / "api" / "detection_lab.db"` |
| TD-04 | No Alembic migrations (schema changes need DB reset) | Low | ✅ Mitigated (Phase 2) | Added `make reset-db` target for deterministic read-model rebuilds |
| TD-05 | `coverage_notes.md` MTTD parsing is heuristic | Low | ✅ Resolved (Phase 2) | Hardened parser with column alignment and backtick stripping |
| TD-06 | No authentication on API (localhost-only assumed) | Low | Out of scope | Local engineering workstation assumption |
| TD-07 | WebSocket reconnect logic not implemented in frontend | Medium | ✅ Resolved (Phase 2) | Resilient exponential backoff reconnect loop added in `App.svelte` |

---

*End of UI_plan.md*
