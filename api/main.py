"""
Detection Engineering Lab — FastAPI Application
================================================
Architecture: CQRS-lite hybrid backend
  - YAML files (rules/sigma/**/*.yml) = Source of Truth (Git-tracked)
  - SQLite (detection_lab.db)         = Derived read model (disposable)
  - FastAPI                            = REST + WebSocket API layer
  - Svelte 5 (ui/)                     = Frontend SPA

Startup sequence:
  1. Create SQLite tables (idempotent)
  2. Full cold-start reconciliation: scan all YAML files → upsert to SQLite
  3. Launch watchdog file watcher: YAML changes → incremental DB sync → WS broadcast
  4. Serve REST + WebSocket traffic

References:
  - Grafana provisioned alerting rules (hybrid YAML+DB pattern)
  - Elastic detection-rules CLI (GitOps push model)
  - Argo CD (Git as SoT, Redis as read model cache)
"""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.core.reconciler import full_reconciliation
from api.core.watcher import FileWatcher
from api.core.ws_manager import ws_manager
from api.models.db import create_tables
from api.routers import bypass, coverage, deploy, reports, rules, sync, tests, websocket


PROJECT_ROOT = Path(__file__).parent.parent
RULES_DIR = PROJECT_ROOT / "rules" / "sigma"
BYPASS_LOG = PROJECT_ROOT / "docs" / "bypass_log.md"
UI_DIST = PROJECT_ROOT / "ui" / "dist"

# Global watcher instance (needs to persist across lifespan)
_watcher: FileWatcher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager (replaces deprecated @app.on_event).
    Runs startup tasks before serving, cleanup tasks on shutdown.
    """
    global _watcher

    # ── STARTUP ──────────────────────────────────────────────────────────────
    print("\n[BOOT] Detection Engineering Lab API starting...")

    # 1. Create database schema (idempotent — safe to run on every boot)
    create_tables()
    print("[BOOT] SQLite schema ready (WAL mode)")

    # 2. Full cold-start reconciliation in a thread (non-blocking to event loop)
    print(f"[BOOT] Reconciling YAML rules from {RULES_DIR}...")
    results = await asyncio.to_thread(
        full_reconciliation, RULES_DIR, BYPASS_LOG, True
    )
    print(
        f"[BOOT] Reconciliation complete: "
        f"{results['upserted']} upserted, "
        f"{results['skipped']} unchanged, "
        f"{results['errors']} errors, "
        f"{results['bypass_entries']} bypass entries"
    )

    # 3. Start file watcher (watchdog in background OS thread)
    _watcher = FileWatcher(RULES_DIR, ws_manager.broadcast)
    _watcher.start(asyncio.get_running_loop())

    print("[BOOT] API ready. Listening...\n")

    yield  # ── Server is live here ──────────────────────────────────────────

    # ── SHUTDOWN ─────────────────────────────────────────────────────────────
    if _watcher:
        _watcher.stop()
    print("[SHUTDOWN] Detection Engineering Lab API stopped.")


# ── App instance ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Detection Engineering Lab API",
    description=(
        "CQRS-lite hybrid backend: Sigma YAML files as source of truth, "
        "SQLite as derived read model, FastAPI as REST+WebSocket API layer."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS (development: allow Vite dev server on port 5173) ───────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",   # Vite preview
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Cache Control (Prevents Stale Browser SPA Cache) ─────────────────────────
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response: Response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith(".html"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(rules.router)
app.include_router(coverage.router)
app.include_router(bypass.router)
app.include_router(sync.router)
app.include_router(tests.router)
app.include_router(reports.router)
app.include_router(deploy.router)
app.include_router(websocket.router)



# ── Health check ─────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "ws_clients": ws_manager.active_count,
    }


# ── Serve Svelte SPA (production build) ──────────────────────────────────────
# Only mount if the dist/ folder exists (after `npm run build`)
if UI_DIST.exists():
    app.mount("/", StaticFiles(directory=str(UI_DIST), html=True), name="ui")
