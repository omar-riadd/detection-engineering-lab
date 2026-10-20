"""
/api/sync — Manual DB rebuild and sync status endpoints.
"""
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks

from api.core.reconciler import full_reconciliation
from api.models.db import engine
from sqlalchemy import text

PROJECT_ROOT = Path(__file__).parent.parent.parent

router = APIRouter(prefix="/api/sync", tags=["sync"])


def _run_reconciliation():
    rules_dir = PROJECT_ROOT / "rules" / "sigma"
    bypass_log = PROJECT_ROOT / "docs" / "bypass_log.md"
    return full_reconciliation(rules_dir, bypass_log, verbose=True)


@router.post("/rebuild")
@router.post("/trigger")
def rebuild_database(background_tasks: BackgroundTasks):
    """
    Trigger a full rebuild of the SQLite read model from disk.
    Runs in background; use GET /api/sync/status to check.
    CV talking point: equivalent to Argo CD 'hard refresh' — forces reconciliation loop.
    """
    background_tasks.add_task(_run_reconciliation)
    return {"status": "rebuilding", "message": "Full reconciliation started in background"}


@router.post("/force-rule/{rule_id}")
async def force_rule_sync(rule_id: str):
    """
    Targeted single rule re-sync by rule UUID or filename stem.
    Updates SQLite and broadcasts a rule_changed event over WebSocket.
    """
    from fastapi import HTTPException
    from api.core.reconciler import sync_sigma_rule
    from api.core.ws_manager import ws_manager
    from api.models.db import Session

    rules_dir = PROJECT_ROOT / "rules" / "sigma"
    target_file = None
    for p in rules_dir.rglob("*.yml"):
        if rule_id in p.name:
            target_file = p
            break
        try:
            content = p.read_text(encoding="utf-8")
            if f"id: {rule_id}" in content or f"id: '{rule_id}'" in content:
                target_file = p
                break
        except Exception:
            pass

    if not target_file:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found on disk")

    with Session(engine) as session:
        result = sync_sigma_rule(target_file, session)
        action = result.get("action", "synced")
        rid = result.get("id", rule_id)

    await ws_manager.broadcast({
        "event": "rule_changed",
        "rule_id": rid,
        "action": action,
    })
    return {
        "status": "synced",
        "rule_id": rid,
        "action": action,
        "file": str(target_file.name),
    }




@router.get("/status")
def sync_status():
    """
    Returns DB health and rule count as a quick sync status check.
    """
    try:
        with engine.connect() as conn:
            rule_count = conn.execute(text("SELECT COUNT(*) FROM rules")).scalar()
            synced = conn.execute(
                text("SELECT COUNT(*) FROM rules WHERE sync_status='synced'")
            ).scalar()
            errors = conn.execute(
                text("SELECT COUNT(*) FROM rules WHERE sync_status='error'")
            ).scalar()
            bypass_count = conn.execute(text("SELECT COUNT(*) FROM bypass_attempts")).scalar()
        return {
            "db_healthy": True,
            "rules_total": rule_count,
            "rules_synced": synced,
            "rules_error": errors,
            "bypass_entries": bypass_count,
        }
    except Exception as exc:
        return {"db_healthy": False, "error": str(exc)}
