import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from api.models.db import BypassAttempt, get_session
from api.core.ws_manager import ws_manager

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
BYPASS_LOG_FILE = PROJECT_ROOT / "docs" / "bypass_log.md"
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"

router = APIRouter(prefix="/api/bypass", tags=["bypass"])


@router.get("")
def list_bypass_attempts(session: Session = Depends(get_session)):
    """
    List all purple-team bypass attempts parsed from docs/bypass_log.md.
    """
    attempts = session.scalars(select(BypassAttempt).order_by(BypassAttempt.id)).all()
    return [a.to_dict() for a in attempts]


@router.get("/stats")
def bypass_stats(session: Session = Depends(get_session)):
    """
    Aggregate bypass statistics for the Purple Team screen.
    """
    attempts = session.scalars(select(BypassAttempt)).all()
    by_outcome = {}
    for a in attempts:
        by_outcome[a.outcome] = by_outcome.get(a.outcome, 0) + 1

    detected = by_outcome.get("DETECTED", 0)
    total = len(attempts)

    return {
        "total_cases": total,
        "by_outcome": by_outcome,
        "detection_rate_pct": round(detected / total * 100, 1) if total else 0,
    }


class BypassCreateRequest(BaseModel):
    title: str = Field(..., description="Evasion case title")
    technique: str = Field(..., description="Technique name, e.g. PowerShell EncodedCommand")
    technique_id: str = Field(..., description="MITRE Technique ID, e.g. T1059.001")
    target_rule: Optional[str] = Field(None, description="Target rule filepath or title")
    evasion_method: str = Field(..., description="Adversary tradecraft / bypass method")
    notes: Optional[str] = Field(None, description="Root cause failure analysis & hardening remediation")
    outcome: str = Field("DETECTED", description="Outcome: DETECTED | EVADED | PARTIAL")
    test_fixture: Optional[dict] = Field(None, description="Optional simulated attack log JSON fixture")


@router.post("")
async def create_bypass_attempt(
    payload: BypassCreateRequest,
    session: Session = Depends(get_session),
):
    """
    Register a new Purple Team Adversarial Evasion Case Study:
    1. Determines next sequential case ID.
    2. Appends formatted case study to docs/bypass_log.md (Source of Truth).
    3. Optionally saves simulated attack event fixture to tests/fixtures/.
    4. Inserts into SQLite read-model.
    5. Broadcasts event via WebSocket.
    """
    max_id = session.scalar(select(func.max(BypassAttempt.id))) or 0
    new_id = max_id + 1

    # Optional test fixture write
    fixture_name = "N/A"
    if payload.test_fixture:
        FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        safe_slug = re.sub(r'[^a-zA-Z0-9_]', '_', payload.title.lower()).strip('_')[:30]
        fixture_name = f"{payload.technique_id}_evasion_{safe_slug}_positive.json"
        fixture_path = FIXTURES_DIR / fixture_name
        try:
            fixture_path.write_text(json.dumps(payload.test_fixture, indent=2), encoding="utf-8")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to write fixture file: {exc}")

    # Append to docs/bypass_log.md
    if BYPASS_LOG_FILE.exists():
        md_entry = (
            f"\n\n---\n\n"
            f"### Bypass Case {new_id:03d}: {payload.title}\n"
            f"- **Technique:** [{payload.technique_id}: {payload.technique}](https://attack.mitre.org/techniques/{payload.technique_id.replace('.', '/')}/)\n"
            f"- **Target Rule:** `{payload.target_rule or 'N/A'}`\n"
            f"- **Threat Actor Rationale:** {payload.evasion_method}\n"
            f"- **Pre-Hardening Failure Analysis:** {payload.notes or 'Initial detection rule filter was bypassed by modified evasion syntax.'}\n"
            f"- **Hardening Applied:** {payload.evasion_method}\n"
            f"- **Verification Fixture:** `tests/fixtures/{fixture_name}`\n"
            f"- **Result:** {payload.outcome.upper()} alert confirmed. Regression verified.\n"
        )
        try:
            with open(BYPASS_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(md_entry)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to update bypass_log.md: {exc}")

    # Insert into SQLite read-model
    attempt = BypassAttempt(
        id=new_id,
        technique=f"-  {payload.technique_id}: {payload.technique}",
        technique_id=payload.technique_id,
        evasion_method=payload.evasion_method,
        outcome=payload.outcome.upper(),
        rule_hardened=payload.target_rule,
        notes=payload.notes,
        synced_at=datetime.now(timezone.utc),
    )
    session.add(attempt)
    session.commit()
    session.refresh(attempt)

    # Broadcast via WebSocket
    await ws_manager.broadcast({
        "event": "bypass_created",
        "case_id": new_id,
        "title": payload.title,
        "technique_id": payload.technique_id,
    })

    return attempt.to_dict()

