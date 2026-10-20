"""
/api/bypass — Purple team bypass case studies from docs/bypass_log.md.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import select

from api.models.db import BypassAttempt, get_session

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
