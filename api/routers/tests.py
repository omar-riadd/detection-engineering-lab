"""
/api/test-runs — Historical test execution records and statistics.
Data is recorded whenever test suite or replay engine runs via WebSocket.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from api.models.db import TestRun, get_session

router = APIRouter(prefix="/api/test-runs", tags=["tests"])


@router.get("")
def list_test_runs(
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    run_type: Optional[str] = Query(None, description="Filter by run type: pytest | replay"),
    status: Optional[str] = Query(None, description="Filter by status: pass | fail"),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
):
    """
    List past test execution runs with optional filters.
    """
    stmt = select(TestRun).order_by(desc(TestRun.id)).limit(limit)
    if rule_id:
        stmt = stmt.where(TestRun.rule_id == rule_id)
    if run_type:
        stmt = stmt.where(TestRun.run_type == run_type)
    if status:
        stmt = stmt.where(TestRun.status == status)

    runs = session.scalars(stmt).all()
    return [r.to_dict() for r in runs]


@router.get("/stats")
def test_runs_stats(session: Session = Depends(get_session)):
    """
    Aggregated telemetry for test runs (pass/fail ratio, total runs, avg duration).
    """
    total = session.scalar(select(func.count(TestRun.id))) or 0
    passed = session.scalar(select(func.count(TestRun.id)).where(TestRun.status == "pass")) or 0
    failed = session.scalar(select(func.count(TestRun.id)).where(TestRun.status == "fail")) or 0
    avg_duration = session.scalar(select(func.avg(TestRun.duration_seconds))) or 0.0

    return {
        "total_runs": total,
        "passed": passed,
        "failed": failed,
        "pass_rate_pct": round((passed / total * 100), 1) if total > 0 else 100.0,
        "avg_duration_seconds": round(float(avg_duration), 2),
    }


@router.get("/{run_id}")
def get_test_run(run_id: int, session: Session = Depends(get_session)):
    """
    Retrieve single test run details including output.
    """
    run = session.get(TestRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Test run {run_id} not found")
    return run.to_dict()
