"""
/api/rules — CRUD-read endpoints for Sigma detection rules.
All data is served from SQLite read model (synced from YAML files).
"""
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import yaml
from sqlalchemy.orm import Session
from sqlalchemy import select

from api.models.db import Rule, get_session
from api.core.reconciler import sync_sigma_rule
from api.core.ws_manager import ws_manager

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = PROJECT_ROOT / "rules" / "sigma"

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleSaveRequest(BaseModel):
    yaml_content: str = Field(..., description="Raw Sigma YAML content to write to disk")



@router.get("")
def list_rules(
    severity: Optional[str] = Query(None, description="Filter by severity: low|medium|high|critical"),
    status: Optional[str] = Query(None, description="Filter by status: experimental|test|stable"),
    technique: Optional[str] = Query(None, description="Filter by ATT&CK technique ID, e.g. T1003.001"),
    tactic: Optional[str] = Query(None, description="Filter by tactic slug, e.g. credential-access"),
    sync_status: Optional[str] = Query(None, description="Filter by sync_status: synced|error"),
    search: Optional[str] = Query(None, description="Free-text search in title/description"),
    session: Session = Depends(get_session),
):
    """
    List all detection rules with optional filters.
    Returns metadata only (no raw YAML) for fast list rendering.
    """
    stmt = select(Rule)

    if severity:
        stmt = stmt.where(Rule.severity == severity.lower())
    if status:
        stmt = stmt.where(Rule.status == status.lower())
    if sync_status:
        stmt = stmt.where(Rule.sync_status == sync_status)
    if technique:
        stmt = stmt.where(Rule.techniques.contains(technique.upper()))
    if tactic:
        stmt = stmt.where(Rule.tactics.contains(tactic.lower()))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            Rule.title.ilike(like) | Rule.description.ilike(like)
        )

    rules = session.scalars(stmt.order_by(Rule.severity.desc(), Rule.title)).all()
    return [r.to_dict() for r in rules]


@router.get("/stats")
def rule_stats(session: Session = Depends(get_session)):
    """
    Aggregate statistics for the dashboard header.
    Returns: counts by severity, status, sync_status, technique coverage.
    """
    all_rules = session.scalars(select(Rule)).all()
    
    severity_counts = {}
    status_counts = {}
    sync_counts = {}
    all_techniques = set()
    all_tactics = set()

    for r in all_rules:
        severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
        sync_counts[r.sync_status] = sync_counts.get(r.sync_status, 0) + 1
        if r.techniques:
            for t in r.techniques.split("|"):
                if t:
                    all_techniques.add(t)
        if r.tactics:
            for t in r.tactics.split("|"):
                if t:
                    all_tactics.add(t)

    return {
        "total": len(all_rules),
        "by_severity": severity_counts,
        "by_status": status_counts,
        "by_sync_status": sync_counts,
        "unique_techniques": len(all_techniques),
        "unique_tactics": len(all_tactics),
        "techniques": sorted(all_techniques),
        "tactics": sorted(all_tactics),
    }


@router.get("/{rule_id}")
def get_rule(rule_id: str, session: Session = Depends(get_session)):
    """
    Get full rule details including raw YAML source.
    """
    rule = session.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    data = rule.to_dict()
    data["raw_yaml"] = rule.raw_yaml  # Include full YAML for detail view
    return data


@router.get("/{rule_id}/converted")
def get_rule_converted(rule_id: str, session: Session = Depends(get_session)):
    """
    Get all multi-SIEM transpiled representations for a detection rule:
      - Sigma YAML (rules/sigma/)
      - Wazuh XML (rules/wazuh/)
      - Microsoft Sentinel KQL (converted/kql/)
      - Splunk SPL (converted/splunk/)
    """
    rule = session.get(Rule, rule_id)
    if not rule:
        rule = session.scalars(
            select(Rule).where((Rule.id == rule_id) | (Rule.techniques.contains(rule_id)))
        ).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    stem = Path(rule.file_path).stem if rule.file_path else rule.id

    wazuh_path = PROJECT_ROOT / "rules" / "wazuh" / f"{stem}.xml"
    kql_path = PROJECT_ROOT / "converted" / "kql" / f"{stem}.kql"
    splunk_path = PROJECT_ROOT / "converted" / "splunk" / f"{stem}.spl"

    return {
        "rule_id": rule.id,
        "title": rule.title,
        "stem": stem,
        "techniques": rule.techniques.split("|") if rule.techniques else [],
        "formats": {
            "sigma": {
                "format": "yaml",
                "label": "Sigma (YAML)",
                "target": "Vendor-Neutral Source",
                "content": rule.raw_yaml,
            },
            "wazuh": {
                "format": "xml",
                "label": "Wazuh (XML)",
                "target": "Wazuh Engine / Analysisd",
                "content": wazuh_path.read_text(encoding="utf-8") if wazuh_path.exists() else None,
            },
            "kql": {
                "format": "kql",
                "label": "Microsoft Sentinel (KQL)",
                "target": "Azure Log Analytics / Sentinel",
                "content": kql_path.read_text(encoding="utf-8") if kql_path.exists() else None,
            },
            "splunk": {
                "format": "spl",
                "label": "Splunk (SPL)",
                "target": "Splunk Enterprise / Cloud",
                "content": splunk_path.read_text(encoding="utf-8") if splunk_path.exists() else None,
            },
        },
    }


@router.put("/{rule_id}/save")
async def save_rule(
    rule_id: str,
    payload: RuleSaveRequest,
    session: Session = Depends(get_session),
):
    """
    CQRS Write Path:
    1. Look up rule in SQLite read model to resolve its source YAML file path.
    2. Validate YAML syntax and mandatory Sigma keys.
    3. Safely update the YAML file on disk (Git-tracked Source of Truth).
    4. Reconcile updated rule into SQLite read model via sync_sigma_rule.
    5. Broadcast WebSocket event to all connected UI clients.
    """
    rule = session.execute(
        select(Rule).where(
            (Rule.id == rule_id) | (Rule.file_path.like(f"%{rule_id}%"))
        )
    ).scalars().first()

    if not rule or not rule.file_path:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    target_file = Path(rule.file_path).resolve()

    # Security check: must reside within RULES_DIR
    try:
        target_file.relative_to(RULES_DIR.resolve())
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Cannot write outside the rules/sigma directory"
        )

    # Validate YAML syntax
    try:
        parsed = yaml.safe_load(payload.yaml_content)
    except yaml.YAMLError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid YAML syntax: {exc}"
        )

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422,
            detail="Invalid Sigma rule: YAML root must be a mapping/dictionary"
        )

    # Check essential Sigma fields
    missing_fields = [f for f in ["title", "logsource", "detection"] if f not in parsed]
    if missing_fields:
        raise HTTPException(
            status_code=422,
            detail=f"Missing mandatory Sigma fields: {', '.join(missing_fields)}"
        )

    # Write to disk (Source of Truth)
    try:
        target_file.write_text(payload.yaml_content, encoding="utf-8")
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to write file to disk: {exc}"
        )

    # Reconcile into SQLite read model
    sync_result = sync_sigma_rule(target_file, session)

    # Refresh rule from session
    session.refresh(rule)

    # Broadcast change via WebSocket
    await ws_manager.broadcast({
        "event": "rule_changed",
        "rule_id": rule.id,
        "action": "saved",
        "title": rule.title,
    })

    return {
        "status": "ok",
        "action": sync_result.get("action", "updated"),
        "rule_id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "status_level": rule.status,
        "synced_at": rule.synced_at.isoformat() if rule.synced_at else None,
    }


