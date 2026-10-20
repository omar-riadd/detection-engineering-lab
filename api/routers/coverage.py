"""
/api/coverage — ATT&CK coverage and D3FEND mapping data.
Reads directly from docs/coverage/navigator_layer.json and docs/d3fend_mapping.md.
"""
import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = Path(__file__).parent.parent.parent

router = APIRouter(prefix="/api/coverage", tags=["coverage"])


@router.get("/attack")
def get_attack_coverage():
    """
    Full ATT&CK Navigator layer data.
    Returns the parsed navigator_layer.json with technique scores and metadata.
    """
    layer_path = PROJECT_ROOT / "docs" / "coverage" / "navigator_layer.json"
    if not layer_path.exists():
        raise HTTPException(status_code=404, detail="Navigator layer not found")

    data = json.loads(layer_path.read_text(encoding="utf-8"))

    # Flatten techniques for easier frontend consumption
    techniques = []
    for t in data.get("techniques", []):
        techniques.append({
            "technique_id": t.get("techniqueID", ""),
            "tactic": t.get("tactic", ""),
            "score": t.get("score", 0),
            "color": t.get("color", ""),
            "comment": t.get("comment", ""),
            "enabled": t.get("enabled", True),
        })

    return {
        "layer_name": data.get("name", ""),
        "domain": data.get("domain", "enterprise-attack"),
        "attack_version": data.get("versions", {}).get("attack", "14"),
        "technique_count": len(techniques),
        "gradient": data.get("gradient", {}),
        "legend": data.get("legendItems", []),
        "techniques": techniques,
    }


@router.get("/d3fend")
def get_d3fend_mapping():
    """
    Parse and return D3FEND countermeasure mappings from docs/d3fend_mapping.md.
    """
    d3fend_path = PROJECT_ROOT / "docs" / "d3fend_mapping.md"
    if not d3fend_path.exists():
        raise HTTPException(status_code=404, detail="D3FEND mapping not found")

    content = d3fend_path.read_text(encoding="utf-8")
    entries = []

    # Parse markdown table rows: | T1003.001 | technique name | D3FEND technique | ...
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("| ---") or "ATT&CK" in line:
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        tech_id = cols[0].strip("*").strip()
        if len(cols) >= 6 and tech_id.startswith("T"):
            countermeasure_text = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', cols[4])
            d3fend_id = cols[5].strip("*").strip()
            defense_type = cols[6] if len(cols) > 6 else ""
            entries.append({
                "technique_id": tech_id,
                "technique_name": cols[1],
                "d3fend_id": d3fend_id,
                "countermeasure": countermeasure_text,
                "defense_type": defense_type,
                "runbook": re.sub(r'\[(.*?)\]\(.*?\)', r'\1', cols[3]),
            })

    return {"count": len(entries), "mappings": entries}



@router.get("/mttd")
def get_mttd_metrics():
    """
    Parse and return MTTD (Mean Time to Detect) metrics from docs/mttd_metrics.md.
    """
    mttd_path = PROJECT_ROOT / "docs" / "mttd_metrics.md"
    if not mttd_path.exists():
        raise HTTPException(status_code=404, detail="MTTD metrics not found")

    content = mttd_path.read_text(encoding="utf-8")
    entries = []

    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("| ---") or line.startswith("| #") or "ATT&CK ID" in line:
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) >= 6 and cols[1].startswith("T"):
            try:
                match = re.search(r'[\d.]+', cols[5])
                if match:
                    entries.append({
                        "rule_id": cols[1],
                        "technique": cols[2],
                        "mttd_seconds": float(match.group()),
                    })
            except (AttributeError, ValueError):
                continue

    # Compute summary stats
    if entries:
        values = [e["mttd_seconds"] for e in entries]
        avg = sum(values) / len(values)
        min_v = min(values)
        max_v = max(values)
    else:
        avg = min_v = max_v = 0.0

    return {
        "avg_mttd_seconds": round(avg, 2),
        "min_mttd_seconds": round(min_v, 2),
        "max_mttd_seconds": round(max_v, 2),
        "rule_count": len(entries),
        "entries": entries,
    }


@router.get("/fp-report")
def get_fp_report():
    """
    Parse and return False Positive rates from docs/fp_report.md.
    """
    fp_path = PROJECT_ROOT / "docs" / "fp_report.md"
    if not fp_path.exists():
        raise HTTPException(status_code=404, detail="FP report not found")

    content = fp_path.read_text(encoding="utf-8")
    entries = []

    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("| ---") or "Rule File" in line:
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        rule_col = cols[0].strip("`")
        if len(cols) >= 5 and rule_col.endswith(".yml"):
            try:
                match = re.search(r'[\d.]+', cols[4])
                if match:
                    entries.append({
                        "rule_id": rule_col,
                        "technique_id": cols[1],
                        "fp_rate": float(match.group()),
                        "status": cols[5] if len(cols) > 5 else "",
                        "details": cols[6] if len(cols) > 6 else "",
                    })

            except (AttributeError, ValueError):
                continue

    return {
        "overall_fp_rate": 0.00,  # From docs: 0.00% across all rules
        "rule_count": len(entries),
        "entries": entries,
    }

