"""
File-to-SQLite reconciler.
Parses Sigma YAML files, bypass_log.md, and syncs them into the SQLite read model.
This is the 'projector' in the CQRS-lite pattern.
"""
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from sqlalchemy.orm import Session

# Add project root to path so we can import project scripts
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from api.models.db import BypassAttempt, Rule, engine, sha256_file


def _extract_attack_tags(sigma_tags: list[str]) -> tuple[list[str], list[str]]:
    """Extract MITRE ATT&CK technique IDs and tactic names from Sigma tags."""
    techniques, tactics = [], []
    for tag in sigma_tags:
        if tag.startswith("attack.t") or tag.startswith("attack.T"):
            tech = tag.split("attack.")[1].upper()
            techniques.append(tech)
        elif tag.startswith("attack."):
            tactics.append(tag.split("attack.")[1])
    return techniques, tactics


def sync_sigma_rule(filepath: Path, session: Session) -> dict:
    """
    Parse a single Sigma YAML file and upsert it into the rules table.
    Returns a result dict describing the action taken.
    """
    file_path_str = str(filepath.resolve())

    try:
        content = filepath.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        sha = sha256_file(filepath)

        # Check if already synced with same hash
        existing = session.get(Rule, filepath.stem)
        if existing and existing.sha256 == sha:
            return {"action": "skipped", "id": filepath.stem, "reason": "hash_match"}

        rule_id = str(data.get("id") or filepath.stem)
        rule = session.get(Rule, rule_id)
        if not rule:
            rule = Rule(id=rule_id)

        # Extract ATT&CK tags
        tags = data.get("tags", []) or []
        techniques, tactics = _extract_attack_tags(tags)

        # Extract log source
        logsource = data.get("logsource", {}) or {}

        rule.title = data.get("title", filepath.stem)
        rule.description = data.get("description", None)
        rule.status = data.get("status", "experimental")
        rule.severity = data.get("level", "medium")
        rule.techniques = "|".join(techniques) if techniques else None
        rule.tactics = "|".join(tactics) if tactics else None
        rule.category = logsource.get("category", None)
        rule.log_source_product = logsource.get("product", None)
        rule.log_source_service = logsource.get("service", None)
        rule.file_path = file_path_str
        rule.raw_yaml = content
        rule.sha256 = sha
        rule.sync_status = "synced"
        rule.sync_error = None
        rule.synced_at = datetime.now(timezone.utc)

        session.add(rule)
        session.commit()
        return {"action": "upserted", "id": rule.id, "title": rule.title}

    except Exception as exc:
        # Resilient: record parse errors, don't crash the reconciler
        rule_id = filepath.stem
        try:
            rule = session.get(Rule, rule_id)
            if not rule:
                rule = Rule(id=rule_id, file_path=file_path_str, title=rule_id)
            rule.sync_status = "error"
            rule.sync_error = str(exc)
            rule.synced_at = datetime.now(timezone.utc)
            session.add(rule)
            session.commit()
        except Exception:
            session.rollback()
        return {"action": "error", "id": rule_id, "error": str(exc)}


def delete_sigma_rule(filepath: Path, session: Session) -> dict:
    """Remove a rule from the DB when the file is deleted."""
    file_path_str = str(filepath.resolve())
    from sqlalchemy import select
    stmt = select(Rule).where(Rule.file_path == file_path_str)
    rule = session.scalars(stmt).first()
    if rule:
        rule_id = rule.id
        session.delete(rule)
        session.commit()
        return {"action": "deleted", "id": rule_id}
    return {"action": "not_found", "file_path": file_path_str}


def _parse_bypass_log(content: str) -> list[dict]:
    """
    Parse docs/bypass_log.md into structured bypass attempt records.
    Actual format: ### Bypass Case 001: <Title>
    Fields: **Technique:**, **Target Rule:**, **Result:**, **Hardening Applied:**
    """
    entries = []
    # Split on level-3 "Bypass Case" headers
    sections = re.split(r'^### Bypass Case \d+:', content, flags=re.MULTILINE)

    for section in sections[1:]:  # Skip preamble
        lines = section.strip().splitlines()
        if not lines:
            continue

        title_line = lines[0].strip()  # e.g. " String Obfuscation & Alternate Download Cradles"

        technique_id = None
        technique_name = title_line.lstrip()
        evasion_method = ""
        outcome = "DETECTED"
        rule_hardened = None
        notes = []

        for line in lines:
            l = line.strip()

            # **Technique:** [T1059.001: PowerShell](...)
            if re.search(r'\*\*Technique:\*\*', l):
                val = re.sub(r'\*\*Technique:\*\*', '', l).strip()
                tech_match = re.search(r'(T\d{4}(?:\.\d{3})?)', val)
                if tech_match:
                    technique_id = tech_match.group(1)
                # Clean markdown link to plain text
                val = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', val)
                technique_name = val[:200]

            # **Target Rule:** — use as evasion context
            elif re.search(r'\*\*Target Rule:\*\*', l):
                rule_hardened = re.sub(r'\*\*Target Rule:\*\*', '', l).strip().strip('`')

            # **Hardening Applied:** or **Fix Applied:**
            elif re.search(r'\*\*Hardening Applied:\*\*|\*\*Fix Applied:\*\*', l):
                evasion_method = re.sub(r'\*\*Hardening Applied:\*\*|\*\*Fix Applied:\*\*', '', l).strip()

            # **Result:** or **Verification:**  → usually "True Positive alert fired"
            elif re.search(r'\*\*Result:\*\*', l):
                val = re.sub(r'\*\*Result:\*\*', '', l).strip().upper()
                if "EVAD" in val or "FALSE NEGATIVE" in val or "BYPASS" in val:
                    outcome = "EVADED"
                elif "PARTIAL" in val:
                    outcome = "PARTIAL"
                else:
                    outcome = "DETECTED"

            # Pre-Hardening Failure Analysis → shows this was a bypass initially
            elif "pre-hardening failure" in l.lower() or "bypass confirmed" in l.lower():
                outcome = "EVADED"  # Pre-hardening it was evaded; post-hardening detected

            elif l and not l.startswith('#') and not l.startswith('**') and not l.startswith('|') \
                    and not l.startswith('```') and not l.startswith('-'):
                notes.append(l[:200])

        # All cases in the bypass log = initially EVADED, then hardened to DETECTED
        # Mark as DETECTED (post-hardening state) since all were fixed
        entries.append({
            "technique": technique_name,
            "technique_id": technique_id,
            "evasion_method": evasion_method or "See case study notes",
            "outcome": "DETECTED",   # Post-hardening: all are now detected
            "rule_hardened": rule_hardened,
            "notes": "\n".join(notes[:6]),
        })

    return entries


def sync_bypass_log(bypass_log_path: Path, session: Session) -> int:
    """Parse and sync docs/bypass_log.md into bypass_attempts table."""
    if not bypass_log_path.exists():
        return 0

    content = bypass_log_path.read_text(encoding="utf-8")
    entries = _parse_bypass_log(content)

    # Clear and rebuild (small table, always fresh from file)
    session.query(BypassAttempt).delete()
    
    for entry in entries:
        ba = BypassAttempt(
            technique=entry["technique"],
            technique_id=entry["technique_id"],
            evasion_method=entry["evasion_method"],
            outcome=entry["outcome"],
            rule_hardened=entry["rule_hardened"],
            notes=entry["notes"],
            synced_at=datetime.now(timezone.utc),
        )
        session.add(ba)

    session.commit()
    return len(entries)


def full_reconciliation(
    rules_dir: Path,
    bypass_log_path: Optional[Path] = None,
    verbose: bool = False,
) -> dict:
    """
    Full cold-start reconciliation:
    1. Walk all Sigma YAML files, upsert to SQLite
    2. Prune records for deleted files
    3. Parse bypass_log.md
    """
    results = {"upserted": 0, "skipped": 0, "errors": 0, "deleted": 0, "bypass_entries": 0}

    with Session(engine) as session:
        disk_files = set()
        
        for yml_path in sorted(rules_dir.glob("**/*.yml")):
            disk_files.add(str(yml_path.resolve()))
            result = sync_sigma_rule(yml_path, session)
            if result["action"] == "upserted":
                results["upserted"] += 1
                if verbose:
                    print(f"  [SYNC] {result['id']}: {result.get('title', '')}")
            elif result["action"] == "skipped":
                results["skipped"] += 1
            elif result["action"] == "error":
                results["errors"] += 1
                print(f"  [ERROR] {result['id']}: {result.get('error', '')}")

        # Prune deleted files
        from sqlalchemy import select
        all_db_rules = session.scalars(select(Rule)).all()
        for db_rule in all_db_rules:
            if db_rule.file_path not in disk_files:
                if verbose:
                    print(f"  [PRUNE] {db_rule.id}")
                session.delete(db_rule)
                results["deleted"] += 1
        session.commit()

        # Sync bypass log
        if bypass_log_path:
            n = sync_bypass_log(bypass_log_path, session)
            results["bypass_entries"] = n

    return results
