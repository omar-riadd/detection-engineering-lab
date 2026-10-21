"""
Unit and Integration Tests for FastAPI Detection Engineering Backend
=====================================================================
Validates all REST endpoints, CQRS write path, validation rules,
error handling, and report generation using FastAPI TestClient.
"""
import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_api_health():
    """Verify health endpoint returns status and server metadata."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["version"] == "2.0.0"
    assert "ws_clients" in data


def test_list_rules():
    """Verify rules catalog returns all production rules (at least 26) and supports query filtering."""
    res = client.get("/api/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 26
    assert all("id" in r and "title" in r for r in rules)

    # Filter by severity
    res_crit = client.get("/api/rules?severity=critical")
    assert res_crit.status_code == 200
    crit_rules = res_crit.json()
    assert len(crit_rules) > 0
    assert all(r["severity"] == "critical" for r in crit_rules)

    # Filter by search
    res_search = client.get("/api/rules?search=PowerShell")
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 2


def test_rule_stats():
    """Verify rules statistics aggregation."""
    res = client.get("/api/rules/stats")
    assert res.status_code == 200
    data = res.json()
    rules_res = client.get("/api/rules")
    expected_total = len(rules_res.json())
    assert data["total"] == expected_total
    assert data["total"] >= 26
    assert "by_severity" in data
    assert "by_status" in data
    assert data["unique_techniques"] >= 20


def test_rule_detail_and_converted():
    """Verify single rule inspection and multi-SIEM transpilation outputs."""
    rule_id = "4e1b8c29-3910-46d2-88f1-a1b920499009"
    res = client.get(f"/api/rules/{rule_id}")
    assert res.status_code == 200
    rule = res.json()
    assert rule["id"] == rule_id
    assert "Active Directory" in rule["title"]
    assert rule["raw_yaml"] is not None

    # Multi-SIEM converted formats
    res_conv = client.get(f"/api/rules/{rule_id}/converted")
    assert res_conv.status_code == 200
    conv = res_conv.json()
    assert conv["rule_id"] == rule_id
    assert "formats" in conv
    assert "sigma" in conv["formats"]
    assert "wazuh" in conv["formats"]
    assert "kql" in conv["formats"]
    assert "splunk" in conv["formats"]
    assert conv["formats"]["kql"]["content"] is not None
    assert conv["formats"]["splunk"]["content"] is not None

    # 404 on nonexistent rule
    res_404 = client.get("/api/rules/non-existent-rule-id-123")
    assert res_404.status_code == 404


def test_cqrs_rule_save_validation():
    """Verify CQRS write path: catches invalid YAML, catches missing fields, allows valid save."""
    rule_id = "4e1b8c29-3910-46d2-88f1-a1b920499009"

    # 1. Invalid YAML syntax
    res_invalid_yaml = client.put(
        f"/api/rules/{rule_id}/save",
        json={"yaml_content": "invalid: [unclosed sequence"}
    )
    assert res_invalid_yaml.status_code == 422
    assert "Invalid YAML syntax" in res_invalid_yaml.json()["detail"]

    # 2. Missing mandatory Sigma fields
    res_missing_fields = client.put(
        f"/api/rules/{rule_id}/save",
        json={"yaml_content": "title: Incomplete Rule\nauthor: Test"}
    )
    assert res_missing_fields.status_code == 422
    assert "Missing mandatory Sigma fields" in res_missing_fields.json()["detail"]

    # 3. Valid round-trip save
    res_get = client.get(f"/api/rules/{rule_id}")
    current_yaml = res_get.json()["raw_yaml"]

    res_save = client.put(
        f"/api/rules/{rule_id}/save",
        json={"yaml_content": current_yaml}
    )
    assert res_save.status_code == 200
    data = res_save.json()
    assert data["status"] == "ok"
    assert data["rule_id"] == rule_id


def test_coverage_endpoints():
    """Verify ATT&CK coverage, D3FEND countermeasure mappings, MTTD, and FP reports."""
    # ATT&CK Navigator
    res_attack = client.get("/api/coverage/attack")
    assert res_attack.status_code == 200
    attack_data = res_attack.json()
    assert attack_data["technique_count"] >= 22

    # D3FEND mappings
    res_d3fend = client.get("/api/coverage/d3fend")
    assert res_d3fend.status_code == 200
    d3fend_data = res_d3fend.json()
    assert d3fend_data["count"] >= 25
    assert len(d3fend_data["mappings"]) >= 25

    # MTTD metrics
    res_mttd = client.get("/api/coverage/mttd")
    assert res_mttd.status_code == 200
    mttd_data = res_mttd.json()
    assert mttd_data["rule_count"] >= 20
    assert mttd_data["avg_mttd_seconds"] < 60.0

    # FP report
    res_fp = client.get("/api/coverage/fp-report")
    assert res_fp.status_code == 200
    fp_data = res_fp.json()
    assert fp_data["overall_fp_rate"] == 0.0


def test_bypass_endpoints():
    """Verify purple-team adversarial evasion records and stats."""
    res_list = client.get("/api/bypass")
    assert res_list.status_code == 200
    bypasses = res_list.json()
    assert len(bypasses) >= 7

    res_stats = client.get("/api/bypass/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total_cases"] == len(bypasses)
    assert stats["total_cases"] >= 7
    assert stats["detection_rate_pct"] == 100.0


def test_sync_endpoints():
    """Verify disk-to-read-model synchronization endpoints."""
    res_status = client.get("/api/sync/status")
    assert res_status.status_code == 200
    status = res_status.json()
    assert status["db_healthy"] is True
    rules_res = client.get("/api/rules")
    expected_total = len(rules_res.json())
    assert status["rules_total"] == expected_total
    assert status["rules_total"] >= 26
    assert status["rules_synced"] == status["rules_total"]
    assert status["rules_error"] == 0

    # Targeted rule sync
    rule_id = "4e1b8c29-3910-46d2-88f1-a1b920499009"
    res_force = client.post(f"/api/sync/force-rule/{rule_id}")
    assert res_force.status_code == 200
    assert res_force.json()["status"] in ("ok", "synced")


def test_test_runs_endpoints():
    """Verify test run telemetry and statistics."""
    res_runs = client.get("/api/test-runs")
    assert res_runs.status_code == 200
    assert isinstance(res_runs.json(), list)

    res_stats = client.get("/api/test-runs/stats")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "total_runs" in stats
    assert "pass_rate_pct" in stats
    assert "avg_duration_seconds" in stats


def test_reports_endpoints():
    """Verify executive summary generation and markdown export."""
    res_sum = client.get("/api/reports/summary")
    assert res_sum.status_code == 200
    summary = res_sum.json()
    assert summary["portfolio_version"] == "v2.0"
    exec_sum = summary["executive_summary"]
    rules_res = client.get("/api/rules")
    expected_total = len(rules_res.json())
    assert exec_sum["total_detections"] == expected_total
    assert exec_sum["total_detections"] >= 26
    assert exec_sum["unique_techniques"] >= 22
    assert exec_sum["overall_status"] == "OPERATIONAL / PRODUCTION READY"

    # Markdown export
    res_md = client.get("/api/reports/markdown")
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert "# Detection Engineering Lab — Executive Security Report" in res_md.text


def test_create_rule_endpoint():
    """Verify POST /api/rules creates rule file, validates schema, and reconciles into read model."""
    yaml_content = """title: Test Automated Process Execution Rule
status: test
description: Automated test rule created via REST API.
author: CI Bot
date: 2026/10/21
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\pytest_automated_test.exe'
    condition: selection
falsepositives:
    - None
level: low"""

    res = client.post(
        "/api/rules",
        json={
            "filename": "test_win_proc_automated_test.yml",
            "target_dir": "windows/proc_creation",
            "yaml_content": yaml_content,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["title"] == "Test Automated Process Execution Rule"
    assert "rule_id" in data

    # Verify rule exists in GET
    rule_res = client.get(f"/api/rules/{data['rule_id']}")
    assert rule_res.status_code == 200

    # Cleanup test file and DB entry
    from api.routers.rules import PROJECT_ROOT
    from api.models.db import Rule, get_session
    from sqlalchemy import select
    test_path = PROJECT_ROOT / data["file_path"]
    if test_path.exists():
        test_path.unlink()

    (PROJECT_ROOT / "converted" / "kql" / "test_win_proc_automated_test.kql").unlink(missing_ok=True)
    (PROJECT_ROOT / "converted" / "splunk" / "test_win_proc_automated_test.spl").unlink(missing_ok=True)
    (PROJECT_ROOT / "rules" / "wazuh" / "test_win_proc_automated_test.xml").unlink(missing_ok=True)

    with next(get_session()) as s:
        r = s.get(Rule, data["rule_id"])
        if r:
            s.delete(r)
            s.commit()


def test_create_bypass_endpoint():
    """Verify POST /api/bypass registers evasion case study and read model."""
    res = client.post(
        "/api/bypass",
        json={
            "title": "Automated CI Test Evasion",
            "technique": "PowerShell Alternate Cradles",
            "technique_id": "T1059.001",
            "target_rule": "rules/sigma/windows/proc_creation/posh_pm_susp_script_block.yml",
            "evasion_method": "Testing automated evasion creation via REST API",
            "notes": "Root cause failure analysis documented in automated test",
            "outcome": "DETECTED",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["technique_id"] == "T1059.001"
    assert data["outcome"] == "DETECTED"
    assert data["evasion_method"] == "Testing automated evasion creation via REST API"

    # Cleanup DB entry and docs/bypass_log.md
    from api.models.db import BypassAttempt, get_session
    from api.routers.bypass import BYPASS_LOG_FILE
    with next(get_session()) as s:
        ba = s.get(BypassAttempt, data["id"])
        if ba:
            s.delete(ba)
            s.commit()

    if BYPASS_LOG_FILE.exists():
        content = BYPASS_LOG_FILE.read_text(encoding="utf-8")
        idx = content.find("Automated CI Test Evasion")
        if idx != -1:
            header_idx = content.rfind("---", 0, idx)
            if header_idx != -1:
                BYPASS_LOG_FILE.write_text(content[:header_idx].rstrip() + "\n", encoding="utf-8")


def test_api_key_authentication(monkeypatch):
    """Verify optional API key authentication on write endpoints."""
    # 1. When API_KEY is set in environment
    monkeypatch.setenv("API_KEY", "super-secret-ci-key")

    # Request without key -> 403 Forbidden
    res_no_key = client.post(
        "/api/rules",
        json={
            "filename": "unauth_test.yml",
            "target_dir": "windows/proc_creation",
            "yaml_content": "title: Test\nlogsource:\n  category: proc\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n",
        },
    )
    assert res_no_key.status_code == 403
    assert "Invalid or missing API key" in res_no_key.json()["detail"]

    # Request with wrong key -> 403 Forbidden
    res_wrong_key = client.post(
        "/api/rules",
        headers={"X-API-Key": "wrong-key"},
        json={
            "filename": "unauth_test.yml",
            "target_dir": "windows/proc_creation",
            "yaml_content": "title: Test\nlogsource:\n  category: proc\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n",
        },
    )
    assert res_wrong_key.status_code == 403

    # Request with correct key -> Authorized (not 403)
    res_valid_key = client.post(
        "/api/rules",
        headers={"X-API-Key": "super-secret-ci-key"},
        json={
            "filename": "auth_test_rule.yml",
            "target_dir": "windows/proc_creation",
            "yaml_content": "title: Auth Test Rule\nlogsource:\n  category: proc\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection\n",
        },
    )
    assert res_valid_key.status_code == 200
    created_id = res_valid_key.json()["rule_id"]

    # Clean up created test rule file and database row
    from api.models.db import Rule, get_session
    from api.routers.rules import RULES_DIR, PROJECT_ROOT
    test_file = RULES_DIR / "windows" / "proc_creation" / "auth_test_rule.yml"
    if test_file.exists():
        test_file.unlink()

    (PROJECT_ROOT / "converted" / "kql" / "auth_test_rule.kql").unlink(missing_ok=True)
    (PROJECT_ROOT / "converted" / "splunk" / "auth_test_rule.spl").unlink(missing_ok=True)
    (PROJECT_ROOT / "rules" / "wazuh" / "auth_test_rule.xml").unlink(missing_ok=True)

    with next(get_session()) as s:
        rule_row = s.get(Rule, created_id)
        if rule_row:
            s.delete(rule_row)
            s.commit()


def test_deployment_endpoints():
    """Verify live SIEM deployment integration endpoints."""
    # 1. Target status
    res_status = client.get("/api/deploy/status")
    assert res_status.status_code == 200
    targets = res_status.json()
    assert "wazuh" in targets
    assert "sentinel" in targets
    assert "splunk" in targets

    # 2. Deploy existing rule with simulation
    rule_id = "4e1b8c29-3910-46d2-88f1-a1b920499009"
    res_deploy = client.post(f"/api/deploy/{rule_id}?target=all&simulate=true")
    assert res_deploy.status_code == 200
    dep_data = res_deploy.json()
    assert dep_data["status"] == "ok"
    assert dep_data["rule_id"] == rule_id
    assert len(dep_data["deployments"]) == 3
    assert all(d["status"] == "simulated" for d in dep_data["deployments"])

    # 3. Deployment history
    res_hist = client.get("/api/deploy/history")
    assert res_hist.status_code == 200
    history = res_hist.json()
    assert len(history) >= 3
    assert history[0]["rule_id"] == rule_id

    # 4. Non-existent rule returns 404
    res_404 = client.post("/api/deploy/non-existent-rule-id?target=wazuh")
    assert res_404.status_code == 404



