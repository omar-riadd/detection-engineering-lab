"""
Detection Regression Test Suite

Automates unit testing of Sigma detection rules using pytest:
- Stage 4: Positive regression tests (attack fixtures MUST fire)
- Stage 5: Negative regression tests (benign fixtures MUST NOT fire)
"""

import os
import sys
import glob
import json
import pytest
import yaml

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts.replay_logs import evaluate_sigma_rule, evaluate_sigma_rule_sequence

def get_rule_map():
    """Maps ATT&CK Technique ID to list of Sigma Rule dicts."""
    rule_files = glob.glob('rules/sigma/**/*.yml', recursive=True)
    mapping = {}
    for rf in rule_files:
        with open(rf, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        tags = data.get('tags', [])
        for t in tags:
            if t.startswith('attack.t'):
                tech_id = t.replace('attack.', '').upper()
                mapping.setdefault(tech_id, []).append((rf, data))
    return mapping

RULE_MAP = get_rule_map()

# Discover positive fixtures (supports standard and evasion variants)
POSITIVE_FIXTURES = sorted(glob.glob('tests/fixtures/*_positive.json'))
POSITIVE_PARAMS = []
for pf in POSITIVE_FIXTURES:
    base = os.path.basename(pf).replace('_positive.json', '')
    tech = base.split('_')[0]
    if tech in RULE_MAP:
        POSITIVE_PARAMS.append((tech, pf))

# Discover negative fixtures (test EVERY rule mapped to the technique)
NEGATIVE_FIXTURES = sorted(glob.glob('tests/fixtures/*_negative.json'))
NEGATIVE_PARAMS = []
for nf in NEGATIVE_FIXTURES:
    base = os.path.basename(nf).replace('_negative.json', '')
    tech = base.split('_')[0]
    if tech in RULE_MAP:
        for rf, rdata in RULE_MAP[tech]:
            NEGATIVE_PARAMS.append((tech, rf, nf))

@pytest.mark.parametrize("tech_id,fixture_path", POSITIVE_PARAMS)
def test_positive_detection_fires(tech_id, fixture_path):
    """
    Positive Regression Test: Attack log fixture MUST trigger at least one
    detection rule covering the technique.
    Failure indicates broken detection logic or regression.
    """
    rule_list = RULE_MAP[tech_id]
    with open(fixture_path, 'r', encoding='utf-8') as ff:
        attack_event = json.load(ff)

    if isinstance(attack_event, list):
        fired = any(evaluate_sigma_rule_sequence(rdata, attack_event) for rf, rdata in rule_list)
    else:
        fired = any(evaluate_sigma_rule(rdata, attack_event) for rf, rdata in rule_list)

    assert fired is True, (
        f"FALSE NEGATIVE REGRESSION: None of the {len(rule_list)} rules for ({tech_id}) "
        f"fired on attack log fixture {fixture_path}"
    )

@pytest.mark.parametrize("tech_id,rule_path,fixture_path", NEGATIVE_PARAMS)
def test_negative_detection_ignores_benign(tech_id, rule_path, fixture_path):
    """
    Negative Regression Test: Benign log fixture MUST NOT trigger the detection rule.
    Failure indicates a false positive regression.
    """
    with open(rule_path, 'r', encoding='utf-8') as rf:
        rule_data = yaml.safe_load(rf)

    with open(fixture_path, 'r', encoding='utf-8') as ff:
        benign_event = json.load(ff)

    if isinstance(benign_event, list):
        fired = evaluate_sigma_rule_sequence(rule_data, benign_event)
    else:
        fired = evaluate_sigma_rule(rule_data, benign_event)

    assert fired is False, (
        f"FALSE POSITIVE REGRESSION: Rule {rule_data.get('title')} ({tech_id}) "
        f"falsely triggered on benign log fixture {fixture_path}"
    )


def test_wazuh_alert_format_adapter():
    """Verify Wazuh JSON alert format adapter normalizes nested win.eventdata and triggers detection."""
    from scripts.replay_logs import load_log_file
    event = load_log_file('tests/fixtures/formats/sample_wazuh_alert.json')
    rule_list = RULE_MAP['T1059.001']
    fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
    assert fired is True, "Wazuh alert format adapter failed to trigger T1059.001 detection rule"


def test_sysmon_xml_format_adapter():
    """Verify Sysmon XML event log adapter parses XML elements into flat dict and triggers detection."""
    from scripts.replay_logs import load_log_file
    event = load_log_file('tests/fixtures/formats/sample_sysmon.xml')
    rule_list = RULE_MAP['T1218.011']
    fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
    assert fired is True, "Sysmon XML format adapter failed to trigger T1218.011 detection rule"


def test_cef_format_adapter():
    """Verify Common Event Format (CEF) adapter parses extension tokens and triggers detection."""
    from scripts.replay_logs import load_log_file
    event = load_log_file('tests/fixtures/formats/sample_cef.log')
    rule_list = RULE_MAP['T1003.001']
    fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
    assert fired is True, "CEF format adapter failed to trigger T1003.001 detection rule"


def test_ndjson_format_adapter():
    """Verify NDJSON stream adapter parses multiple lines, discriminating benign and malicious events."""
    from scripts.replay_logs import load_log_file
    events = load_log_file('tests/fixtures/formats/sample_ndjson.log')
    assert isinstance(events, list) and len(events) == 2
    rule_list = RULE_MAP['T1490']
    # Event 1 (explorer.exe) must NOT fire
    assert not any(evaluate_sigma_rule(rdata, events[0]) for rf, rdata in rule_list)
    # Event 2 (vssadmin delete shadows) MUST fire
    assert any(evaluate_sigma_rule(rdata, events[1]) for rf, rdata in rule_list)

