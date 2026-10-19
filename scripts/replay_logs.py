#!/usr/bin/env python3
"""
Detection Log Replay Engine

Feeds JSON log fixtures (positive attack logs, negative benign logs, baseline corpus)
into Sigma detection rule evaluation logic to verify rule accuracy and detect regressions.
"""

import os
import sys
import glob
import json
import argparse
import yaml

def get_field_value(event, field_name):
    """
    Extracts field value from log event supporting top-level, EventData,
    and nested win.eventdata structures case-insensitively.
    """
    # 1. Top-level match
    if field_name in event:
        return event[field_name]
    for k, v in event.items():
        if k.lower() == field_name.lower():
            return v
            
    # 2. Sysmon / Windows EventData dict
    event_data = event.get('EventData') or event.get('event_data')
    if isinstance(event_data, dict):
        if field_name in event_data:
            return event_data[field_name]
        for k, v in event_data.items():
            if k.lower() == field_name.lower():
                return v

    # 3. Wazuh decoded win.eventdata structure
    win_data = event.get('win', {})
    if isinstance(win_data, dict):
        ed = win_data.get('eventdata', {})
        if isinstance(ed, dict):
            if field_name in ed:
                return ed[field_name]
            for k, v in ed.items():
                if k.lower() == field_name.lower():
                    return v

    return None

def match_field_pattern(actual_val, expected_pattern, modifier=''):
    """
    Evaluates whether actual_val matches expected_pattern using Sigma modifiers.
    """
    if actual_val is None:
        return False

    actual_str = str(actual_val).lower()
    
    if isinstance(expected_pattern, list):
        if modifier == 'contains':
            return any(str(p).lower() in actual_str for p in expected_pattern)
        elif modifier == 'endswith':
            return any(actual_str.endswith(str(p).lower()) for p in expected_pattern)
        elif modifier == 'startswith':
            return any(actual_str.startswith(str(p).lower()) for p in expected_pattern)
        else:
            return any(str(p).lower() == actual_str for p in expected_pattern)
    else:
        exp_str = str(expected_pattern).lower()
        if modifier == 'contains':
            return exp_str in actual_str
        elif modifier == 'endswith':
            return actual_str.endswith(exp_str)
        elif modifier == 'startswith':
            return actual_str.startswith(exp_str)
        else:
            return exp_str == actual_str

def evaluate_sigma_rule(sigma_data, event):
    """
    Evaluates a single JSON event against the Sigma rule detection definition.
    Returns True if rule fires, False otherwise.
    """
    detection = sigma_data.get('detection', {})
    condition = detection.get('condition', '')
    if not condition:
        return False

    block_results = {}
    for block_name, block_spec in detection.items():
        if block_name == 'condition' or not isinstance(block_spec, dict):
            continue

        block_match = True
        for field_def, pattern in block_spec.items():
            parts = field_def.split('|')
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else ''

            actual_val = get_field_value(event, field_name)
            if not match_field_pattern(actual_val, pattern, modifier):
                block_match = False
                break
        block_results[block_name] = block_match

    # Evaluate the condition string safely
    # Tokens to replace: block identifiers with Python True/False
    tokens = condition.split()
    eval_tokens = []
    for tok in tokens:
        clean_tok = tok.strip('()')
        if clean_tok in block_results:
            rep = str(block_results[clean_tok])
            eval_tokens.append(tok.replace(clean_tok, rep))
        elif tok in ('and', 'or', 'not', '(', ')'):
            eval_tokens.append(tok)
        else:
            eval_tokens.append('False')

    try:
        res = eval(' '.join(eval_tokens))
        return bool(res)
    except Exception as e:
        return False

def replay(rules_dir='rules/sigma/', fixtures_dir='tests/fixtures/', test_type='all', verbose=False):
    """
    Executes log replay test suite and prints evaluation results.
    """
    rule_files = glob.glob(os.path.join(rules_dir, '**', '*.yml'), recursive=True)
    if not rule_files:
        print(f"No Sigma rules found in {rules_dir}")
        return False

    # Map technique ID to list of rules
    rules_by_tech = {}
    for rf in rule_files:
        with open(rf, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        tags = data.get('tags', [])
        for t in tags:
            if t.startswith('attack.t'):
                tech_id = t.replace('attack.', '').upper()
                rules_by_tech.setdefault(tech_id, []).append((rf, data))

    print("=" * 70)
    print("DETECTION ENGINEERING LOG REPLAY TEST HARNESS")
    print("=" * 70)
    print(f"Loaded {len(rule_files)} Sigma rule(s) covering {len(rules_by_tech)} technique(s).")
    print(f"Target Fixture Directory: {fixtures_dir}")
    print(f"Test Mode: {test_type.upper()}")
    print("-" * 70)

    total_tests = 0
    passed_tests = 0
    failures = []

    # 1. Positive Tests (Attack logs MUST trigger rule)
    if test_type in ('all', 'positive'):
        pos_fixtures = sorted(glob.glob(os.path.join(fixtures_dir, '*_positive.json')))
        print(f"\n[+] Executing Positive Regression Tests ({len(pos_fixtures)} fixtures)...")
        for pf in pos_fixtures:
            tech_id = os.path.basename(pf).replace('_positive.json', '')
            if tech_id not in rules_by_tech:
                continue

            rule_list = rules_by_tech[tech_id]
            with open(pf, 'r', encoding='utf-8') as f:
                event = json.load(f)

            fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
            total_tests += 1
            if fired:
                passed_tests += 1
                if verbose:
                    matching = [rdata.get('title') for rf, rdata in rule_list if evaluate_sigma_rule(rdata, event)]
                    print(f"  [PASS] {tech_id}: True Positive confirmed ({', '.join(matching)})")
            else:
                failures.append(f"FAILED Positive test for {tech_id}: None of {len(rule_list)} rules fired on attack fixture")
                print(f"  [FAIL] {tech_id}: Expected ALERT but rule did NOT fire!")

    # 2. Negative Tests (Benign logs MUST NOT trigger rule)
    if test_type in ('all', 'negative'):
        neg_fixtures = sorted(glob.glob(os.path.join(fixtures_dir, '*_negative.json')))
        print(f"\n[-] Executing Negative Regression Tests ({len(neg_fixtures)} fixtures)...")
        for nf in neg_fixtures:
            tech_id = os.path.basename(nf).replace('_negative.json', '')
            if tech_id not in rules_by_tech:
                continue

            rule_list = rules_by_tech[tech_id]
            with open(nf, 'r', encoding='utf-8') as f:
                event = json.load(f)

            any_fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
            total_tests += 1
            if not any_fired:
                passed_tests += 1
                if verbose:
                    print(f"  [PASS] {tech_id}: True Negative confirmed (Benign log ignored by all {len(rule_list)} rules)")
            else:
                fired_titles = [rdata.get('title') for rf, rdata in rule_list if evaluate_sigma_rule(rdata, event)]
                failures.append(f"FAILED Negative test for {tech_id}: False Positive fired ({', '.join(fired_titles)})")
                print(f"  [FAIL] {tech_id}: False Positive! Rule fired on benign log!")

    # 3. Baseline Corpus Replay
    if test_type in ('all', 'baseline'):
        baseline_files = glob.glob(os.path.join(fixtures_dir, 'baseline', '*.json'))
        if baseline_files:
            print(f"\n[~] Replaying Benign Baseline Corpus ({len(baseline_files)} files)...")
            for bf in baseline_files:
                with open(bf, 'r', encoding='utf-8') as f:
                    corpus = json.load(f)
                events = corpus if isinstance(corpus, list) else [corpus]
                fp_count = 0
                for ev in events:
                    for tech_id, rule_list in rules_by_tech.items():
                        for rf, rule_data in rule_list:
                            if evaluate_sigma_rule(rule_data, ev):
                                fp_count += 1
                                failures.append(f"Baseline FP: Rule {rule_data.get('title')} ({tech_id}) triggered on benign baseline event ID {ev.get('EventID')}")
                print(f"  Replayed {len(events)} baseline events. Total False Positives: {fp_count}")

    print("\n" + "=" * 70)
    print(f"TEST RESULTS SUMMARY: {passed_tests}/{total_tests} PASSED")
    print("=" * 70)

    if failures:
        print("\nFailures:")
        for fail in failures:
            print(f" - {fail}")
        return False
    else:
        print("\nAll regression tests passed with 100% accuracy!")
        return True

def main():
    parser = argparse.ArgumentParser(description="Replay log fixtures against Sigma detection rules")
    parser.add_argument('--rules', default='rules/sigma/', help="Directory of Sigma rules")
    parser.add_argument('--fixtures', default='tests/fixtures/', help="Directory of JSON log fixtures")
    parser.add_argument('--type', choices=['positive', 'negative', 'baseline', 'all'], default='all', help="Type of tests to run")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose per-test output")
    args = parser.parse_args()

    success = replay(args.rules, args.fixtures, args.type, args.verbose)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
