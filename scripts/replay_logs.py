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
import re
import argparse
import yaml
import xml.etree.ElementTree as ET

def normalize_wazuh_event(event):
    """
    Normalizes a Wazuh alert JSON structure into a flat dictionary with standard
    Windows / Sysmon field names at the top level.
    """
    if not isinstance(event, dict):
        return event

    normalized = dict(event)
    data = event.get('data')
    if isinstance(data, dict):
        win = data.get('win')
        if isinstance(win, dict):
            sys_info = win.get('system', {})
            if isinstance(sys_info, dict):
                if 'eventID' in sys_info and 'EventID' not in normalized:
                    normalized['EventID'] = sys_info['eventID']
                if 'computer' in sys_info and 'Computer' not in normalized:
                    normalized['Computer'] = sys_info['computer']
                if 'channel' in sys_info and 'Channel' not in normalized:
                    normalized['Channel'] = sys_info['channel']

            event_data = win.get('eventdata', {})
            if isinstance(event_data, dict):
                for k, v in event_data.items():
                    normalized[k] = v
                    k_lower = k.lower()
                    if k_lower == 'commandline' and 'CommandLine' not in normalized:
                        normalized['CommandLine'] = v
                    elif k_lower == 'image' and 'Image' not in normalized:
                        normalized['Image'] = v
                    elif k_lower == 'parentimage' and 'ParentImage' not in normalized:
                        normalized['ParentImage'] = v
                    elif k_lower == 'user' and 'User' not in normalized:
                        normalized['User'] = v
                    elif k_lower == 'targetfilename' and 'TargetFilename' not in normalized:
                        normalized['TargetFilename'] = v
        for dk, dv in data.items():
            if dk != 'win' and dk not in normalized:
                normalized[dk] = dv

    return normalized


def _parse_single_xml_event(event_el):
    """Parses a single XML <Event> element into a normalized dictionary."""
    ev = {}
    for child in event_el:
        tag = child.tag.split('}')[-1]
        if tag == 'System':
            for sc in child:
                stag = sc.tag.split('}')[-1]
                if stag == 'TimeCreated':
                    ev['TimeCreated'] = sc.attrib.get('SystemTime', '')
                    ev['timestamp'] = ev['TimeCreated']
                elif stag == 'Execution':
                    ev['ProcessId'] = sc.attrib.get('ProcessID', '')
                    ev['ThreadId'] = sc.attrib.get('ThreadID', '')
                elif sc.text:
                    ev[stag] = sc.text.strip()
        elif tag == 'EventData':
            for dc in child:
                name = dc.attrib.get('Name')
                val = dc.text or ''
                if name:
                    clean_val = val.strip()
                    ev[name] = clean_val
                    name_lower = name.lower()
                    if name_lower == 'commandline' and 'CommandLine' not in ev:
                        ev['CommandLine'] = clean_val
                    elif name_lower == 'image' and 'Image' not in ev:
                        ev['Image'] = clean_val
                    elif name_lower == 'parentimage' and 'ParentImage' not in ev:
                        ev['ParentImage'] = clean_val
    return [ev]


def parse_sysmon_xml(xml_content):
    """
    Parses Windows Event Log / Sysmon XML exports into normalized event dicts.
    Handles single <Event> or multiple <Events><Event>...</Event></Events>.
    """
    events = []
    text = xml_content.strip()
    if not text:
        return events

    if text.count('<Event') > 1 and not text.startswith('<Events'):
        text = f"<Events>{text}</Events>"

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        chunks = re.findall(r'(<Event\b.*?</Event>)', text, re.DOTALL)
        for chunk in chunks:
            try:
                sub_root = ET.fromstring(chunk)
                events.extend(_parse_single_xml_event(sub_root))
            except Exception:
                pass
        return events

    tag_clean = root.tag.split('}')[-1]
    if tag_clean == 'Event':
        events.extend(_parse_single_xml_event(root))
    else:
        for child in root:
            if child.tag.split('}')[-1] == 'Event':
                events.extend(_parse_single_xml_event(child))

    return events


def parse_cef_log(cef_content):
    """
    Parses Common Event Format (CEF) log string(s) into normalized event dicts.
    Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    events = []
    lines = cef_content.strip().splitlines()
    cef_regex = re.compile(r'^CEF:\s*(\d+)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$')

    for line in lines:
        line = line.strip()
        if not line or not line.startswith('CEF:'):
            continue
        m = cef_regex.match(line)
        if not m:
            continue

        ev = {
            'cefVersion': m.group(1),
            'deviceVendor': m.group(2),
            'deviceProduct': m.group(3),
            'deviceVersion': m.group(4),
            'signatureId': m.group(5),
            'name': m.group(6),
            'severity': m.group(7),
            'EventID': m.group(5),
        }

        ext_str = m.group(8)
        tokens = re.findall(r'(\w+)=(.*?)(?=(?:\s+\w+=|$))', ext_str)
        for k, v in tokens:
            ev[k] = v.strip()

        for i in range(1, 10):
            label_key = f'cs{i}Label'
            val_key = f'cs{i}'
            if label_key in ev and val_key in ev:
                ev[ev[label_key]] = ev[val_key]

        if 'dproc' in ev and 'Image' not in ev:
            ev['Image'] = ev['dproc']
        if 'sproc' in ev and 'ParentImage' not in ev:
            ev['ParentImage'] = ev['sproc']
        if 'cs1' in ev and 'CommandLine' not in ev and ev.get('cs1Label') == 'CommandLine':
            ev['CommandLine'] = ev['cs1']
        if 'suser' in ev and 'User' not in ev:
            ev['User'] = ev['suser']
        if 'duser' in ev and 'TargetUserName' not in ev:
            ev['TargetUserName'] = ev['duser']

        events.append(ev)

    return events


def parse_ndjson_log(ndjson_content):
    """
    Parses newline-delimited JSON (NDJSON) string into a list of normalized event dicts.
    """
    events = []
    for line in ndjson_content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
            if isinstance(ev, dict):
                events.append(normalize_wazuh_event(ev))
        except Exception:
            pass
    return events


def load_log_file(file_path, log_format='auto'):
    """
    Loads and normalizes events from a log file supporting multiple formats:
    'json', 'wazuh', 'sysmon_xml', 'cef', 'ndjson', 'auto'.
    Returns a list of normalized event dictionaries or a single dict.
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    resolved_format = log_format.lower()
    if resolved_format == 'auto':
        ext = os.path.splitext(file_path)[1].lower()
        stripped = content.strip()
        if ext == '.xml' or stripped.startswith('<'):
            resolved_format = 'sysmon_xml'
        elif ext == '.cef' or stripped.startswith('CEF:'):
            resolved_format = 'cef'
        elif ext == '.ndjson':
            resolved_format = 'ndjson'
        else:
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict) and ('rule' in parsed or ('data' in parsed and 'win' in parsed.get('data', {}))):
                    resolved_format = 'wazuh'
                else:
                    resolved_format = 'json'
            except Exception:
                if '\n' in stripped and any(line.strip().startswith('{') for line in stripped.splitlines()):
                    resolved_format = 'ndjson'
                else:
                    resolved_format = 'json'

    if resolved_format == 'sysmon_xml':
        evs = parse_sysmon_xml(content)
        return evs if len(evs) > 1 else (evs[0] if evs else {})
    elif resolved_format == 'cef':
        evs = parse_cef_log(content)
        return evs if len(evs) > 1 else (evs[0] if evs else {})
    elif resolved_format == 'ndjson':
        return parse_ndjson_log(content)
    elif resolved_format == 'wazuh':
        data = json.loads(content)
        if isinstance(data, list):
            return [normalize_wazuh_event(d) for d in data]
        return normalize_wazuh_event(data)
    else:
        data = json.loads(content)
        if isinstance(data, list):
            return [normalize_wazuh_event(d) if isinstance(d, dict) else d for d in data]
        return normalize_wazuh_event(data) if isinstance(data, dict) else data


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

    # 4. Common field aliases across Windows event channels (e.g., EID 4688 vs Sysmon EID 1)
    field_aliases = {
        'image': ['NewProcessName', 'ProcessName', 'ImagePath'],
        'parentimage': ['ParentProcessName'],
        'commandline': ['ProcessCommandLine'],
        'user': ['SubjectUserName', 'TargetUserName'],
    }
    for alias in field_aliases.get(field_name.lower(), []):
        if alias in event:
            return event[alias]
        for k, v in event.items():
            if k.lower() == alias.lower():
                return v
        if isinstance(event_data, dict):
            for k, v in event_data.items():
                if k.lower() == alias.lower():
                    return v
        if isinstance(win_data, dict):
            ed = win_data.get('eventdata', {})
            if isinstance(ed, dict):
                for k, v in ed.items():
                    if k.lower() == alias.lower():
                        return v

    return None

def match_field_pattern(actual_val, expected_pattern, modifier='', all_must_match=False):
    """
    Evaluates whether actual_val matches expected_pattern using Sigma modifiers.
    Supports |contains, |endswith, |startswith, |re (regex), and |all modifier.
    """
    if actual_val is None:
        return False

    actual_str = str(actual_val)
    actual_str_lower = actual_str.lower()
    
    if isinstance(expected_pattern, list):
        if all_must_match:
            # ALL items in the list must match
            if modifier == 'contains':
                return all(str(p).lower() in actual_str_lower for p in expected_pattern)
            elif modifier == 'endswith':
                return all(actual_str_lower.endswith(str(p).lower()) for p in expected_pattern)
            elif modifier == 'startswith':
                return all(actual_str_lower.startswith(str(p).lower()) for p in expected_pattern)
            elif modifier == 're':
                return all(bool(re.search(str(p), actual_str, re.IGNORECASE)) for p in expected_pattern)
            else:
                return all(str(p).lower() == actual_str_lower for p in expected_pattern)
        else:
            # ANY item in the list matches (standard Sigma default)
            if modifier == 'contains':
                return any(str(p).lower() in actual_str_lower for p in expected_pattern)
            elif modifier == 'endswith':
                return any(actual_str_lower.endswith(str(p).lower()) for p in expected_pattern)
            elif modifier == 'startswith':
                return any(actual_str_lower.startswith(str(p).lower()) for p in expected_pattern)
            elif modifier == 're':
                return any(bool(re.search(str(p), actual_str, re.IGNORECASE)) for p in expected_pattern)
            else:
                return any(str(p).lower() == actual_str_lower for p in expected_pattern)
    else:
        exp_str = str(expected_pattern)
        exp_str_lower = exp_str.lower()
        if modifier == 'contains':
            return exp_str_lower in actual_str_lower
        elif modifier == 'endswith':
            return actual_str_lower.endswith(exp_str_lower)
        elif modifier == 'startswith':
            return actual_str_lower.startswith(exp_str_lower)
        elif modifier == 're':
            return bool(re.search(exp_str, actual_str, re.IGNORECASE))
        else:
            return exp_str_lower == actual_str_lower

def evaluate_sigma_rule(sigma_data, event):
    """
    Evaluates a single JSON event against the Sigma rule detection definition.
    Returns True if rule fires, False otherwise.
    Supports dictionary field definitions, modifiers (|contains, |endswith, |startswith, |re, |all),
    and free-text keywords detection blocks.
    """
    detection = sigma_data.get('detection', {})
    condition = detection.get('condition', '')
    if not condition:
        return False

    block_results = {}
    for block_name, block_spec in detection.items():
        if block_name == 'condition':
            continue

        # Handle free-text keywords blocks (list of strings)
        if isinstance(block_spec, list):
            parts = block_name.split('|')
            base_block = parts[0]
            mods = [p.lower() for p in parts[1:]]
            all_kw = 'all' in mods
            event_text = json.dumps(event).lower()
            if all_kw:
                match_val = all(str(kw).lower() in event_text for kw in block_spec)
            else:
                match_val = any(str(kw).lower() in event_text for kw in block_spec)
            block_results[base_block] = match_val
            block_results[block_name] = match_val
            continue

        if not isinstance(block_spec, dict):
            continue

        block_match = True
        for field_def, pattern in block_spec.items():
            parts = field_def.split('|')
            field_name = parts[0]
            modifiers = [p.lower() for p in parts[1:]]
            all_must_match = 'all' in modifiers
            non_all_mods = [m for m in modifiers if m != 'all']
            modifier = non_all_mods[0] if non_all_mods else ''

            actual_val = get_field_value(event, field_name)
            if not match_field_pattern(actual_val, pattern, modifier, all_must_match):
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

def parse_event_timestamp(event, default_index=0):
    """
    Extracts numerical timestamp from log event in seconds.
    Supports Unix epoch timestamps, ISO 8601 strings, or sequential fallback index.
    """
    if not isinstance(event, dict):
        return float(default_index)

    for k in ('timestamp', 'Timestamp', 'TimeGenerated', 'time'):
        if k in event and event[k] is not None:
            try:
                return float(event[k])
            except (ValueError, TypeError):
                pass

    for k in ('UtcTime', 'TimeCreated', 'SystemTime'):
        val = get_field_value(event, k)
        if val is not None:
            if isinstance(val, (int, float)):
                return float(val)
            try:
                from datetime import datetime
                s = str(val).replace('Z', '+00:00').strip()
                dt = datetime.fromisoformat(s)
                return dt.timestamp()
            except Exception:
                pass

    return float(default_index)


def parse_timeframe_seconds(tf_val):
    """
    Parses Sigma timeframe string into floating-point seconds (e.g. 60s, 5m, 1h).
    """
    if isinstance(tf_val, (int, float)):
        return float(tf_val)
    if not tf_val:
        return 60.0
    tf_str = str(tf_val).strip().lower()
    if tf_str.endswith('s'):
        return float(tf_str[:-1])
    elif tf_str.endswith('m'):
        return float(tf_str[:-1]) * 60.0
    elif tf_str.endswith('h'):
        return float(tf_str[:-1]) * 3600.0
    elif tf_str.endswith('d'):
        return float(tf_str[:-1]) * 86400.0
    try:
        return float(tf_str)
    except ValueError:
        return 60.0


def evaluate_sigma_rule_sequence(sigma_data, events):
    """
    Evaluates a sequence of events against a Sigma rule with temporal correlation:
    - Count threshold: 'selection | count() >= N' or '> N' within timeframe
    - Ordered sequence: 'selection_a then selection_b' within timeframe
    Supports sliding time windows and groupby entity aggregation.
    """
    if not isinstance(events, list):
        return evaluate_sigma_rule(sigma_data, events)

    if not events:
        return False

    detection = sigma_data.get('detection', {})
    condition = detection.get('condition', '')
    timeframe_val = (
        sigma_data.get('timeframe')
        or detection.get('timeframe')
        or sigma_data.get('timespan')
    )
    window_seconds = parse_timeframe_seconds(timeframe_val) if timeframe_val else 60.0

    groupby = sigma_data.get('groupby') or sigma_data.get('group-by') or detection.get('groupby')
    groupby_fields = [groupby] if isinstance(groupby, str) else (groupby or [])

    # Group events by groupby fields if specified
    grouped_events = {}
    for idx, ev in enumerate(events):
        if groupby_fields:
            key = tuple(get_field_value(ev, f) for f in groupby_fields)
        else:
            key = None
        grouped_events.setdefault(key, []).append((parse_event_timestamp(ev, idx), ev))

    # Pattern 1: Count threshold correlation ("selection | count() >= 5")
    count_match = re.search(r'([a-zA-Z0-9_]+)\s*\|\s*count\(\)\s*(>=|>|==|=)\s*(\d+)', condition)
    if count_match:
        target_block = count_match.group(1)
        op = count_match.group(2)
        threshold = int(count_match.group(3))

        if target_block not in detection:
            return False

        single_rule = {
            'detection': {
                target_block: detection[target_block],
                'condition': target_block
            }
        }

        for grp_key, ev_list in grouped_events.items():
            matching_events = [
                (ts, ev) for ts, ev in ev_list if evaluate_sigma_rule(single_rule, ev)
            ]
            matching_events.sort(key=lambda x: x[0])

            # Sliding time-window evaluation
            for i in range(len(matching_events)):
                start_ts = matching_events[i][0]
                window_matches = [
                    ev for ts, ev in matching_events[i:]
                    if (ts - start_ts) <= window_seconds
                ]
                win_len = len(window_matches)
                if op == '>=' and win_len >= threshold:
                    return True
                elif op == '>' and win_len > threshold:
                    return True
                elif op in ('==', '=') and win_len == threshold:
                    return True

        return False

    # Pattern 2: Ordered sequence correlation ("selection_a then selection_b")
    then_match = re.search(r'([a-zA-Z0-9_]+)\s+then\s+([a-zA-Z0-9_]+)', condition, re.IGNORECASE)
    if then_match:
        block_a = then_match.group(1)
        block_b = then_match.group(2)

        if block_a not in detection or block_b not in detection:
            return False

        rule_a = {'detection': {block_a: detection[block_a], 'condition': block_a}}
        rule_b = {'detection': {block_b: detection[block_b], 'condition': block_b}}

        for grp_key, ev_list in grouped_events.items():
            ev_list.sort(key=lambda x: x[0])
            for i, (ts_a, ev_a) in enumerate(ev_list):
                if evaluate_sigma_rule(rule_a, ev_a):
                    for ts_b, ev_b in ev_list[i + 1:]:
                        if 0 <= (ts_b - ts_a) <= window_seconds:
                            if evaluate_sigma_rule(rule_b, ev_b):
                                return True

        return False

    # Fallback: if standard boolean rule evaluated against list, match if any event triggers it
    return any(evaluate_sigma_rule(sigma_data, ev) for ev in events)


class CorrelationEngine:
    """
    Stateful multi-event sliding window correlation engine.
    Maintains time-ordered event buffers and evaluates count thresholds and
    event transitions across configurable entity dimensions.
    """
    def __init__(self, window_seconds=60.0):
        self.window_seconds = window_seconds
        self.events = []

    def add_event(self, event, timestamp=None):
        ts = timestamp if timestamp is not None else parse_event_timestamp(event, len(self.events))
        self.events.append((ts, event))

    def clear(self):
        self.events.clear()

    def evaluate_rule(self, sigma_rule):
        event_objs = [e for _, e in self.events]
        return evaluate_sigma_rule_sequence(sigma_rule, event_objs)


def replay(rules_dir='rules/sigma/', fixtures_dir='tests/fixtures/', test_type='all', verbose=False, rule_filter=None, log_format='auto', target_file=None):
    """
    Executes log replay test suite and prints evaluation results.
    Supports real-world log formats (JSON, Wazuh alerts, Sysmon XML, CEF, NDJSON)
    and arbitrary log file replay via target_file.
    """
    rule_files = glob.glob(os.path.join(rules_dir, '**', '*.yml'), recursive=True)
    if not rule_files:
        print(f"No Sigma rules found in {rules_dir}")
        return False

    if rule_filter:
        rf_clean = rule_filter.lower().strip()
        matched_files = []
        for rf in rule_files:
            stem = os.path.splitext(os.path.basename(rf))[0].lower()
            if rf_clean in stem or stem in rf_clean:
                matched_files.append(rf)
                continue
            try:
                with open(rf, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                rule_id = str(data.get('id', '')).lower()
                tags = [t.lower() for t in data.get('tags', [])]
                if rf_clean == rule_id or any(rf_clean in t for t in tags):
                    matched_files.append(rf)
            except Exception:
                pass
        if matched_files:
            rule_files = matched_files

    # Map technique ID to list of rules
    rules_by_tech = {}
    all_rules_data = []
    for rf in rule_files:
        with open(rf, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        all_rules_data.append((rf, data))
        tags = data.get('tags', [])
        for t in tags:
            if t.startswith('attack.t'):
                tech_id = t.replace('attack.', '').upper()
                rules_by_tech.setdefault(tech_id, []).append((rf, data))

    print("=" * 70)
    print("DETECTION ENGINEERING LOG REPLAY TEST HARNESS")
    print("=" * 70)
    print(f"Loaded {len(rule_files)} Sigma rule(s) covering {len(rules_by_tech)} technique(s).")
    if rule_filter:
        print(f"Filter: {rule_filter}")
    print(f"Log Format Mode: {log_format.upper()}")

    # Optional single-file replay mode
    if target_file:
        print(f"Target Single Log File: {target_file}")
        print("-" * 70)
        events = load_log_file(target_file, log_format=log_format)
        if not isinstance(events, list):
            events = [events]
        print(f"Parsed {len(events)} event(s) from '{target_file}'.")
        alerts = []
        for idx, ev in enumerate(events):
            for rf, rdata in all_rules_data:
                if evaluate_sigma_rule(rdata, ev):
                    alerts.append((idx + 1, rdata.get('title'), rdata.get('level'), rdata.get('tags', [])))

        # Also evaluate multi-event correlation rules across full sequence
        for rf, rdata in all_rules_data:
            cond = rdata.get('detection', {}).get('condition', '')
            if 'count()' in cond or ' then ' in cond or 'timeframe' in rdata:
                if evaluate_sigma_rule_sequence(rdata, events):
                    alerts.append(('Sequence', rdata.get('title'), rdata.get('level'), rdata.get('tags', [])))

        print(f"\n[+] Total Detections Triggered: {len(alerts)}")
        for idx, title, level, tags in alerts:
            techs = [t for t in tags if t.startswith('attack.t')]
            print(f"  [ALERT] Event {idx}: {title} (Severity: {level.upper()}, Techniques: {', '.join(techs)})")
        print("=" * 70)
        return True

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
            base = os.path.basename(pf).replace('_positive.json', '')
            tech_id = base.split('_')[0]
            if tech_id not in rules_by_tech:
                continue

            rule_list = rules_by_tech[tech_id]
            event = load_log_file(pf, log_format=log_format)

            if isinstance(event, list):
                fired = any(evaluate_sigma_rule_sequence(rdata, event) for rf, rdata in rule_list)
            else:
                fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
            total_tests += 1
            variant_name = os.path.basename(pf).replace('.json', '')
            if fired:
                passed_tests += 1
                if verbose:
                    matching = [
                        rdata.get('title') for rf, rdata in rule_list
                        if (evaluate_sigma_rule_sequence(rdata, event) if isinstance(event, list) else evaluate_sigma_rule(rdata, event))
                    ]
                    print(f"  [PASS] {variant_name} ({tech_id}): True Positive confirmed ({', '.join(matching)})")
            else:
                failures.append(f"FAILED Positive test for {variant_name} ({tech_id}): None of {len(rule_list)} rules fired on attack fixture")
                print(f"  [FAIL] {variant_name} ({tech_id}): Expected ALERT but rule did NOT fire!")

    # 2. Negative Tests (Benign logs MUST NOT trigger rule)
    if test_type in ('all', 'negative'):
        neg_fixtures = sorted(glob.glob(os.path.join(fixtures_dir, '*_negative.json')))
        print(f"\n[-] Executing Negative Regression Tests ({len(neg_fixtures)} fixtures)...")
        for nf in neg_fixtures:
            tech_id = os.path.basename(nf).replace('_negative.json', '')
            if tech_id not in rules_by_tech:
                continue

            rule_list = rules_by_tech[tech_id]
            event = load_log_file(nf, log_format=log_format)

            if isinstance(event, list):
                any_fired = any(evaluate_sigma_rule_sequence(rdata, event) for rf, rdata in rule_list)
            else:
                any_fired = any(evaluate_sigma_rule(rdata, event) for rf, rdata in rule_list)
            total_tests += 1
            if not any_fired:
                passed_tests += 1
                if verbose:
                    print(f"  [PASS] {tech_id}: True Negative confirmed (Benign log ignored by all {len(rule_list)} rules)")
            else:
                fired_titles = [
                    rdata.get('title') for rf, rdata in rule_list
                    if (evaluate_sigma_rule_sequence(rdata, event) if isinstance(event, list) else evaluate_sigma_rule(rdata, event))
                ]
                failures.append(f"FAILED Negative test for {tech_id}: False Positive fired ({', '.join(fired_titles)})")
                print(f"  [FAIL] {tech_id}: False Positive! Rule fired on benign log!")

    # 3. Baseline Corpus Replay
    if test_type in ('all', 'baseline'):
        baseline_files = glob.glob(os.path.join(fixtures_dir, 'baseline', '*.json'))
        if baseline_files:
            print(f"\n[~] Replaying Benign Baseline Corpus ({len(baseline_files)} files)...")
            for bf in baseline_files:
                corpus = load_log_file(bf, log_format=log_format)
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
    parser.add_argument('--format', choices=['json', 'wazuh', 'sysmon_xml', 'cef', 'ndjson', 'auto'], default='auto', help="Log format adapter")
    parser.add_argument('--file', default=None, help="Replay a specific external log file (in any supported format)")
    parser.add_argument('--rule', default=None, help="Filter replay to a specific rule ID, stem name, or ATT&CK technique")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose per-test output")
    args = parser.parse_args()

    success = replay(
        rules_dir=args.rules,
        fixtures_dir=args.fixtures,
        test_type=args.type,
        verbose=args.verbose,
        rule_filter=args.rule,
        log_format=args.format,
        target_file=args.file,
    )
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
