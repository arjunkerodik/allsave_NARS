"""What makes a log a threat, stated as parameters that can be checked.

One log is rarely a threat by itself. A rule says which logs count, how they are grouped, what is
measured over them, the limit, and the time window. This module states those parameters in words,
measures them on any set of logs, and explains the result for a single log.
"""
import statistics
from collections import Counter

from models import get_alerts_by_ids, get_detections_for_logs, get_log_context
from utils.dataset_analysis import _confirmed_threshold, is_confirmed
from utils.detection_engine import matches, simulation_run_of

MB = 1024 * 1024

FIELD_NAMES = {
    'event_type': 'event type', 'command_line': 'command line', 'src_ip': 'source IP', 'dst_ip': 'destination IP', 'dst_port': 'destination port',
    'process_name': 'process', 'parent_process_name': 'parent process', 'bytes_out': 'bytes sent', 'hostname': 'host', 'connection_status': 'connection status',
    'file_path': 'file path', 'status_code': 'status code', 'auth_result': 'login result', 'user': 'user',
}


def field_name(field):
    return FIELD_NAMES.get(field, field.replace('_', ' '))


def condition_words(condition):
    """A rule's condition in plain words"""
    if 'all' in condition:
        return ' and '.join(condition_words(child) for child in condition['all'])
    if 'any' in condition:
        return '(' + ' or '.join(condition_words(child) for child in condition['any']) + ')'
    if 'not' in condition:
        return f"not {condition_words(condition['not'])}"
    name = field_name(condition['field'])
    if 'exists' in condition:
        return f"{name} is {'present' if condition['exists'] else 'absent'}"
    if 'regex' in condition:
        return f'{name} matches a known suspicious pattern'
    if 'ip_scope' in condition:
        return f"{name} is {condition['ip_scope']}"
    if 'equals' in condition:
        return f"{name} is {condition['equals']}"
    return f"{name} is one of {', '.join(str(value) for value in condition['in'])}"


def condition_checks(condition, event):
    """Each simple test in a condition, with what this log actually holds and whether it passed"""
    checks = []
    for key in ('all', 'any'):
        for child in condition.get(key, ()):
            checks.extend(condition_checks(child, event))
    if 'not' in condition:
        checks.extend({**check, 'required': f"not: {check['required']}", 'met': not check['met']}
                      for check in condition_checks(condition['not'], event))
    if 'field' in condition:
        checks.append({'field': field_name(condition['field']), 'required': condition_words(condition),
                       'actual': event.get(condition['field']), 'met': matches(condition, event)})
    return checks


def measure_of(rule):
    """What the rule measures: (description, unit)"""
    if rule['type'] == 'sum':
        return f"total {field_name(rule['field'])}", 'bytes'
    if rule['type'] == 'sequence':
        return 'matching logs before the follow-up log', 'logs'
    if rule['type'] == 'periodic':
        return 'evenly spaced connections', 'connections'
    if rule.get('distinct'):
        return f"different {field_name(rule['distinct'])} values", 'distinct values'
    return 'matching logs', 'logs'


def limit_of(rule):
    return rule['min_events'] if rule['type'] == 'periodic' else rule['threshold']


def format_measure(value, unit):
    if value is None:
        return '--'
    return f'{value / MB:,.1f} MB' if unit == 'bytes' else f'{value:,}'


def rule_parameters(rule):
    """One rule's parameters, and the sentence that defines when logs become a threat"""
    measure, unit = measure_of(rule)
    limit = limit_of(rule)
    group = ', '.join(field_name(field) for field in rule['group_by'])
    window = rule['window_seconds']
    if rule['type'] == 'sequence':
        logs = f"first {condition_words(rule['first'])}, then {condition_words(rule['then'])}"
        definition = f"At least {limit} logs where {condition_words(rule['first'])}, followed by one where {condition_words(rule['then'])}, from the same {group} within {window} seconds."
    elif rule['type'] == 'periodic':
        logs = condition_words(rule['match'])
        definition = (f"At least {limit} logs where {logs}, from the same {group} within {window} seconds, at least {rule['min_interval_seconds']} seconds apart "
                      f"with timing that varies by no more than {round(rule['max_jitter_ratio'] * 100)}%.")
    else:
        logs = condition_words(rule['match'])
        amount = f'{format_measure(limit, unit)} or more' if unit == 'bytes' else f'At least {limit}'
        counted = {'bytes': measure, 'logs': 'logs'}.get(unit, measure)
        joiner = 'where' if unit == 'logs' else 'in logs where'
        definition = f'{amount} {counted} {joiner} {logs}, for the same {group} within {window} seconds.'
    return {
        'id': rule['id'], 'name': rule['name'], 'type': rule['type'], 'logs_that_count': logs, 'grouped_by': group, 'measure': measure, 'unit': unit,
        'threshold': limit, 'threshold_text': format_measure(limit, unit), 'window_seconds': window, 'severity': rule['severity'],
        'confidence': rule['confidence'], 'max_confidence': rule.get('max_confidence'), 'mitre': rule.get('mitre') or [], 'definition': definition,
        'alerts': rule.get('alerts', 0), 'last_fired': rule.get('last_fired'),
    }


def _sliding_peak(rule, events):
    """The largest value the rule's measure reaches in any window over these events, and when the
    limit was first reached"""
    distinct = rule.get('distinct')
    values, total, left, peak, crossed_at = Counter(), 0, 0, 0, None
    for event in events:
        if rule['type'] == 'sum':
            total += event.get(rule['field']) or 0
        elif distinct:
            if event.get(distinct) not in (None, ''):
                values[event[distinct]] += 1
        else:
            total += 1
        while event['ts_epoch'] - events[left]['ts_epoch'] > rule['window_seconds']:
            gone = events[left]
            if rule['type'] == 'sum':
                total -= gone.get(rule['field']) or 0
            elif distinct:
                if gone.get(distinct) not in (None, ''):
                    values[gone[distinct]] -= 1
                    if values[gone[distinct]] <= 0:
                        del values[gone[distinct]]
            else:
                total -= 1
            left += 1
        peak = max(peak, len(values) if distinct else total)
        if crossed_at is None and peak >= rule['threshold']:
            crossed_at = event['ts_epoch']
    return peak, crossed_at


def _sequence_peak(rule, events):
    peak, crossed_at = 0, None
    for index, event in enumerate(events):
        earlier = [e for e in events[:index] if event['ts_epoch'] - e['ts_epoch'] <= rule['window_seconds'] and matches(rule['first'], e)]
        if matches(rule['then'], event):
            peak = max(peak, len(earlier))
            if crossed_at is None and len(earlier) >= rule['threshold']:
                crossed_at = event['ts_epoch']
    if crossed_at is None:
        # Failures with no success yet are progress toward the rule, and worth showing
        peak = max(peak, sum(1 for event in events if matches(rule['first'], event)))
    return peak, crossed_at


def _periodic_peak(rule, events):
    recent = [e for e in events if events[-1]['ts_epoch'] - e['ts_epoch'] <= rule['window_seconds']][-200:]
    if len(recent) < max(rule['min_events'], 2):
        return len(recent), None
    gaps = [b['ts_epoch'] - a['ts_epoch'] for a, b in zip(recent, recent[1:])]
    mean_gap = statistics.mean(gaps)
    regular = mean_gap >= rule['min_interval_seconds'] and statistics.pstdev(gaps) / mean_gap <= rule['max_jitter_ratio']
    return len(recent), recent[-1]['ts_epoch'] if regular else None


def peak_of(rule, events):
    """Measure a rule on a set of logs: {'observed', 'reached', 'reached_ts', 'group'}, for its strongest
    group, with reached_ts the earliest moment any group reached the limit"""
    groups = {}
    for event in events:
        if event.get('ts_epoch') is None or not matches(rule['match'], event):
            continue
        key = tuple(event.get(field) for field in rule['group_by'])
        usable = any(part not in (None, '') for part in key) if rule.get('group_optional') else all(part not in (None, '') for part in key)
        if usable:
            groups.setdefault(key, []).append(event)
    best = {'observed': 0, 'reached': False, 'reached_ts': None, 'group': None}
    measure = {'threshold': _sliding_peak, 'sum': _sliding_peak, 'sequence': _sequence_peak, 'periodic': _periodic_peak}[rule['type']]
    for key, members in groups.items():
        members.sort(key=lambda e: (e['ts_epoch'], e['id']))
        observed, crossed_at = measure(rule, members)
        earliest = min(item for item in (best['reached_ts'], crossed_at) if item is not None) if crossed_at is not None or best['reached_ts'] is not None else None
        if (crossed_at is not None, observed) > (best['reached'], best['observed']):
            best = {'observed': observed, 'reached': crossed_at is not None, 'reached_ts': earliest, 'group': dict(zip(rule['group_by'], key))}
        else:
            best['reached_ts'] = earliest
    return best


def explain_log(log, rules):
    """Why this one log is, or is not, a threat: every rule it counts toward, measured in context"""
    links = get_detections_for_logs([log['id']]).get(log['id'], [])
    linked_ids = [link['alert_id'] for link in links]
    alerts = {alert['id']: alert for alert in get_alerts_by_ids(linked_ids)}
    alert_of_rule = {alert['rule_id']: alert for alert in alerts.values()}
    minimum = _confirmed_threshold()

    rows = []
    for rule in rules:
        if not matches(rule['match'], log):
            continue
        parameters = rule_parameters(rule)
        key = {field: log.get(field) for field in rule['group_by']}
        usable = any(v not in (None, '') for v in key.values()) if rule.get('group_optional') else all(v not in (None, '') for v in key.values())
        observed, reached = 0, False
        if usable and log.get('ts_epoch') is not None:
            window = rule['window_seconds']
            context = get_log_context(simulation_run_of(log), log['ts_epoch'] - window, log['ts_epoch'] + window, key)
            measured = peak_of(rule, context)
            observed, reached = measured['observed'], measured['reached']
        alert = alert_of_rule.get(rule['id'])
        rows.append({
            **{name: parameters[name] for name in ('id', 'name', 'measure', 'unit', 'threshold', 'threshold_text', 'window_seconds', 'grouped_by', 'definition')},
            'checks': condition_checks(rule['then'] if rule['type'] == 'sequence' and matches(rule['then'], log) else rule['first'] if rule['type'] == 'sequence' else rule['match'], log),
            'group': key, 'observed': observed, 'observed_text': format_measure(observed, parameters['unit']),
            'threshold_reached': bool(alert) or reached, 'alert_id': alert['id'] if alert else None, 'confirmed': is_confirmed(alert, minimum) if alert else False,
        })
    known = {row['id'] for row in rows}
    other = [{'rule_id': alert['rule_id'], 'name': alert['rule_name'], 'detection_type': alert['detection_type'], 'severity': alert['severity'], 'confidence': alert['confidence'],
              'explanation': alert['explanation'], 'alert_id': alert['id'], 'confirmed': is_confirmed(alert, minimum)} for alert in alerts.values() if alert['rule_id'] not in known]

    if any(is_confirmed(alert, minimum) for alert in alerts.values()):
        verdict, statement = 'THREAT', 'This log is evidence for a confirmed detection: it counts toward a rule or indicator match whose parameters were met, with enough confidence.'
    elif alerts:
        verdict, statement = 'SUSPICIOUS', 'This log supports a detection that is too weak to count as confirmed, such as a behavioral or low-severity signal.'
    elif rows:
        verdict, statement = 'SUSPICIOUS', 'This log has the pattern a rule looks for, but the rule\'s limit was not reached, so no alert was raised. It is watched, not flagged.'
    else:
        verdict, statement = 'NORMAL', f'This log has none of the patterns the {len(rules)} rules look for, and supports no detection. That does not prove it is harmless.'
    return {'verdict': verdict, 'statement': statement, 'rules': rows, 'other_evidence': other, 'rules_checked': len(rules), 'confirmed_min_confidence': minimum}


def threat_parameters(rules, behavioral, ml_rules, anomaly_status, network_status, risk_settings):
    """Everything that decides whether logs count as a threat"""
    return {
        'principle': 'One log is rarely a threat by itself. Logs become a threat when they meet a rule\'s parameters: which logs count, how they are grouped, what is measured, the limit and the time window.',
        'classes': [
            {'name': 'NORMAL', 'means': 'Matches no rule\'s pattern and supports no detection.'},
            {'name': 'SUSPICIOUS', 'means': 'Has a rule\'s pattern but the limit was not reached, or supports a weak detection, or only a behavioral or model signal.'},
            {'name': 'THREAT', 'means': f"Supports an IOA rule or IOC match with confidence of at least {_confirmed_threshold()}%, and severity above LOW."},
        ],
        'rules': [rule_parameters(rule) for rule in rules],
        'indicators': {'definition': 'An event field equals a threat intelligence indicator. One match is enough, and it is evidence rather than proof.',
                       'fields': {'IP address': 'source IP, destination IP', 'Domain': 'domain, including subdomains', 'URL': 'url', 'File hash': 'file hash'},
                       'severity': 'Set by the feed. Never above HIGH on an indicator alone.'},
        'behavioral': [{'id': rule['id'], 'name': rule['name'], 'definition': rule.get('logic') or rule.get('description'), 'severity': rule.get('severity'),
                        'confidence': rule.get('confidence'), 'minimum_history': rule.get('min_baseline_events'), 'alerts': rule.get('alerts', 0)} for rule in behavioral],
        'models': {
            'anomaly': {'name': anomaly_status['name'], 'features': anomaly_status['features'], 'threshold_quantile': anomaly_status['threshold_quantile'],
                        'minimum_events': anomaly_status['minimum_events'], 'counts_as': 'Suspicious only, never a confirmed threat.'},
            'network': {'name': network_status['name'], 'input': network_status['input'], 'counts_as': 'Suspicious only, never a confirmed threat. Not validated, so no accuracy is claimed.',
                        'rules': [{'id': rule['id'], 'name': rule['name'], 'classes': rule.get('classes')} for rule in ml_rules]},
        },
        'risk': {'weights': risk_settings['weights'], 'levels': risk_settings['levels'], 'note': 'Risk sets investigation priority. It does not decide whether logs are a threat.'},
    }
