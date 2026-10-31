"""What a threat did to a simulated environment.

Compares the same batch's normal logs with its attack logs, shows which parameters crossed their
limits, and works out which assets were affected and how far it got. Asset states are inferred from
the detections, using config/impact_model.json. Nothing real is changed or measured.
"""
import ipaddress
import json
import os

from models import get_all_batch_events, get_batch_alerts, get_batch_evidence_ids, get_ground_truth, get_response_actions
from utils.threat_parameters import format_measure, limit_of, measure_of, peak_of

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'impact_model.json')
MB = 1024 * 1024
ASSET_KINDS = {'user': 'Account', 'hostname': 'Host', 'dst_ip': 'Internal address'}
ADMIN_PORTS = (22, 135, 445, 3389, 5985, 5986)
CIA_NAMES = {'C': 'Confidentiality', 'I': 'Integrity', 'A': 'Availability'}


def _load_model(path=MODEL_PATH):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def _is_external(value):
    try:
        return ipaddress.ip_address(value).is_global or str(value).startswith(('192.0.2.', '198.51.100.', '203.0.113.'))
    except (TypeError, ValueError):
        return False


def _activity(events):
    """What these logs show, so that normal and attack logs can be set side by side"""
    logins = [event for event in events if event.get('event_category') == 'authentication']
    network = [event for event in events if event.get('source') == 'network']
    times = [event['ts_epoch'] for event in events if event.get('ts_epoch') is not None]
    minutes = max((max(times) - min(times)) / 60, 1) if times else 1
    return {
        'events': len(events),
        'events_per_minute': round(len(events) / minutes, 2),
        'failed_logins': sum(1 for event in logins if event.get('auth_result') == 'failure'),
        'successful_logins': sum(1 for event in logins if event.get('auth_result') != 'failure'),
        'sources': len({event['src_ip'] for event in events if event.get('src_ip')}),
        'admin_port_connections': sum(1 for event in network if event.get('dst_port') in ADMIN_PORTS),
        'outbound_mb': round(sum(event.get('bytes_out') or 0 for event in network if _is_external(event.get('dst_ip'))) / MB, 1),
        'processes_started': sum(1 for event in events if event.get('process_name')),
    }


ACTIVITY_LABELS = (
    ('events', 'Logs'), ('events_per_minute', 'Logs per minute'), ('failed_logins', 'Failed logins'), ('successful_logins', 'Successful logins'),
    ('sources', 'Different source IPs'), ('admin_port_connections', 'Connections to administration ports'), ('outbound_mb', 'MB sent to external addresses'),
    ('processes_started', 'Processes started'),
)


def _parameter_rows(rules_by_id, alerts, normal, attack):
    """Each rule that fired: how far normal logs got, how far attack logs got, and the limit"""
    rows = []
    for rule_id in sorted({alert['rule_id'] for alert in alerts}):
        rule = rules_by_id.get(rule_id)
        fired = [alert for alert in alerts if alert['rule_id'] == rule_id]
        if not rule:
            rows.append({'rule_id': rule_id, 'name': fired[0]['rule_name'], 'measure': 'Evidence for this detection', 'detection_type': fired[0]['detection_type'],
                         'normal': None, 'attack': None, 'normal_text': '--', 'attack_text': f"{sum(a.get('event_count') or 0 for a in fired)} logs", 'threshold_text': 'See explanation',
                         'crossed': True, 'explanation': fired[0]['explanation']})
            continue
        measure, unit = measure_of(rule)
        before, during = peak_of(rule, normal), peak_of(rule, attack)
        rows.append({'rule_id': rule_id, 'name': rule['name'], 'measure': measure, 'detection_type': 'IOA', 'window_seconds': rule['window_seconds'], 'reached_ts': during['reached_ts'],
                     'normal': before['observed'], 'attack': during['observed'], 'normal_text': format_measure(before['observed'], unit), 'attack_text': format_measure(during['observed'], unit),
                     'threshold': limit_of(rule), 'threshold_text': format_measure(limit_of(rule), unit), 'crossed': during['reached'], 'normal_crossed': before['reached'],
                     'explanation': fired[0]['explanation']})
    return rows


def _assets(alerts, model):
    """Each asset the detections point to, the worst state it reached, and how it got there"""
    assets = {}
    for alert in sorted(alerts, key=lambda a: a.get('first_seen_ts') or 0):
        effect = model['rules'].get(alert['rule_id'])
        if not effect:
            continue
        entities = alert.get('entities') or {}
        for field in effect['assets']:
            for name in entities.get(field) or []:
                if field == 'dst_ip' and _is_external(name):
                    continue
                asset = assets.setdefault((field, name), {'kind': ASSET_KINDS[field], 'name': name, 'before': 'Normal', 'level': 0, 'after': 'Normal', 'steps': [], 'cia': set()})
                asset['steps'].append({'time': alert['first_seen'], 'rule_id': alert['rule_id'], 'effect': effect['effect'], 'level': effect['level'], 'state': model['levels'][str(effect['level'])]})
                asset['cia'].update(effect['cia'])
                if effect['level'] > asset['level']:
                    asset['level'] = effect['level']
                    asset['after'] = model['levels'][str(effect['level'])]
                    asset['cause'] = {'rule_id': alert['rule_id'], 'effect': effect['effect']}
    return assets


def _apply_response(assets, actions):
    """Actions an analyst has run count, in simulation. Pending ones change nothing."""
    executed = [action for action in actions if action['status'] == 'EXECUTED']
    for asset in assets.values():
        targeting = [action for action in executed if action.get('target') == asset['name']]
        asset['response'] = 'Contained in simulation' if targeting else None
        asset['actions_run'] = [action['label'] for action in targeting]


def build_impact(batch_id, rules):
    """The effect of the attack in one simulation run or dataset, from its stored results"""
    model = _load_model()
    events = get_all_batch_events(batch_id)
    truth = get_ground_truth(batch_id)
    alerts = get_batch_alerts(batch_id)
    rules_by_id = {rule['id']: rule for rule in rules}

    evidence_ids = get_batch_evidence_ids(batch_id)
    incident_ids = sorted({alert['incident_id'] for alert in alerts if alert.get('incident_id')})
    labelled = any(item['label'] != 'normal' for item in truth.values())
    if labelled:
        is_attack = lambda event: (truth.get(event.get('event_id')) or {}).get('label', 'normal') != 'normal'
    else:
        is_attack = lambda event: event['id'] in evidence_ids
    attack = [event for event in events if is_attack(event)]
    normal = [event for event in events if not is_attack(event)]

    assets = _assets(alerts, model)
    actions = [action for incident_id in incident_ids for action in get_response_actions(incident_id=incident_id)]
    _apply_response(assets, actions)
    known = {('user', event['user']) for event in events if event.get('user')} | {('hostname', event['hostname']) for event in events if event.get('hostname')}
    known_total = len(known | set(assets))
    asset_list = sorted(assets.values(), key=lambda asset: (-asset['level'], asset['kind'], asset['name']))
    for asset in asset_list:
        asset['cia'] = sorted(CIA_NAMES[letter] for letter in asset['cia'])

    attack_times = [event['ts_epoch'] for event in attack if event.get('ts_epoch') is not None]
    parameters = _parameter_rows(rules_by_id, alerts, normal, attack)
    # The moment a limit was reached is when logs became a detection. Single-log detections have no limit to wait for.
    detection_times = [row['reached_ts'] for row in parameters if row.get('reached_ts') is not None]
    detection_times += [alert['first_seen_ts'] for alert in alerts if alert['rule_id'] not in rules_by_id and alert.get('first_seen_ts') is not None]
    detected = [event for event in attack if event['id'] in evidence_ids]
    data_out = {}
    for event in attack:
        if event.get('source') == 'network' and _is_external(event.get('dst_ip')) and (event.get('bytes_out') or 0):
            data_out[event['dst_ip']] = data_out.get(event['dst_ip'], 0) + event['bytes_out']

    counts = {name: sum(1 for asset in asset_list if asset['level'] == int(level)) for level, name in model['levels'].items()}
    affected_cia = sorted({name for asset in asset_list for name in asset['cia']})
    worst = next((name for level, name in sorted(model['levels'].items(), reverse=True) if counts[name]), None)
    if not asset_list:
        headline = f"No asset was affected. None of the {len(events)} logs met a rule's parameters." if not alerts else f'{len(alerts)} detection(s) fired, but they point to no specific host or account.'
    else:
        parts = [f'{count} {name.lower()}' for name, count in sorted(counts.items(), key=lambda item: list(model['levels'].values()).index(item[0]), reverse=True) if count]
        headline = f"The threat affected {len(asset_list)} of {known_total} known assets: {', '.join(parts)}."

    pending = [action for action in actions if action['status'] == 'PENDING']
    return {
        'batch_id': batch_id,
        'simulated': not str(batch_id).startswith('ds-'),
        'headline': headline,
        'worst_state': worst,
        'state_counts': counts,
        'assets': asset_list,
        'known_assets': known_total,
        'assets_unaffected': known_total - len(asset_list),
        'cia_affected': affected_cia,
        'comparison_basis': 'Attack and normal logs are separated by the recorded ground truth.' if labelled else 'No labels exist, so logs behind a detection are compared with the rest.',
        'activity': [{'name': label, 'normal': (_activity(normal))[key], 'attack': (_activity(attack))[key]} for key, label in ACTIVITY_LABELS],
        'parameters': parameters,
        'detection': {
            'attack_logs': len(attack), 'normal_logs': len(normal), 'attack_logs_detected': len(detected), 'attack_logs_missed': len(attack) - len(detected),
            'normal_logs_flagged': sum(1 for event in normal if event['id'] in evidence_ids),
            'seconds_to_first_detection': round(max(min(detection_times) - min(attack_times), 0), 1) if attack_times and detection_times else None,
            'note': 'Event time, from the first attack log to the first log that met a rule\'s limit.',
        },
        'data_out': [{'destination': destination, 'mb': round(size / MB, 1)} for destination, size in sorted(data_out.items(), key=lambda item: -item[1])],
        'response': {'pending': len(pending), 'executed': sum(1 for action in actions if action['status'] == 'EXECUTED'),
                     'still_exposed': sum(1 for asset in asset_list if not asset['response'])},
        'note': ('Read from this log file. ' if str(batch_id).startswith('ds-') else 'Simulated environment. ')
                + 'Asset states are inferred from which detections fired, using config/impact_model.json. Nothing real was changed.',
    }
