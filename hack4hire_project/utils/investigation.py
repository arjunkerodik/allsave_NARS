import json

from models import (
    get_alert_event_ids, get_alerts_for_incident, get_audit_entries, get_automation_log, get_incident, get_logs_by_ids,
    get_response_actions,
)
from utils.detection_engine import event_summary
from utils.response_engine import describe_actions
from utils.risk_engine import tactics_in_order

MAX_RELATED_EVENTS = 500

# What each observed MITRE tactic could mean for the organization if the activity is genuine.
TACTIC_IMPACT = {
    'Credential Access': 'Stolen credentials could give an attacker access as a legitimate user.',
    'Initial Access': 'An attacker may have an authenticated foothold on the system.',
    'Privilege Escalation': 'An attacker may have administrative control of the host.',
    'Persistence': 'Access could survive password resets and reboots.',
    'Discovery': 'An attacker may be mapping systems for later attacks.',
    'Execution': 'Attacker-controlled code may be running on the host.',
    'Lateral Movement': 'The compromise may have spread to other hosts.',
    'Collection': 'Sensitive data may have been gathered for removal.',
    'Exfiltration': 'Data may have left the organization.',
    'Command and Control': 'An attacker may have an active channel for remote control.',
}


def build_timeline(events, rules_by_event):
    """Chronological attack timeline. Consecutive identical events collapse into one entry,
    so 500 failed logins read as one line with a count."""
    timeline = []
    for event in sorted(events, key=lambda e: (e.get('ts_epoch') or 0, e['id'])):
        rules = sorted(rules_by_event.get(event['id'], []))
        key = (tuple(rules), event.get('event_type'), event.get('src_ip'), event.get('dst_ip'),
               event.get('user'), event.get('process_name'))
        if timeline and timeline[-1]['_key'] == key:
            timeline[-1]['count'] += 1
            timeline[-1]['last_timestamp'] = event.get('timestamp')
            timeline[-1]['event_ids'].append(event.get('event_id'))
            continue
        timeline.append({
            '_key': key,
            'timestamp': event.get('timestamp'),
            'last_timestamp': event.get('timestamp'),
            'count': 1,
            'source': event.get('source'),
            'event_type': event.get('event_type'),
            'summary': event_summary(event),
            'src_ip': event.get('src_ip'),
            'dst_ip': event.get('dst_ip'),
            'user': event.get('user'),
            'hostname': event.get('hostname'),
            'rule_ids': rules,
            'event_ids': [event.get('event_id')],
        })
    for entry in timeline:
        del entry['_key']
    return timeline


def _potential_impact(alerts):
    impact = []
    for tactic in tactics_in_order(alerts):
        if tactic in TACTIC_IMPACT:
            impact.append({'tactic': tactic, 'impact': TACTIC_IMPACT[tactic]})
    return impact


def _public_event(event):
    item = dict(event)
    for field in ('raw_event', 'normalized_fields'):
        if item.get(field):
            try:
                item[field] = json.loads(item[field])
            except ValueError:
                pass
    return item


def get_incident_detail(incident_id):
    """Everything an analyst needs to investigate one incident, from stored data only"""
    incident = get_incident(incident_id)
    if not incident:
        return None
    alerts = get_alerts_for_incident(incident_id)
    rules_by_event = {}
    for alert in alerts:
        for log_id in get_alert_event_ids(alert['id']):
            rules_by_event.setdefault(log_id, []).append(alert['rule_id'])
    all_ids = sorted(rules_by_event)
    events = get_logs_by_ids(all_ids[:MAX_RELATED_EVENTS])
    return {
        'incident': incident,
        'alerts': alerts,
        'timeline': build_timeline(events, rules_by_event),
        'related_events': [{**_public_event(e), 'rule_ids': sorted(rules_by_event.get(e['id'], []))}
                           for e in sorted(events, key=lambda e: (e.get('ts_epoch') or 0, e['id']))],
        'related_events_total': len(all_ids),
        'related_events_truncated': len(all_ids) > MAX_RELATED_EVENTS,
        'potential_impact': _potential_impact(alerts),
        'response_actions': describe_actions(get_response_actions(incident_id=incident_id)),
        'audit_log': get_audit_entries(incident_id=incident_id),
        'automation_log': get_automation_log(incident_id=incident_id),
    }


def _one_line(value):
    """Logs can hold anything, so keep each value on its own line of the report"""
    return ' '.join(str(value if value is not None else '').split())


def build_incident_report(detail):
    """A Markdown investigation report, built only from what is stored for the incident"""
    incident = detail['incident']
    origins = sorted({event.get('origin') or 'legacy' for event in detail['related_events']})
    breakdown = incident.get('score_breakdown') or {}
    risk = breakdown.get('risk') or {}
    lines = [
        f"# {_one_line(incident.get('incident_uid') or '#' + str(incident['id']))}: {_one_line(incident['title'])}",
        '',
        f"- **Status:** {_one_line(incident['status'])}",
        f"- **Severity:** {_one_line(incident['severity'])}",
        f"- **Confidence:** {_one_line(incident.get('confidence'))}%",
        f"- **Risk:** {_one_line(incident.get('risk_score'))}/100 {_one_line(incident.get('risk_level'))}",
        f"- **Activity:** {_one_line(incident.get('first_seen'))} to {_one_line(incident.get('last_seen'))}",
        f"- **Data origin:** {', '.join(origins) or 'unknown'}",
    ]
    if 'simulation' in origins:
        lines += ['', '> Built from synthetic events. It shows how the pipeline behaves, not a real compromise.']
    if not detail['alerts']:
        lines += ['', 'Recorded before evidence tracking was added, so it has no linked alerts or timeline.',
                  '', _one_line(incident.get('description'))]
        return '\n'.join(lines) + '\n'

    lines += ['', '## Entities', '']
    lines += [f'- **{_one_line(field)}:** {", ".join(_one_line(v) for v in values)}'
              for field, values in (incident.get('entities') or {}).items()]
    lines += ['', '## Potential impact', '']
    lines += [f"- **{item['tactic']}:** {item['impact']}" for item in detail['potential_impact']] or ['- No MITRE tactic is mapped to these detections.']
    lines += ['', '## Attack timeline', '']
    for entry in detail['timeline']:
        count = f" (x{entry['count']})" if entry['count'] > 1 else ''
        rules = f" [{', '.join(entry['rule_ids'])}]" if entry['rule_ids'] else ''
        lines.append(f"- {_one_line(entry['timestamp'])}: {_one_line(entry['summary'])}{count}{rules}")
    lines += ['', '## Detections and why they fired', '']
    for alert in detail['alerts']:
        lines.append(f"- **{_one_line(alert['rule_id'])} {_one_line(alert['rule_name'])}** "
                     f"({_one_line(alert['severity'])}, {_one_line(alert['confidence'])}% confidence, "
                     f"{_one_line(alert['event_count'])} events): {_one_line(alert['explanation'])}")
    lines += ['', '## How this was scored', '']
    lines += [f"- **{_one_line(c['factor']).replace('_', ' ')}** ({_one_line(c['points'])} points): {_one_line(c['reason'])}"
              for c in risk.get('components', [])]
    if risk:
        lines.append(f"- **Result:** {_one_line(risk.get('subtotal'))} points, capped at 100, gives {_one_line(risk.get('value'))}. {_one_line(risk.get('note'))}")
    lines += ['', '## Response actions (simulation only: no real system is changed)', '']
    for action in detail['response_actions']:
        decided = f", decided by {_one_line(action['decided_by'])}" if action.get('decided_by') else ''
        lines.append(f"- **{_one_line(action['status'])}:** {_one_line(action['label'])} on `{_one_line(action['target'])}`{decided}")
    if not detail['response_actions']:
        lines.append('- No response is recommended for these detections.')
    lines += ['', '## Audit trail', '']
    lines += [f"- {_one_line(entry['timestamp'])}: {_one_line(entry['actor'])}, {_one_line(entry['action'])}"
              for entry in detail['audit_log']] or ['- No entries.']
    if detail['related_events_truncated']:
        lines += ['', f"Timeline covers the first {len(detail['related_events'])} of {detail['related_events_total']} related events."]
    return '\n'.join(lines) + '\n'
