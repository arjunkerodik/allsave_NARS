import logging

from models import add_audit_entry, get_alert_event_ids, get_all_iocs, insert_automation_step, insert_notification, update_alert, update_incident
from utils.normalizer import is_internal_ip
from utils.response_engine import PLAYBOOK
from utils.risk_engine import tactics_in_order

logger = logging.getLogger(__name__)

MAX_EVIDENCE_IDS = 200

# Everything here only reads stored data and writes SOC records. A step that could affect a
# system (block, disable, terminate, isolate) is a response action, and never runs without an analyst.


def _entity_values(entities):
    return {field: values for field, values in (entities or {}).items() if field != 'simulation_run'}


def _enrich(subject, config):
    entities = _entity_values(subject['entities'])
    addresses = entities.get('src_ip', []) + entities.get('dst_ip', [])
    indicators = {ioc['value'] for ioc in get_all_iocs()}
    assets = config.get('asset_criticality', {})
    known = [value for values in entities.values() for value in values if value in assets]
    return {
        'external_addresses': sorted({ip for ip in addresses if is_internal_ip(ip) is False}),
        'internal_addresses': sorted({ip for ip in addresses if is_internal_ip(ip)}),
        'known_indicators': sorted({value for values in entities.values() for value in values if value in indicators}),
        'known_assets': sorted(set(known)),
    }


def _monitoring(subject, config):
    return {'watched_entities': _entity_values(subject['entities']), 'note': 'Recorded for analyst follow-up. No sensor or system was changed.'}


def _duplicates(subject, config):
    alerts = subject['alerts']
    return {'alerts': len(alerts), 'distinct_rules': len({a['rule_id'] for a in alerts}), 'events_merged': sum(a.get('event_count') or 0 for a in alerts)}


def _evidence(subject, config):
    ids = sorted({log_id for alert in subject['alerts'] for log_id in get_alert_event_ids(alert['id'])})
    return {'event_count': len(ids), 'event_log_ids': ids[:MAX_EVIDENCE_IDS]}


def _task(subject, config):
    return {'task': f"Review {subject['label']}", 'priority': subject['priority']}


STEPS = {
    'enrich': ('Enriched with address scope, indicators and assets', _enrich),
    'update_monitoring_record': ('Updated the monitoring record', _monitoring),
    'group_duplicates': ('Grouped duplicate alerts', _duplicates),
    'collect_evidence': ('Collected the supporting evidence', _evidence),
    'create_investigation_task': ('Created an investigation task', _task),
}


def _run_steps(key, incident_id, tier, policy, subject, config):
    applied = []
    for step in policy['automatic']:
        title, operation = STEPS[step]
        detail = {'title': title, **operation(subject, config)}
        if insert_automation_step(key, incident_id, tier, step, detail):
            add_audit_entry('automation', 'automation_applied', subject['type'], subject['id'], incident_id,
                            {'step': step, 'risk_level': tier, 'title': title})
            applied.append(step)
    return applied


def _tags(subject, tier, policy):
    tags = [f'risk:{tier.lower()}', f"priority:{policy['priority'].lower()}"]
    tags += [f"tactic:{tactic.lower().replace(' ', '-')}" for tactic in tactics_in_order(subject['alerts'])]
    if any(a.get('detection_type') == 'IOC' for a in subject['alerts']):
        tags.append('threat-intel-match')
    if any(a.get('detection_type') == 'UEBA' for a in subject['alerts']):
        tags.append('behavioral-anomaly')
    return tags


def apply_incident_policy(incident, alerts, actions, config, policies=None):
    """Run the automatic steps for an incident's risk tier. Each runs once per tier, so an
    escalation adds the higher tier's steps. Returns a new notification, if there is one."""
    policies = policies or PLAYBOOK['risk_policy']
    tier = incident['risk_level']
    policy = policies[tier]
    subject = {'type': 'incident', 'id': incident['id'], 'entities': incident.get('entities'), 'alerts': alerts,
               'label': incident.get('incident_uid') or f"incident {incident['id']}", 'priority': policy['priority']}
    _run_steps(f"incident:{incident['id']}", incident['id'], tier, policy, subject, config)

    waiting = sum(1 for action in actions if action['status'] in ('PENDING', 'NEEDS_INVESTIGATION'))
    disruptive = sum(1 for action in actions if action['disruptive'] and action['status'] in ('PENDING', 'NEEDS_INVESTIGATION'))
    update_incident(incident['id'], {
        'priority': policy['priority'],
        'tags': _tags(subject, tier, policy),
        'automation_status': policy['summary'],
        'response_status': 'AWAITING_APPROVAL' if waiting else ('NONE' if not actions else 'AUTOMATED' if policy.get('response') == 'automatic' else 'COMPLETE'),
        'disruptive_pending': disruptive,
    })

    if policy.get('notify'):
        message = f"{policy['notify']}: {subject['label']} is {tier} risk ({incident['risk_score']}/100). {incident['title']}"
        if insert_notification(incident['id'], tier, message):
            add_audit_entry('automation', 'analyst_notified', 'incident', incident['id'], incident['id'],
                            {'risk_level': tier, 'message': message})
            return {'incident_id': incident['id'], 'level': tier, 'message': message}
    return None


def apply_alert_policy(alert, risk_level, config, policies=None):
    """An alert too weak to open an incident still gets its tier's safe handling"""
    policies = policies or PLAYBOOK['risk_policy']
    policy = policies[risk_level]
    subject = {'type': 'alert', 'id': alert['id'], 'entities': alert.get('entities'), 'alerts': [alert],
               'label': alert['alert_uid'], 'priority': policy['priority']}
    _run_steps(f"alert:{alert['id']}", None, risk_level, policy, subject, config)
    update_alert(alert['id'], {'tags': _tags(subject, risk_level, policy), 'automation_status': policy['summary']})
