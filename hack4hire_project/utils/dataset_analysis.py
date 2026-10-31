import json

from models import (
    get_alert_event_ids, get_batch_alerts, get_batch_anomalies, get_batch_counts, get_engine_runs, get_engine_state, get_ml_prediction_counts,
    get_ml_flagged_log_ids,
)
from utils.nids_engine import BENIGN
from utils.risk_engine import load_scoring_config

NO_THREAT_STATEMENT = ('No suspicious activity was detected by the enabled detection engines during this analysis. '
                       'This does not guarantee that the environment is completely free of threats.')

ENGINE_NAMES = {
    'IOC': 'IOC enrichment',
    'IOA': 'IOA behavior rules',
    'NIDS': 'Supervised ML (saved network model)',
    'UEBA': 'UEBA baselines',
    'ANOMALY': 'Anomaly model',
}
_SKIP_REASONS = {
    'IOC': 'No event had both a timestamp and an IP address, domain, URL or file hash to check.',
    'IOA': 'No event had a usable timestamp, and every behavior rule works over a time window.',
    'NIDS': 'This data has no records with all 78 CIC-IDS2017 flow features the model needs. Logs of other kinds are never fed to it.',
    'UEBA': 'No event was a successful login or an outbound transfer with a timestamp, which is what the baselines compare.',
    'ANOMALY': 'No event had a timestamp and a source or host to group by.',
}


def engine_statuses(batch_id):
    """What each engine really did for this batch, read back from what it recorded as it ran"""
    runs = {run['engine']: run for run in get_engine_runs(batch_id)}
    statuses = []
    for engine, name in ENGINE_NAMES.items():
        run = runs.get(engine)
        if not run:
            statuses.append({'engine': engine, 'name': name, 'status': 'NOT_RUN', 'evaluated': 0, 'findings': 0, 'seen': 0,
                             'reason': 'This engine has no record of running on this data.'})
            continue
        detail = run.get('detail') or {}
        applicable = run['applicable'] or 0
        if run['failures']:
            status, reason = 'FAILED', f"The engine failed on this data: {', '.join(detail.get('failures') or ['internal error'])}."
        elif detail.get('reason'):
            status, reason = 'SKIPPED', detail['reason']
        elif not applicable:
            status, reason = 'SKIPPED', _SKIP_REASONS[engine]
        else:
            status = 'COMPLETED'
            not_evaluated = (run['events_seen'] or 0) - applicable
            reason = f'{not_evaluated:,} of {run["events_seen"]:,} events did not apply to this engine.' if not_evaluated else None
        statuses.append({'engine': engine, 'name': name, 'status': status, 'seen': run['events_seen'] or 0, 'evaluated': applicable if status != 'SKIPPED' else 0,
                         'findings': run['findings'] or 0, 'reason': reason, 'detail': detail})
    return statuses


def _confirmed_threshold():
    return load_scoring_config().get('classification', {}).get('confirmed_min_confidence', 70)


def is_confirmed(alert, minimum):
    """Rule and indicator detections with strong enough evidence. A statistical or model signal
    alone never counts: it stays suspicious until something else supports it."""
    return alert['detection_type'] in ('IOA', 'IOC') and alert['confidence'] >= minimum and alert['severity'] != 'LOW'


def _engine_by_name(engines, name):
    return next(engine for engine in engines if engine['engine'] == name)


def analyze_batch(batch_id, summary=None, failure=None):
    """Classify what happened to a dataset or run, and reach an honest verdict about it.

    Everything comes from stored results and from what the engines recorded. If an engine failed
    or could evaluate nothing, the verdict is ANALYSIS_INCOMPLETE, never a clean result.
    """
    summary = summary or {}
    engines = engine_statuses(batch_id)
    alerts = get_batch_alerts(batch_id)
    anomalies = get_batch_anomalies(batch_id)
    predictions = get_ml_prediction_counts(batch_id)
    counts = get_batch_counts(batch_id)
    minimum = _confirmed_threshold()

    confirmed_alerts = [alert for alert in alerts if is_confirmed(alert, minimum)]
    suspicious_alerts = [alert for alert in alerts if not is_confirmed(alert, minimum)]
    confirmed_events = {log_id for alert in confirmed_alerts for log_id in get_alert_event_ids(alert['id'])}
    suspicious_events = {log_id for alert in suspicious_alerts for log_id in get_alert_event_ids(alert['id'])}
    suspicious_events |= {log_id for anomaly in anomalies for log_id in (anomaly.get('event_log_ids') or [])}
    suspicious_events |= set(get_ml_flagged_log_ids(batch_id))
    suspicious_events -= confirmed_events

    confirmed_incidents = sorted({alert['incident_id'] for alert in confirmed_alerts if alert['incident_id']})
    suspicious_incidents = sorted({alert['incident_id'] for alert in suspicious_alerts if alert['incident_id']} - set(confirmed_incidents))

    flagged_predictions = sum(count for label, count in predictions.items() if label != BENIGN)
    classified = sum(predictions.values())
    not_evaluated = max(0, counts['without_timestamp'] - counts['without_timestamp_classified'])
    evaluated_events = max(0, counts['total'] - not_evaluated)
    benign_events = max(0, evaluated_events - len(confirmed_events) - len(suspicious_events))

    limitations = []
    for engine in engines:
        if engine['status'] in ('SKIPPED', 'NOT_RUN'):
            limitations.append(f"{engine['name']}: {engine['reason']}")
    if not_evaluated:
        limitations.append(f'{not_evaluated:,} event(s) could not be evaluated by any engine, because they have no timestamp and could not be classified by the network model.')
    for rule_id, count in json.loads(get_engine_state(f'alerts_left_out:{batch_id}', '{}')).items():
        limitations.append(f'{rule_id} fired {count:,} more time(s) than are stored here. The first alerts of each rule are kept, so that a noisy file does not bury the rest.')

    data_quality = {
        'rejected_records': summary.get('invalid_records', 0),
        'duplicate_records': summary.get('skipped_duplicates', 0),
        'malformed_records': summary.get('malformed_records', 0),
        'invalid_timestamps': summary.get('invalid_timestamps', 0),
        'missing_timestamps': summary.get('missing_timestamps', 0),
        'flows_without_timestamp': summary.get('flows_without_timestamp', 0),
        'missing_values': summary.get('missing_values', {}),
        'unsupported_fields': summary.get('unsupported_fields', []),
        'warnings': summary.get('warnings', []),
    }

    failed_engines = [engine for engine in engines if engine['status'] in ('FAILED', 'NOT_RUN')]
    ran_engines = [engine for engine in engines if engine['status'] == 'COMPLETED']
    reasons = []
    if failure:
        reasons.append(failure)
    for engine in failed_engines:
        reasons.append(f"{engine['name']}: {engine['reason']}")
    if counts['total'] and not ran_engines and not failure:
        reasons.append('No detection engine could evaluate these records, so nothing can be said about them.')
    if not counts['total'] and not failure:
        reasons.append('No events were stored for this analysis.')

    if reasons:
        status, headline = 'ANALYSIS_INCOMPLETE', 'ANALYSIS INCOMPLETE'
        statement = 'This analysis could not evaluate everything it needed to, so it is not a clean result. Any findings below are partial.'
    elif confirmed_alerts:
        status, headline = 'THREATS_DETECTED', 'THREATS DETECTED'
        statement = f'{len(confirmed_alerts)} detection(s) have strong supporting evidence and need investigation.'
    elif suspicious_alerts or anomalies or flagged_predictions:
        status, headline = 'SUSPICIOUS_ACTIVITY', 'SUSPICIOUS ACTIVITY FOUND'
        statement = 'Nothing here has strong enough evidence to count as a confirmed detection, but some of it needs an analyst to look at it.'
    else:
        status, headline = 'NO_THREATS_DETECTED', 'NO THREATS DETECTED'
        statement = NO_THREAT_STATEMENT

    users, hosts, mitre, severity, remediation = set(), set(), {}, {}, {}
    for alert in alerts:
        entities = alert.get('entities') or {}
        users.update(entities.get('user', []))
        hosts.update(entities.get('hostname', []))
        severity[alert['severity']] = severity.get(alert['severity'], 0) + 1
        for technique in alert.get('mitre') or []:
            mitre.setdefault(technique.get('id'), {'id': technique.get('id'), 'name': technique.get('name'), 'tactic': technique.get('tactic')})
        if alert.get('recommendations'):
            remediation.setdefault(alert['rule_id'], {'rule_id': alert['rule_id'], 'rule_name': alert['rule_name'], 'steps': alert['recommendations']})

    return {
        'verdict': {'status': status, 'headline': headline, 'statement': statement, 'reasons': reasons},
        'engines': engines,
        'engines_executed': [engine['name'] for engine in ran_engines],
        'engines_skipped': [{'name': engine['name'], 'status': engine['status'], 'reason': engine['reason']} for engine in engines if engine['status'] != 'COMPLETED'],
        'classification': {
            'confirmed_detections': {'alerts': len(confirmed_alerts), 'events': len(confirmed_events), 'incidents': len(confirmed_incidents)},
            'suspicious_activity': {'alerts': len(suspicious_alerts), 'events': len(suspicious_events), 'incidents': len(suspicious_incidents),
                                    'anomaly_windows': len(anomalies), 'flows_classified_as_attacks': flagged_predictions},
            'benign_activity': {'events': benign_events, 'note': 'These events triggered no applicable detection condition. That is not proof they are safe.'},
            'data_quality_issues': data_quality,
            'detection_limitations': limitations,
        },
        'counts': {'stored_events': counts['total'], 'evaluated_events': evaluated_events, 'not_evaluated_events': not_evaluated,
                   'without_timestamp': counts['without_timestamp'], 'alerts': len(alerts)},
        'ioc': {'matches': sum(1 for alert in alerts if alert['detection_type'] == 'IOC'), 'events_checked': _engine_by_name(engines, 'IOC')['evaluated'],
                'note': None if any(alert['detection_type'] == 'IOC' for alert in alerts) else 'No known indicator was matched. This does not mean these events are safe: the feed only holds known indicators.'},
        'ioa': {'matches': sum(1 for alert in alerts if alert['detection_type'] == 'IOA')},
        'ueba': {'matches': sum(1 for alert in alerts if alert['detection_type'] == 'UEBA')},
        'ml': {'flows_classified': classified, 'distribution': predictions, 'flagged_as_attacks': flagged_predictions,
               'model_version': (_engine_by_name(engines, 'NIDS').get('detail') or {}).get('model_version'), 'calibrated': False,
               'confidence': None, 'note': 'Predictions from one uncalibrated model, not validated here. They are suspicious until something else supports them.'},
        'anomalies': {'windows': len(anomalies), 'findings': anomalies,
                      'note': 'Statistically unusual activity, not confirmed attacks.'},
        'affected': {'users': sorted(users), 'hosts': sorted(hosts)},
        'severity_distribution': severity,
        'mitre': sorted(mitre.values(), key=lambda t: t['id'] or ''),
        'remediation': sorted(remediation.values(), key=lambda r: r['rule_id']),
    }
