from datetime import datetime

import re

from models import (
    get_alert_batch_event_ids, get_batch_alerts, get_batch_anomalies, get_batch_event_summary, get_ground_truth,
    get_logs_by_ids, get_ml_predictions,
)

POSITIVE_LABELS = ('malicious', 'suspicious')
BENIGN_PREDICTION = 'BENIGN'


def _ratio(top, bottom):
    return round(top / bottom, 4) if bottom else None


def _rates(tp, fp, fn, tn=None):
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
    result = {'true_positives': tp, 'false_positives': fp, 'false_negatives': fn, 'precision': precision, 'recall': recall, 'f1': f1}
    if tn is not None:
        result.update(true_negatives=tn, false_positive_rate=_ratio(fp, fp + tn))
    return result


def _seconds_between(start, end):
    try:
        return round((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds(), 3)
    except (TypeError, ValueError):
        return None


def evaluate_batch(batch_id, expected_rules=None):
    """Compare what the pipeline produced for a batch with its ground truth.

    Risk scores are never used here: they are a priority, not a prediction. Without ground
    truth this reports descriptive counts only. Measured on synthetic data, these numbers show
    how the pipeline behaves on these scenarios, not how it would perform on real attacks.
    """
    events = get_batch_event_summary(batch_id)
    alerts = get_batch_alerts(batch_id)
    truth = get_ground_truth(batch_id)
    detected = sum(1 for event in events if event['detected'])
    result = {
        'has_ground_truth': bool(truth),
        'events': len(events),
        'detected_events': detected,
        'alerts': len(alerts),
        'incidents': len({a['incident_id'] for a in alerts if a['incident_id']}),
    }
    if not truth:
        result['note'] = 'This data has no ground truth labels, so these are descriptive counts, not performance metrics.'
        return result

    positive = {event_id for event_id, row in truth.items() if row['label'] in POSITIVE_LABELS}

    # Event level: was each event cited by any alert?
    tp = fp = fn = tn = 0
    for event in events:
        if event['event_id'] in positive:
            tp, fn = (tp + 1, fn) if event['detected'] else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if event['detected'] else (fp, tn + 1)
    result['event_level'] = _rates(tp, fp, fn, tn)
    result['labels'] = {label: sum(1 for row in truth.values() if row['label'] == label) for label in ('normal', 'suspicious', 'malicious')}

    # Alert level: does each alert cite a truly bad event? Missed means an expected rule never fired.
    cited = {alert['id']: set(get_alert_batch_event_ids(alert['id'])) for alert in alerts}
    true_alerts = [a for a in alerts if cited[a['id']] & positive]
    fired = {a['rule_id'] for a in alerts}
    missed = sorted(set(expected_rules) - fired) if expected_rules is not None else None
    result['alert_level'] = _rates(len(true_alerts), len(alerts) - len(true_alerts), len(missed) if missed is not None else 0)
    if missed is None:
        result['alert_level']['recall'] = result['alert_level']['f1'] = None
    result['missed_rules'] = missed
    result['unexpected_rules'] = sorted(fired - set(expected_rules)) if expected_rules is not None else None

    # Incident level: is each incident built on truly bad events? Missed means an attack with no incident.
    incidents = {}
    for alert in alerts:
        if alert['incident_id']:
            incidents.setdefault(alert['incident_id'], set()).update(cited[alert['id']])
    true_incidents = sum(1 for ids in incidents.values() if ids & positive)
    result['incident_level'] = _rates(true_incidents, len(incidents) - true_incidents, 1 if positive and not true_incidents else 0)

    # The network model, where it ran. Its classes are compared by name, whatever the punctuation.
    predictions = get_ml_predictions(batch_id)
    if predictions:
        def name(text):
            return re.sub(r'[^a-z0-9]', '', str(text or '').lower())
        compared = [(truth[event_id], row) for event_id, row in predictions.items() if event_id in truth]
        tp_ml = sum(1 for label, row in compared if label['label'] in POSITIVE_LABELS and row['predicted_label'] != BENIGN_PREDICTION)
        fp_ml = sum(1 for label, row in compared if label['label'] not in POSITIVE_LABELS and row['predicted_label'] != BENIGN_PREDICTION)
        fn_ml = sum(1 for label, row in compared if label['label'] in POSITIVE_LABELS and row['predicted_label'] == BENIGN_PREDICTION)
        tn_ml = sum(1 for label, row in compared if label['label'] not in POSITIVE_LABELS and row['predicted_label'] == BENIGN_PREDICTION)
        named = [(label, row) for label, row in compared if label['label'] in POSITIVE_LABELS and label.get('attack_type')]
        result['ml_level'] = _rates(tp_ml, fp_ml, fn_ml, tn_ml)
        result['ml_level']['flows_compared'] = len(compared)
        result['ml_level']['attack_class_matches'] = sum(1 for label, row in named if name(label['attack_type']) == name(row['predicted_label']))
        result['ml_level']['attack_flows_with_a_named_class'] = len(named)

    # The anomaly model at event level: is an event in a window it flagged truly bad?
    anomalies = get_batch_anomalies(batch_id)
    if anomalies:
        flagged = {row['event_id'] for row in get_logs_by_ids([log_id for anomaly in anomalies for log_id in (anomaly.get('event_log_ids') or [])])}
        event_ids = {event['event_id'] for event in events}
        tp_a = len(flagged & positive)
        fp_a = len(flagged - positive)
        result['anomaly_level'] = _rates(tp_a, fp_a, len((positive & event_ids) - flagged), len(event_ids - positive - flagged))

    # Detection latency: from the first truly bad event reaching the platform to the first alert about one
    arrivals = [e['ingestion_timestamp'] for e in events if e['event_id'] in positive and e['ingestion_timestamp']]
    alert_times = [a['created_at'] for a in true_alerts if a.get('created_at')]
    result['detection_latency_seconds'] = _seconds_between(min(arrivals), min(alert_times)) if arrivals and alert_times else None
    return result
