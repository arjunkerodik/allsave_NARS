import csv
import io
import json
import os
import textwrap
import uuid
from datetime import datetime, timezone

from models import (
    get_alert_batch_event_ids, get_batch_alerts, get_dataset, get_report, get_simulation_outcome, insert_report,
)
from utils.dataset_analysis import analyze_batch, is_confirmed, _confirmed_threshold
from utils.evaluation import evaluate_batch
from utils.investigation import _one_line, get_incident_detail
from utils.simulator import SCENARIOS

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
LIMITATIONS = [
    'Detection combines behavior rules, threat intelligence matches, statistical baselines and two models. None of them proves an attack happened, and none proves that one did not.',
    'The saved network model runs only on flow data with its 78 CIC-IDS2017 features. It has not been validated here, no preprocessing pipeline was saved with it, and its output is uncalibrated, so no accuracy or prediction confidence is claimed.',
    'The anomaly model was trained on synthetic normal activity, and does not run on live telemetry. Its findings are statistical anomalies, not confirmed attacks.',
    'Threat intelligence only covers known indicators, and the bundled feed is synthetic. No match does not mean an event is safe.',
    'Performance metrics compare results with labels on synthetic or supplied data. They do not predict performance on real attacks.',
    'The synthetic scenarios and the detection rules were written by the same team, so scenario results show the pipeline works as designed.',
    'Behavioral checks need history. An entity with too little history is not judged.',
    'Window-based rules cite every matching event in their window, so a normal event inside an attack window counts as an event-level false positive.',
    'Risk is an investigation priority, not the probability that an attack is real.',
    'Historical analysis is read-only. Every response action is a recommendation that needs an analyst, and runs only in simulation. No firewall, account, host or process is changed.',
    'Analyst names are self-reported: there are no user accounts.',
]
MAX_REPORT_SAMPLES = 3
MAX_EVENT_IDS = 10


class ReportError(ValueError):
    """The subject of a report does not exist. The message is safe to show to the client."""


def _rule_catalog():
    """What each rule looks for, from the rule files themselves"""
    catalog = {}
    for name in ('detection_rules.json', 'ueba_rules.json', 'ml_rules.json'):
        with open(os.path.join(CONFIG_DIR, name), encoding='utf-8') as handle:
            for rule in json.load(handle)['rules']:
                catalog[rule['id']] = rule
    return catalog


def _subject(subject_type, subject_id):
    if subject_type == 'simulation':
        run = get_simulation_outcome(subject_id)
        if not run:
            raise ReportError('Simulation run not found')
        definition = SCENARIOS.get(run['scenario'], {})
        failure = None
        if run['status'] != 'COMPLETED':
            failure = f"The run ended as {run['status']}." + (f" {run['error']}" if run['error'] else '')
        return {
            'name': definition.get('name', run['scenario']),
            'kind': 'Simulation', 'status': run['status'], 'file': None, 'dataset_type': 'Synthetic simulation run',
            'started_at': run['started_at'], 'completed_at': run['completed_at'],
            'total': run['event_count'], 'processed': run['processed_count'], 'failed': run['failed_count'],
            'expected_rules': run['expected_rules'], 'synthetic': True, 'summary': {}, 'failure': failure,
            'detail': {'seed': run['seed'], 'intensity': run['intensity'], 'speed': run['speed'], 'background_events': run['background_events']},
        }
    if subject_type == 'dataset':
        dataset = get_dataset(subject_id)
        if not dataset:
            raise ReportError('Dataset not found')
        summary = dataset.get('summary') or {}
        failure = dataset['error'] if dataset['status'] in ('FAILED', 'INTERRUPTED', 'VALIDATION_FAILED') else None
        return {
            'name': dataset['name'], 'kind': f"Log analysis ({dataset['kind']})", 'status': dataset['status'], 'file': dataset['name'],
            'dataset_type': summary.get('dataset_type', 'Not identified'),
            'started_at': dataset['created_at'], 'completed_at': dataset['completed_at'],
            'total': summary.get('total_rows', dataset['total_events']), 'processed': dataset['processed_events'],
            'failed': summary.get('invalid_records', 0),
            'expected_rules': dataset.get('expected_rules'), 'synthetic': dataset['kind'] == 'generated', 'summary': summary, 'failure': failure,
            'detail': {**(dataset.get('params') or {}), 'validation': summary},
        }
    raise ReportError('subject_type must be simulation or dataset')


def _incident_section(detail):
    incident = detail['incident']
    entities = incident.get('entities') or {}
    risk = (incident.get('score_breakdown') or {}).get('risk') or {}
    return {
        'id': incident['id'],
        'uid': incident.get('incident_uid'),
        'title': incident['title'],
        'status': incident['status'],
        'priority': incident.get('priority'),
        'severity': incident['severity'],
        'confidence': incident.get('confidence'),
        'risk_score': incident.get('risk_score'),
        'risk_level': incident.get('risk_level'),
        'automation_status': incident.get('automation_status'),
        'hosts': entities.get('hostname', []),
        'users': entities.get('user', []),
        'source_addresses': entities.get('src_ip', []),
        'mitre': sorted({f"{t.get('id')} {t.get('name')} ({t.get('tactic')})" for t in (incident.get('mitre') or [])}),
        'related_alerts': [alert['rule_id'] for alert in detail['alerts']],
        'risk_reasons': [{'factor': c['factor'], 'points': c['points'], 'reason': c['reason']} for c in risk.get('components', []) if c['points']],
        'timeline': [{'timestamp': e['timestamp'], 'summary': e['summary'], 'count': e['count'], 'rules': e['rule_ids']} for e in detail['timeline']],
        'actions': [{'status': a['status'], 'label': a['label'], 'target': a['target'], 'disruptive': bool(a['disruptive']),
                     'expected_impact': a.get('expected_impact'), 'decided_by': a.get('decided_by'), 'decided_at': a.get('decided_at'),
                     'decision_reason': a.get('decision_reason'), 'executed_at': a.get('executed_at')} for a in detail['response_actions']],
    }


def _executive_summary(subject, analysis, alerts, incidents, recommended):
    top = max(incidents, key=lambda i: i['risk_score'] or 0, default=None)
    text = (f"{subject['name']}: {analysis['counts']['stored_events']} of {subject['total'] or 0} records were processed, producing "
            f"{len(alerts)} alert(s) and {len(incidents)} incident(s). ")
    if top:
        text += f"The highest priority is {top['uid']}, {top['title']}, at {top['risk_score']}/100 ({top['risk_level']}). "
    else:
        text += 'No incident was created. '
    text += (f"{sum(1 for a in recommended if a['status'] == 'PENDING')} recommended action(s) are waiting for an analyst. "
             'No action has changed a real system.')
    if subject['synthetic']:
        text += ' All of this data is synthetic.'
    return text


def build_report(subject_type, subject_id):
    """Assemble a report from stored results only, and save it. Returns the stored report."""
    subject = _subject(subject_type, subject_id)
    alerts = get_batch_alerts(subject_id)
    metrics = evaluate_batch(subject_id, subject.get('expected_rules'))
    analysis = analyze_batch(subject_id, subject['summary'], failure=subject['failure'])
    catalog = _rule_catalog()
    minimum = _confirmed_threshold()
    incident_ids = sorted({a['incident_id'] for a in alerts if a['incident_id']})
    details = [get_incident_detail(incident_id) for incident_id in incident_ids]
    incidents = [_incident_section(detail) for detail in details if detail]

    distribution = {level: 0 for level in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    for incident in incidents:
        if incident['risk_level'] in distribution:
            distribution[incident['risk_level']] += 1
    alert_distribution = {level: 0 for level in distribution}
    for alert in alerts:
        if alert.get('risk_level') in alert_distribution:
            alert_distribution[alert['risk_level']] += 1

    tactics = sorted({t['tactic'] for a in alerts for t in (a.get('mitre') or []) if t.get('tactic')})

    def finding(alert):
        rule = catalog.get(alert['rule_id'], {})
        evidence = alert.get('evidence') or {}
        return {'rule_id': alert['rule_id'], 'rule_name': alert['rule_name'], 'description': rule.get('description'),
                'severity': alert['severity'], 'confidence': alert['confidence'], 'risk_score': alert.get('risk_score'), 'risk_level': alert.get('risk_level'),
                'classification': 'Confirmed detection' if is_confirmed(alert, minimum) else 'Suspicious activity',
                'events': alert['event_count'], 'explanation': alert['explanation'], 'first_seen': alert.get('first_seen'), 'last_seen': alert.get('last_seen'),
                'conditions': evidence.get('rule_logic'), 'mitre': alert.get('mitre') or [],
                'supporting_event_ids': get_alert_batch_event_ids(alert['id'])[:MAX_EVENT_IDS],
                'matched_indicator': evidence.get('matched_indicator'), 'indicator_type': evidence.get('indicator_type'), 'matched_field': evidence.get('matched_field'),
                'feed_source': evidence.get('feed_source'), 'feed_description': evidence.get('feed_description'),
                'predicted_class': evidence.get('predicted_class'), 'model_version': evidence.get('model_version'),
                'samples': [s['summary'] for s in evidence.get('sample_events', [])]}
    by_type = {kind: [finding(a) for a in alerts if a['detection_type'] == kind] for kind in ('IOA', 'IOC', 'UEBA', 'ML')}

    decisions = [{'incident': i['uid'], **action} for i in incidents for action in i['actions'] if action['decided_by']]
    recommended = [{'incident': i['uid'], **action} for i in incidents for action in i['actions']]

    report = {
        'report_id': f'RPT-{uuid.uuid4().hex[:10].upper()}',
        'subject_type': subject_type,
        'subject_id': subject_id,
        'title': f"ALLSAFE Security Analysis Report: {subject['name']}",
        'generated_at': datetime.now(timezone.utc).isoformat(),
    }
    report['content'] = {
        'analysis_id': subject_id,
        'dataset_filename': subject['file'],
        'dataset_type': subject['dataset_type'],
        'overall_assessment': analysis['verdict'],
        'executive_summary': _executive_summary(subject, analysis, alerts, incidents, recommended),
        'threat_overview': {'attack_categories': tactics, 'rules_fired': sorted({a['rule_id'] for a in alerts})},
        'processing_summary': {
            'kind': subject['kind'], 'status': subject['status'], 'started_at': subject['started_at'], 'completed_at': subject['completed_at'],
            'total': subject['total'], 'processed': analysis['counts']['stored_events'], 'failed': subject['failed'],
            'duplicates': analysis['classification']['data_quality_issues']['duplicate_records'],
        },
        'data_quality': analysis['classification']['data_quality_issues'],
        'detection_engines': analysis['engines'],
        'engines_executed': analysis['engines_executed'],
        'engines_skipped': analysis['engines_skipped'],
        'classification': analysis['classification'],
        'subject_detail': subject['detail'],
        'detection_results': {'alerts': len(alerts), 'incidents': len(incidents), 'alert_risk_distribution': alert_distribution,
                              'incident_risk_distribution': distribution, 'severity_distribution': analysis['severity_distribution'],
                              'ioa_matches': by_type['IOA'], 'ioc_matches': by_type['IOC'], 'ueba_findings': by_type['UEBA'], 'ml_findings': by_type['ML'],
                              'ioc_note': analysis['ioc']['note'], 'ioc_events_checked': analysis['ioc']['events_checked']},
        'ml_classification': analysis['ml'],
        'anomaly_results': analysis['anomalies'],
        'affected': analysis['affected'],
        'mitre': analysis['mitre'],
        'incidents': incidents,
        'remediation': analysis['remediation'],
        'recommended_actions': recommended,
        'analyst_decisions': decisions,
        'model_performance': metrics,
        'limitations': LIMITATIONS,
    }
    insert_report(report)
    return report


def load_report(report_id):
    report = get_report(report_id)
    if not report:
        raise ReportError('Report not found')
    return report


def _metric_lines(metrics):
    if not metrics.get('has_ground_truth'):
        return [metrics.get('note', 'No ground truth.')]
    lines = []
    for name, title in (('event_level', 'Event level'), ('alert_level', 'Alert level'), ('incident_level', 'Incident level'),
                        ('ml_level', 'Network model, flow level'), ('anomaly_level', 'Anomaly model, event level')):
        level = metrics.get(name)
        if not level:
            continue
        parts = [f"TP {level['true_positives']}", f"FP {level['false_positives']}", f"FN {level['false_negatives']}"]
        if 'true_negatives' in level:
            parts.append(f"TN {level['true_negatives']}")
        parts += [f"precision {_show(level['precision'])}", f"recall {_show(level['recall'])}", f"F1 {_show(level['f1'])}"]
        if 'false_positive_rate' in level:
            parts.append(f"false-positive rate {_show(level['false_positive_rate'])}")
        lines.append(f"{title}: {', '.join(parts)}")
    latency = metrics.get('detection_latency_seconds')
    lines.append('Detection latency: not measurable, because no attack was detected' if latency is None else f'Detection latency: {latency} seconds')
    if metrics.get('missed_rules') is not None:
        lines.append(f"Expected rules that did not fire: {', '.join(metrics['missed_rules']) or 'none'}")
        lines.append(f"Rules that fired unexpectedly: {', '.join(metrics['unexpected_rules']) or 'none'}")
    lines.append('These numbers come from labelled data, and risk scores play no part in them.')
    return lines


def _show(value):
    return 'not measurable' if value is None else value


def _distribution(values):
    return ', '.join(f'{level} {count}' for level, count in values.items()) or 'none'


def _finding_lines(finding):
    techniques = ', '.join(f"{t.get('id')} {t.get('name')}" for t in finding['mitre']) or 'not mapped'
    lines = [f"- **{_one_line(finding['rule_id'])} {_one_line(finding['rule_name'])}** ({_one_line(finding['classification'])})",
             f"  - Severity {_one_line(finding['severity'])}, confidence {_one_line(finding['confidence'])}%, risk {_one_line(finding['risk_score'])}/100 ({_one_line(finding['risk_level'])}), {_one_line(finding['events'])} event(s), last seen {_one_line(finding['last_seen'])}"]
    if finding['description']:
        lines.append(f"  - Description: {_one_line(finding['description'])}")
    lines.append(f"  - Why it fired: {_one_line(finding['explanation'])}")
    if finding['conditions']:
        lines.append(f"  - Triggering conditions: {_one_line(json.dumps(finding['conditions'], default=str))[:400]}")
    if finding['matched_indicator']:
        lines.append(f"  - Matched indicator: {_one_line(finding['matched_indicator'])} ({_one_line(finding['indicator_type'])}) in {_one_line(finding['matched_field'])}, "
                     f"from feed {_one_line(finding['feed_source'])}. Context: {_one_line(finding['feed_description'])}")
    if finding['predicted_class']:
        lines.append(f"  - Predicted class: {_one_line(finding['predicted_class'])}, model version {_one_line(finding['model_version'])}, uncalibrated")
    lines.append(f"  - MITRE ATT&CK: {_one_line(techniques)}")
    lines.append(f"  - Supporting event IDs: {_one_line(', '.join(finding['supporting_event_ids']))}")
    lines += [f"  - Evidence: {_one_line(sample)}" for sample in finding.get('samples', [])[:MAX_REPORT_SAMPLES]]
    return lines


def render_markdown(report):
    content = report['content']
    results = content['detection_results']
    processing = content['processing_summary']
    verdict = content['overall_assessment']
    quality = content['data_quality']
    classification = content['classification']
    lines = [f"# {_one_line(report['title'])}", '',
             f"- **Analysis ID:** {_one_line(content['analysis_id'])}", f"- **Report ID:** {report['report_id']}", f"- **Generated:** {report['generated_at']}",
             f"- **Log file:** {_one_line(content['dataset_filename'] or 'Not a file: synthetic simulation run')}",
             f"- **Log type:** {_one_line(content['dataset_type'])}",
             f"- **Analysis started:** {_one_line(processing['started_at'])}", f"- **Analysis completed:** {_one_line(processing['completed_at'])}", '',
             '## Overall security assessment', '', f"**{verdict['headline']}**", '', _one_line(verdict['statement']), '']
    if verdict['reasons']:
        lines += [f'- {_one_line(reason)}' for reason in verdict['reasons']] + ['']
    lines += ['## Executive summary', '', _one_line(content['executive_summary']), '',
              '## Threat overview', '', f"- **Attack categories:** {', '.join(content['threat_overview']['attack_categories']) or 'none'}",
              f"- **Rules fired:** {', '.join(content['threat_overview']['rules_fired']) or 'none'}", '',
              '## Processing summary', '', f"- **Status:** {processing['status']}", f"- **Total uploaded records:** {processing['total']}",
              f"- **Successfully processed records:** {processing['processed']}", f"- **Rejected records:** {processing['failed']}", f"- **Duplicate records:** {processing['duplicates']}", '',
              '## Data quality', '',
              f"- **Malformed records:** {quality['malformed_records']}", f"- **Invalid timestamps:** {quality['invalid_timestamps']}",
              f"- **Missing timestamps:** {quality['missing_timestamps']}", f"- **Flows with no timestamp, kept:** {quality['flows_without_timestamp']}",
              f"- **Missing optional values:** {_distribution(quality['missing_values'])}",
              f"- **Fields with no equivalent in the common schema:** {_one_line(', '.join(str(f) for f in quality['unsupported_fields'])) or 'none'}"]
    lines += [f'- **Warning:** {_one_line(warning)}' for warning in quality['warnings']]
    lines += ['', '## Detection engines', '', '### Executed', '']
    lines += [f"- **{_one_line(engine['name'])}:** evaluated {engine['evaluated']} of {engine['seen']} event(s), {engine['findings']} finding(s)"
              for engine in content['detection_engines'] if engine['status'] == 'COMPLETED'] or ['- None.']
    lines += ['', '### Skipped or failed', '']
    lines += [f"- **{_one_line(engine['name'])} ({engine['status']}):** {_one_line(engine['reason'])}" for engine in content['engines_skipped']] or ['- None.']
    confirmed, suspicious, benign = classification['confirmed_detections'], classification['suspicious_activity'], classification['benign_activity']
    lines += ['', '## Finding classification', '',
              f"- **Confirmed detections:** {confirmed['alerts']} alert(s) over {confirmed['events']} event(s), {confirmed['incidents']} incident(s)",
              f"- **Suspicious activity:** {suspicious['alerts']} alert(s) over {suspicious['events']} event(s), {suspicious['anomaly_windows']} anomaly window(s), {suspicious['flows_classified_as_attacks']} flow(s) classified as attacks",
              f"- **Benign activity (normal events):** {benign['events']} event(s). {_one_line(benign['note'])}",
              f"- **Data quality issues:** {quality['invalid_timestamps'] + quality['malformed_records'] + quality['missing_timestamps']} bad record(s), {quality['duplicate_records']} duplicate(s)",
              f"- **Detection limitations:** {len(classification['detection_limitations'])}"]
    lines += [f'  - {_one_line(limit)}' for limit in classification['detection_limitations']]
    lines += ['', '## Detection results', '', f"- **Alerts:** {results['alerts']}", f"- **Incidents:** {results['incidents']}", '',
              f"### IOC matches ({len(results['ioc_matches'])})", '']
    lines += [f"- {results['ioc_events_checked']} event(s) were checked against the threat intelligence database."]
    if results['ioc_note']:
        lines.append(f"- {_one_line(results['ioc_note'])}")
    for finding in results['ioc_matches']:
        lines += _finding_lines(finding)
    lines += ['', f"### IOA rule matches ({len(results['ioa_matches'])})", '']
    for finding in results['ioa_matches']:
        lines += _finding_lines(finding)
    if not results['ioa_matches']:
        lines.append('- None.')
    lines += ['', f"### UEBA findings ({len(results['ueba_findings'])})", '']
    for finding in results['ueba_findings']:
        lines += _finding_lines(finding)
    if not results['ueba_findings']:
        lines.append('- None.')
    ml = content['ml_classification']
    lines += ['', '## ML classification results', '']
    if ml['flows_classified']:
        lines += [f"- **Flows classified:** {ml['flows_classified']}, by model version {_one_line(ml['model_version'])}",
                  f"- **Distribution:** {_distribution(ml['distribution'])}",
                  f"- **Prediction confidence:** not reported, because the model is not calibrated. {_one_line(ml['note'])}"]
    else:
        lines.append('- The saved network model classified nothing in this data. See the detection engines above for why.')
    for finding in results['ml_findings']:
        lines += _finding_lines(finding)
    anomalies = content['anomaly_results']
    lines += ['', '## Anomaly detection results', '', f"- **Unusual activity windows:** {anomalies['windows']}. {_one_line(anomalies['note'])}"]
    lines += [f"- **{_one_line(item['entity'])}** (strength {item['strength']} of 100, {item['event_count']} event(s)): {_one_line(item['explanation'])}" for item in anomalies['findings'][:25]]
    lines += ['', '## Incident investigation', '']
    if not content['incidents']:
        lines += ['No incident was created.', '']
    for incident in content['incidents']:
        lines += [f"### {_one_line(incident['uid'])}: {_one_line(incident['title'])}", '',
                  f"- **Status:** {_one_line(incident['status'])}, priority {_one_line(incident['priority'])}",
                  f"- **Severity:** {_one_line(incident['severity'])}", f"- **Confidence:** {_one_line(incident['confidence'])}%",
                  f"- **Risk:** {_one_line(incident['risk_score'])}/100 {_one_line(incident['risk_level'])}",
                  f"- **Affected hosts:** {_one_line(', '.join(incident['hosts'])) or 'none named'}",
                  f"- **Affected users:** {_one_line(', '.join(incident['users'])) or 'none named'}",
                  f"- **Related alerts:** {_one_line(', '.join(incident['related_alerts']))}",
                  f"- **Possible ATT&CK stages:** {_one_line('; '.join(incident['mitre'])) or 'not mapped'}",
                  f"- **Automation:** {_one_line(incident['automation_status'])}", '', '**Why this score:**', '']
        lines += [f"- {_one_line(r['factor']).replace('_', ' ')} ({_one_line(r['points'])} points): {_one_line(r['reason'])}" for r in incident['risk_reasons']]
        lines += ['', '**Timeline:**', '']
        for entry in incident['timeline']:
            count = f" (x{entry['count']})" if entry['count'] > 1 else ''
            lines.append(f"- {_one_line(entry['timestamp'])}: {_one_line(entry['summary'])}{count} [{', '.join(entry['rules'])}]")
        lines.append('')
    affected = content['affected']
    lines += ['## Affected users and hosts', '', f"- **Users:** {_one_line(', '.join(affected['users'])) or 'none named'}", f"- **Hosts:** {_one_line(', '.join(affected['hosts'])) or 'none named'}", '',
              '## Risk analysis', '',
              f"- **Severity distribution (alerts):** {_distribution(results['severity_distribution'])}",
              f"- **Incident risk distribution:** {_distribution(results['incident_risk_distribution'])}",
              f"- **Alert risk distribution:** {_distribution(results['alert_risk_distribution'])}",
              '- Risk is an investigation priority, not the probability that an attack is real. Each incident above lists the factors behind its score.', '',
              '## MITRE ATT&CK mappings', '']
    lines += [f"- {_one_line(t['id'])} {_one_line(t['name'])} ({_one_line(t['tactic'])})" for t in content['mitre']] or ['- None.']
    lines += ['', '## Recommended remediation', '', 'Historical analysis is read-only. Nothing below has been done, and any disruptive step needs an analyst to approve it.', '']
    for item in content['remediation']:
        lines.append(f"- **{_one_line(item['rule_id'])} {_one_line(item['rule_name'])}:** {_one_line(' '.join(item['steps']))}")
    if not content['remediation']:
        lines.append('- None required by these findings.')
    lines += ['', '## Recommended actions (simulation only)', '']
    lines += [f"- {_one_line(a['incident'])}, **{_one_line(a['status'])}:** {_one_line(a['label'])} on `{_one_line(a['target'])}`"
              + (' (disruptive, needs approval)' if a['disruptive'] else '') for a in content['recommended_actions']] or ['- None.']
    lines += ['', '## Analyst decisions', '']
    lines += [f"- {_one_line(a['incident'])}, {_one_line(a['status'])}: {_one_line(a['label'])} on `{_one_line(a['target'])}` by {_one_line(a['decided_by'])} "
              f"at {_one_line(a['decided_at'])}" + (f". Reason: {_one_line(a['decision_reason'])}" if a['decision_reason'] else '') for a in content['analyst_decisions']] or ['- None yet.']
    lines += ['', '## Model performance', '']
    lines += [f'- {line}' for line in _metric_lines(content['model_performance'])]
    lines += ['', '## Known limitations', ''] + [f'- {item}' for item in content['limitations']]
    return '\n'.join(lines) + '\n'


def _cell(value):
    """A spreadsheet treats these first characters as a formula, and log text can contain anything"""
    text = '' if value is None else str(value)
    return f"'{text}" if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text


def render_csv(report):
    content = report['content']
    results = content['detection_results']
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    def row(*values):
        writer.writerow([_cell(value) for value in values])
    row('section', 'item', 'value', 'detail')
    row('report', 'id', report['report_id'], report['title'])
    row('report', 'generated_at', report['generated_at'], '')
    row('assessment', 'verdict', content['overall_assessment']['status'], content['overall_assessment']['statement'])
    for key, value in content['processing_summary'].items():
        row('processing', key, value, '')
    for engine in content['detection_engines']:
        row('engine', engine['name'], engine['status'], engine['reason'])
    row('detection', 'alerts', results['alerts'], '')
    row('detection', 'incidents', results['incidents'], '')
    for level, count in results['incident_risk_distribution'].items():
        row('incident_risk', level, count, '')
    for key in ('ioa_matches', 'ioc_matches', 'ueba_findings', 'ml_findings'):
        for finding in results[key]:
            row(key, finding['rule_id'], finding['severity'], finding['explanation'])
    for label, count in content['ml_classification']['distribution'].items():
        row('ml_classification', label, count, '')
    for item in content['anomaly_results']['findings']:
        row('anomaly', item['entity'], item['strength'], item['explanation'])
    for incident in content['incidents']:
        row('incident', incident['uid'], f"{incident['risk_score']}/100 {incident['risk_level']}", incident['title'])
    for action in content['recommended_actions']:
        row('action', action['incident'], action['status'], f"{action['label']} on {action['target']}")
    metrics = content['model_performance']
    for name in ('event_level', 'alert_level', 'incident_level', 'ml_level', 'anomaly_level'):
        for key, value in (metrics.get(name) or {}).items():
            row(name, key, value, '')
    row('metrics', 'detection_latency_seconds', metrics.get('detection_latency_seconds'), '')
    return buffer.getvalue()


def _pdf_escape(text):
    return text.encode('latin-1', 'replace').decode('latin-1').replace('\\', r'\\').replace('(', r'\(').replace(')', r'\)')


def render_pdf(text):
    """A plain, paginated text PDF, written directly so that no extra dependency is needed"""
    lines = []
    for line in text.splitlines():
        heading = line.startswith('#')
        clean = line.lstrip('#').strip() if heading else line.replace('**', '').replace('`', '')
        for part in textwrap.wrap(clean, 88, subsequent_indent='    ', break_long_words=True) or ['']:
            lines.append((part, heading))
    per_page = 56
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[('', False)]]

    objects = {
        1: b'<< /Type /Catalog /Pages 2 0 R >>',
        3: b'<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>',
        4: b'<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>',
    }
    kids = []
    number = 5
    for index, page in enumerate(pages, 1):
        body = ['BT 40 800 Td 13 TL']
        current = None
        for part, heading in page:
            font = 'F2' if heading else 'F1'
            if font != current:
                body.append(f'/{font} 9 Tf')
                current = font
            body.append(f'({_pdf_escape(part)}) Tj T*')
        body.append('ET')
        body.append(f'BT /F1 8 Tf 40 28 Td (ALLSAFE security report, page {index} of {len(pages)}) Tj ET')
        stream = '\n'.join(body).encode('latin-1')
        objects[number] = b'<< /Length %d >>\nstream\n%s\nendstream' % (len(stream), stream)
        objects[number + 1] = (b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents %d 0 R '
                               b'/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>' % number)
        kids.append(number + 1)
        number += 2
    objects[2] = b'<< /Type /Pages /Kids [%s] /Count %d >>' % (b' '.join(b'%d 0 R' % kid for kid in kids), len(kids))

    output = io.BytesIO()
    output.write(b'%PDF-1.4\n')
    offsets = {}
    for key in sorted(objects):
        offsets[key] = output.tell()
        output.write(b'%d 0 obj\n%s\nendobj\n' % (key, objects[key]))
    start = output.tell()
    output.write(b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1))
    for key in sorted(objects):
        output.write(b'%010d 00000 n \n' % offsets[key])
    output.write(b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, start))
    return output.getvalue()
