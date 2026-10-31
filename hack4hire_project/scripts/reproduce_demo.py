"""A reproducible demonstration: the whole pipeline, from synthetic data to reports, on a throwaway database.

    python scripts/reproduce_demo.py                  # print what happened
    python scripts/reproduce_demo.py --write-samples  # also refresh docs/sample_reports

It calls the same REST API as the dashboard, so nothing here goes around the pipeline. It sends
no network traffic, and changes nothing outside its temporary database and, if asked, docs/sample_reports.
The exit code is the number of checks that failed.
"""
import argparse
import io
import json
import logging
import os
import shutil
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix='allsafe-demo-')
os.environ['ALLSAFE_DB_PATH'] = os.path.join(WORK, 'demo.db')

import app as allsafe  # noqa: E402

SAMPLES = os.path.join(ROOT, 'data', 'samples')
REPORTS = os.path.join(ROOT, 'docs', 'sample_reports')
ANALYST = 'Demo Analyst'
output = []
failures = []


def say(text=''):
    print(text)
    output.append(text)


def check(name, passed, detail=''):
    say(f"  {'PASS' if passed else 'FAIL'}  {name}{f'  ({detail})' if detail else ''}")
    if not passed:
        failures.append(name)


def wait(client, path, finished, timeout=300):
    end = time.time() + timeout
    while time.time() < end:
        body = client.get(path).get_json()
        if finished(body):
            return body
        time.sleep(0.05)
    raise TimeoutError(path)


def run_simulation(client, scenario, **params):
    started = client.post('/api/simulations', json={'scenario': scenario, 'speed': 'instant', 'seed': 42, **params}).get_json()
    return wait(client, f"/api/simulations/{started['run_id']}", lambda v: not v['active'] and v['status'] not in ('RUNNING', 'PAUSED'))


def finish_dataset(client, response):
    body = response.get_json()
    return wait(client, f"/api/datasets/{body['dataset']['dataset_id']}", lambda d: not d['active'] and d['status'] != 'PROCESSING')


def upload(client, name, **form):
    with open(os.path.join(SAMPLES, name), 'rb') as handle:
        data = handle.read()
    return finish_dataset(client, client.post('/api/datasets/upload', data={'file': (io.BytesIO(data), name), **form}, content_type='multipart/form-data'))


def save(client, report_id, stem, formats=('md',)):
    os.makedirs(REPORTS, exist_ok=True)
    for file_format in formats:
        body = client.get(f'/api/reports/{report_id}?format={file_format}').get_data()
        with open(os.path.join(REPORTS, f'{stem}.{file_format}'), 'wb') as handle:
            handle.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write-samples', action='store_true')
    os.environ['NARS_MODE'] = 'local'
    args = parser.parse_args()

    allsafe.initialize_storage()
    logging.disable(logging.WARNING)
    client = allsafe.app.test_client()

    say('ALLSAFE reproducible demonstration. All data is synthetic.')
    say()
    say('1. Simulation Lab: each risk tier, through the real pipeline')
    say(f"   {'Scenario':24}{'Events':>7}{'Alerts':>7}{'Incidents':>10}{'Risk':>6} {'Level':9}{'Priority':9}{'Missed':>7}{'Unexpected':>11}")
    expected_tiers = (('low_signal', None), ('port_scan', 'MEDIUM'), ('exfil', 'HIGH'), ('multi_stage', 'CRITICAL'), ('benign', None))
    runs = {}
    for scenario, tier in expected_tiers:
        view = run_simulation(client, scenario)
        runs[scenario] = view
        top = max(view['incidents'], key=lambda i: i['risk_score'], default={})
        say(f"   {view['name']:24}{view['event_count']:>7}{view['alert_count']:>7}{len(view['incidents']):>10}{top.get('risk_score', '-'):>6} {top.get('risk_level', '-'):9}{top.get('priority', '-'):9}{len(view['missed_rules']):>7}{len(view['unexpected_rules']):>11}")
    say()
    for scenario, tier in expected_tiers:
        view = runs[scenario]
        check(f'{scenario} produced exactly its expected detections', not view['missed_rules'] and not view['unexpected_rules'])
        if tier:
            check(f'{scenario} is {tier} risk', view['incidents'][0]['risk_level'] == tier, view['incidents'][0]['risk_score'])
    check('a low-risk signal opens no incident', runs['low_signal']['incidents'] == [] and runs['low_signal']['alert_count'] == 1)
    check('normal activity raises nothing', runs['benign']['alert_count'] == 0)

    say()
    say('2. Response: the SOC decides high and critical risk, small risks are automatic, and nothing real ever runs')
    incident = runs['multi_stage']['incidents'][0]
    actions = client.get(f"/api/incidents/{incident['id']}/response-actions").get_json()
    block = next(a for a in actions if a['action_type'] == 'block_test_ip')
    path = f"/api/response-actions/{block['id']}"
    check('critical risk: every action waits for SOC approval', {a['status'] for a in actions} == {'PENDING'}, f'{len(actions)} actions')
    check('running an action without approval is refused', client.post(f'{path}/execute', json={'analyst': ANALYST}).status_code == 409)
    client.post(f'{path}/decision', json={'decision': 'approve', 'analyst': ANALYST, 'reason': 'Confirmed in the timeline'})
    done = client.post(f'{path}/execute', json={'analyst': ANALYST}).get_json()
    check('after approval it runs in simulation and is verified', done['status'] == 'EXECUTED' and done['verification']['verified'] and done['result']['real_system_changed'] is False)
    check('the real blocklist is untouched', client.get('/api/blocklist').get_json() == [])
    audit = [e['action'] for e in client.get(f"/api/audit?incident_id={incident['id']}&limit=500").get_json()]
    check('the audit log recorded it all', {'automation_applied', 'analyst_notified', 'response_approved', 'response_executed', 'response_verified'} <= set(audit))

    small = run_simulation(client, 'suspicious_process')['incidents'][0]
    small_actions = client.get(f"/api/incidents/{small['id']}/response-actions").get_json()
    safe = [a for a in small_actions if not a['disruptive']]
    held = [a for a in small_actions if a['disruptive']]
    check('suspicious_process is MEDIUM risk, so the policy treats it as small', small['risk_level'] == 'MEDIUM', small['risk_score'])
    check('medium risk: safe steps ran automatically in simulation', safe and all(a['status'] == 'EXECUTED' and a['decided_by'] == 'automation' and a['result']['real_system_changed'] is False for a in safe), f'{len(safe)} actions')
    check('medium risk: disruptive actions are held, not run', held and all(a['status'] == 'HELD' for a in held), f'{len(held)} actions')
    small_audit = [e['action'] for e in client.get(f"/api/audit?incident_id={small['id']}&limit=500").get_json()]
    check('the audit log recorded the automatic steps', {'response_auto_approved', 'response_held', 'response_executed'} <= set(small_audit))

    say()
    say('3. Log analysis: each sample file through the real upload path')
    say(f"   {'File':42}{'Type':34}{'Rows':>6}{'Bad':>5}{'Dup':>5}{'Alerts':>7}  Verdict")
    samples = (
        ('clean_activity.csv', 'NO_THREATS_DETECTED'), ('brute_force_windows.csv', 'THREATS_DETECTED'), ('linux_auth.log', 'THREATS_DETECTED'),
        ('firewall_ufw.log', 'THREATS_DETECTED'), ('suspicious_network.csv', 'SUSPICIOUS_ACTIVITY'), ('ioc_match.jsonl', 'THREATS_DETECTED'),
        ('privilege_escalation.jsonl', 'THREATS_DETECTED'), ('exfiltration.csv', 'THREATS_DETECTED'), ('application_access.csv', 'SUSPICIOUS_ACTIVITY'),
        ('malformed_records.csv', 'NO_THREATS_DETECTED'), ('duplicate_records.csv', 'NO_THREATS_DETECTED'), ('unsupported_fields.csv', 'NO_THREATS_DETECTED'),
        ('missing_timestamps.csv', 'NO_THREATS_DETECTED'), ('network_flows_cicids.csv', None),
    )
    results = {}
    for name, expected in samples:
        dataset = upload(client, name)
        results[name] = dataset
        summary = dataset['summary']
        say(f"   {name:42}{summary['dataset_type'][:32]:34}{summary['total_rows']:>6}{summary['invalid_records']:>5}{summary['skipped_duplicates']:>5}{dataset['metrics']['alerts']:>7}  {dataset['verdict']}")
    say()
    for name, expected in samples:
        if expected:
            check(f'{name} is {expected}', results[name]['verdict'] == expected, results[name]['verdict'])
    mapping = json.dumps({'when': 'timestamp', 'kind': 'source', 'origin_addr': 'src_ip', 'who': 'user', 'what': 'event_type', 'machine': 'hostname'})
    mapped = upload(client, 'custom_field_names.csv', mapping=mapping)
    check('a field mapping makes unfamiliar column names readable', 'IOA-001' in mapped['detection_distribution'])
    say()
    say('   Other log formats, from data/samples/formats')
    say(f"   {'File':42}{'Rows':>6}{'Bad':>5}{'Alerts':>7}  Verdict")
    formats = (('zeek_conn.log', 'THREATS_DETECTED'), ('aws_cloudtrail.json', 'THREATS_DETECTED'), ('winlogbeat_ecs.jsonl', 'THREATS_DETECTED'),
               ('nginx_error.log', 'THREATS_DETECTED'), ('syslog_rfc5424.log', 'THREATS_DETECTED'), ('suricata_eve.json', 'SUSPICIOUS_ACTIVITY'))
    for name, expected in formats:
        dataset = upload(client, os.path.join('formats', name))
        summary = dataset['summary']
        say(f"   {name:42}{summary['total_rows']:>6}{summary['invalid_records']:>5}{dataset['metrics']['alerts']:>7}  {dataset['verdict']}")
        check(f'{name} is {expected}', dataset['verdict'] == expected, dataset['verdict'])

    say()
    say('4. The saved network model, on data it can read')
    flows = results['network_flows_cicids.csv']
    ml = flows['analysis']['ml']
    engine = next(e for e in flows['analysis']['engines'] if e['engine'] == 'NIDS')
    say(f"   Status {engine['status']}, {ml['flows_classified']} flows classified, model version {ml['model_version']}")
    say(f"   Distribution: {ml['distribution']}")
    say('   These flows have random values, so this shows the model runs on compatible data. It says nothing about accuracy.')
    check('compatible flows were classified', engine['status'] == 'COMPLETED' and ml['flows_classified'] == 200, engine['status'])
    check('no prediction confidence is claimed', ml['confidence'] is None and ml['calibrated'] is False)
    other = results['brute_force_windows.csv']['analysis']['engines']
    check('Windows logs were not fed to it', next(e for e in other if e['engine'] == 'NIDS')['status'] == 'SKIPPED')

    say()
    say('5. A labelled, generated dataset, measured against its ground truth')
    generated = finish_dataset(client, client.post('/api/datasets/generate', json={'profile': 'mixed', 'count': 2000, 'duration_seconds': 7200, 'seed': 42}))
    metrics = generated['metrics']
    for name, title in (('event_level', 'Events'), ('alert_level', 'Alerts'), ('incident_level', 'Incidents'), ('anomaly_level', 'Anomaly model, events')):
        level = metrics.get(name)
        if level:
            say(f"   {title:24} TP {level['true_positives']:>4}  FP {level['false_positives']:>4}  FN {level['false_negatives']:>4}  precision {level['precision']}  recall {level['recall']}  F1 {level['f1']}")
    say(f"   Detection latency: {metrics['detection_latency_seconds']} seconds. Processing: {metrics['processing_seconds']} seconds.")
    say('   Measured on synthetic data written by the same team as the rules, so this shows the pipeline works as designed.')
    check('no rule was missed, and none fired unexpectedly', metrics['missed_rules'] == [] and metrics['unexpected_rules'] == [])

    say()
    say('6. The anomaly model, measured on seeded data it did not train on')
    evaluation = client.get('/api/ml').get_json()['anomaly_model']['evaluation']
    say(f"   False alarms: {evaluation['held_out_false_alarms']} of {evaluation['held_out_normal_windows']} normal windows ({evaluation['false_alarm_rate']:.2%})")
    say(f"   Attack windows flagged: {evaluation['attack_windows_flagged']} of {evaluation['attack_windows']} (recall {evaluation['recall']})")
    say('   Low recall is expected: a single command is not statistically unusual, and the rules cover those.')
    check('the false alarm rate is low on normal activity', evaluation['false_alarm_rate'] < 0.02)

    say()
    say('7. Reports come from stored results')
    report_id = client.post('/api/reports', json={'subject_type': 'simulation', 'subject_id': runs['multi_stage']['run_id']}).get_json()['report_id']
    report_text = client.get(f'/api/reports/{report_id}?format=md').get_data(as_text=True)
    check('the new report includes the analyst decision', ANALYST in report_text)
    pdf = client.get(f"/api/reports/{results['clean_activity.csv']['report_id']}?format=pdf").get_data()
    check('the clean dataset has a PDF report saying so', pdf.startswith(b'%PDF') and b'NO THREATS DETECTED' in pdf)

    say()
    say('8. Threat intelligence feed: imported, and stored events searched without creating alerts')
    alerts_before = client.get('/api/stats').get_json()['alerts']
    with open(os.path.join(SAMPLES, 'threat_feed.csv'), 'rb') as handle:
        feed = client.post('/api/datasets/upload', data={'file': (handle, 'threat_feed.csv'), 'analyst': ANALYST}, content_type='multipart/form-data').get_json()['ioc_feed']
    say(f"   {feed['total_rows']} rows, {feed['usable']} usable. Left out: {feed['skipped']}")
    say(f"   Retro-hunt: {feed['retro_hunt']['matching_events']} of {feed['retro_hunt']['events_searched']} stored events contain {feed['retro_hunt']['matched_indicators']} of its indicators")
    check('the feed is recognised, and bad entries are left out', feed['usable'] == 5 and len(feed['skipped']) == 3)
    check('the retro-hunt finds stored events', feed['retro_hunt']['matching_events'] > 0)
    check('the retro-hunt creates no alerts', client.get('/api/stats').get_json()['alerts'] == alerts_before)
    say(f"   Analysis: {feed['analysis']['headline']}")
    check('the feed itself is analyzed', feed['analysis']['total'] == 5 and feed['analysis']['themes'])
    feed_test = finish_dataset(client, client.post('/api/iocs/feeds/threat_feed/test', json={'count': 300, 'contacts': 5, 'seed': 42}))
    say(f"   Pipeline test: {feed_test['verdict']}, {feed_test['total_events']} logs, {len(feed_test['alerts'])} alerts, {len(feed_test['incidents'])} incidents")
    check('planting its indicators in synthetic logs is detected', feed_test['verdict'] == 'THREATS_DETECTED' and any(alert['detection_type'] == 'IOC' for alert in feed_test['alerts']))

    say()
    say('9. NARS answers from stored data, and cannot act')
    def ask(question):
        return client.post('/api/nars/ask', json={'question': question, 'analyst': ANALYST}).get_json()
    top = client.get('/api/incidents?status=OPEN&sort=risk&limit=1').get_json()[0]
    explained = ask(f"Explain {top['incident_uid']}")
    say(f"   Mode: {explained['mode']}. Asked to explain {top['incident_uid']}, it read: {', '.join(item['tool'] for item in explained['read'])}")
    check('it explains an incident with its stored score', f"risk {top['risk_score']}/100" in explained['answer'] and explained['grounded'])
    check('it does not invent an incident', 'no incident 999999' in ask('Explain INC-999999')['answer'])
    before = client.get('/api/stats').get_json()
    refusal = ask('Approve all pending actions')
    after = client.get('/api/stats').get_json()
    check('asked to approve, it refuses and nothing changes', 'I cannot do that' in refusal['answer'] and before['responses_pending'] == after['responses_pending'] and before['responses_executed'] == after['responses_executed'])

    say()
    say('10. Threat parameters, simulation impact, live flow, attack graph and coverage are computed from stored data')
    graph = client.get(f"/api/incidents/{top['id']}").get_json()['attack_graph']
    matrix = client.get('/api/attack-matrix').get_json()['totals']
    multi = client.get(f"/api/simulations/{runs['multi_stage']['run_id']}/impact").get_json()
    say(f"   Multi-stage impact: {multi['headline']}")
    for row in multi['parameters'][:6]:
        say(f"     {row['rule_id']:9} {row['measure'][:42]:42} normal {row['normal_text']:>8}  attack {row['attack_text']:>9}  limit {row['threshold_text']:>16}")
    check('attack logs cross limits that normal logs do not', all(row['crossed'] and not row.get('normal_crossed') for row in multi['parameters']))
    check('the benign run affects nothing', client.get(f"/api/simulations/{runs['benign']['run_id']}/impact").get_json()['assets'] == [])
    flagged = client.get('/api/logs?detected=1&limit=1').get_json()[0]
    verdict = client.get(f"/api/logs/{flagged['id']}/verdict").get_json()
    say(f"   One flagged log: {verdict['verdict']}, measured against {verdict['rules_checked']} rules")
    check('one log can be explained against the parameters', verdict['verdict'] in ('THREAT', 'SUSPICIOUS') and (verdict['rules'] or verdict['other_evidence']))
    flow = client.get('/api/flow?minutes=0').get_json()
    check('the live flow counts every stored log once', flow['total'] == client.get('/api/stats').get_json()['total'])
    say(f"   {top['incident_uid']} graph: {len(graph['nodes'])} entities, {len(graph['edges'])} connections")
    say(f"   Coverage: {matrix['techniques']} techniques in {matrix['tactics_with_rules']} of {matrix['tactics']} tactics, {matrix['techniques_tested']} tested by a scenario, {matrix['techniques_with_alerts']} have fired")
    check('the graph has entities and connections', graph['nodes'] and graph['edges'])
    check('the gaps stay visible', matrix['tactics_with_rules'] < matrix['tactics'])

    if args.write_samples:
        save(client, report_id, 'multi_stage_attack', ('md', 'pdf', 'csv', 'json'))
        save(client, runs['exfil']['report_id'], 'data_exfiltration')
        save(client, runs['benign']['report_id'], 'benign_activity')
        save(client, results['clean_activity.csv']['report_id'], 'dataset_no_threats_detected', ('md', 'pdf', 'json'))
        save(client, results['brute_force_windows.csv']['report_id'], 'dataset_windows_brute_force', ('md', 'pdf', 'json'))
        save(client, results['network_flows_cicids.csv']['report_id'], 'dataset_network_flows_ml')
        save(client, results['malformed_records.csv']['report_id'], 'dataset_malformed_records')
        save(client, generated['report_id'], 'dataset_generated_mixed', ('md', 'pdf'))

    say()
    say(f"{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED: ' + '; '.join(failures)}")
    if args.write_samples:
        with open(os.path.join(REPORTS, 'RUN_SUMMARY.txt'), 'w', encoding='utf-8', newline='\n') as handle:
            handle.write('\n'.join(output) + '\n')
        print(f'Sample reports written to {REPORTS}')
    return len(failures)


if __name__ == '__main__':
    code = main()
    logging.shutdown()
    shutil.rmtree(WORK, ignore_errors=True)
    sys.exit(code)
