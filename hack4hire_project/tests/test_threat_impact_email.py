import email
import http.server
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from email import policy
from unittest import mock

os.environ['ALLSAFE_LOAD_ML'] = '0'
for _name in ('GROQ_API_KEY', 'ANTHROPIC_API_KEY', 'NARS_MODE'):
    os.environ.pop(_name, None)

import app as allsafe
import models
from tests.helpers import TempDbTestCase
from utils import auth
from utils.correlation_engine import CorrelationEngine
from utils.email_alerts import EmailAlerter
from utils.impact import build_impact
from utils.ioc_engine import load_synthetic_feed
from utils.nars import Nars
from utils.normalizer import normalize_log
from utils.threat_parameters import condition_words, explain_log, peak_of, rule_parameters


def failed_login(seconds, src_ip='203.0.113.9', user='alice'):
    return normalize_log({'timestamp': f'2026-01-02T03:{seconds // 60:02d}:{seconds % 60:02d}Z', 'event_type': 'authentication_failure', 'src_ip': src_ip, 'user': user, 'hostname': 'web-01'},
                         'application', origin='upload')


class AppCase(TempDbTestCase):

    def setUp(self):
        super().setUp()
        auth.forget_enabled_state()
        load_synthetic_feed()
        allsafe.correlation_engine = CorrelationEngine(None, allsafe.fetch_stats)
        allsafe.app.config['TESTING'] = True
        self.client = allsafe.app.test_client()
        self.rules = allsafe.correlation_engine.detection.rules
        self.by_id = {rule['id']: rule for rule in self.rules}

    def run_scenario(self, name):
        run = allsafe.simulator.run_scenario(name)
        allsafe.correlation_engine.process_new_events()
        return run['run_id']


class ParameterTests(AppCase):

    def stored(self, logs):
        ids = models.batch_insert_logs(logs)
        return [models.get_log(log_id) for log_id in ids]

    def test_every_rule_states_its_parameters(self):
        for rule in self.rules:
            parameters = rule_parameters(rule)
            self.assertTrue(parameters['definition'], rule['id'])
            self.assertIn(str(rule['window_seconds']), parameters['definition'], rule['id'])
            self.assertNotIn('{', parameters['definition'], rule['id'])

    def test_definitions_read_properly(self):
        self.assertEqual(rule_parameters(self.by_id['IOA-001'])['definition'],
                         'At least 5 logs where event type is authentication_failure, for the same source IP within 300 seconds.')
        self.assertIn('50.0 MB or more total bytes sent', rule_parameters(self.by_id['IOA-007'])['definition'])
        self.assertIn('At least 3 different destination IP values', rule_parameters(self.by_id['IOA-009'])['definition'])
        self.assertIn('followed by', rule_parameters(self.by_id['IOA-002'])['definition'])

    def test_condition_words_cover_every_operator(self):
        words = condition_words({'all': [{'field': 'src_ip', 'ip_scope': 'internal'}, {'not': {'field': 'dst_port', 'in': [1, 2]}}, {'any': [{'field': 'user', 'exists': True}]}]})
        self.assertEqual(words, 'source IP is internal and not destination port is one of 1, 2 and (user is present)')

    def test_threshold_is_measured_exactly_at_the_limit(self):
        rule = self.by_id['IOA-001']
        below = peak_of(rule, self.stored([failed_login(i) for i in range(4)]))
        self.assertEqual((below['observed'], below['reached'], below['reached_ts']), (4, False, None))
        self.setUp()
        at_limit = peak_of(rule, self.stored([failed_login(i * 10) for i in range(5)]))
        self.assertEqual((at_limit['observed'], at_limit['reached']), (5, True))
        self.assertEqual(at_limit['reached_ts'], models.get_log(5)['ts_epoch'] if models.get_log(5) else at_limit['reached_ts'])

    def test_logs_outside_the_window_do_not_add_up(self):
        logs = self.stored([failed_login(i * 100) for i in range(5)])  # 400 seconds across, in a 300 second window
        self.assertFalse(peak_of(self.by_id['IOA-001'], logs)['reached'])

    def test_different_sources_are_measured_apart(self):
        logs = self.stored([failed_login(i, src_ip=f'203.0.113.{i}') for i in range(6)])
        self.assertEqual(peak_of(self.by_id['IOA-001'], logs)['observed'], 1)

    def test_normal_log_is_normal(self):
        log = self.stored([normalize_log({'timestamp': '2026-01-02T03:00:00Z', 'event_type': 'process_start', 'process_name': 'notepad.exe', 'hostname': 'wks-1'}, 'endpoint', origin='upload')])[0]
        result = explain_log(log, self.rules)
        self.assertEqual((result['verdict'], result['rules']), ('NORMAL', []))
        self.assertIn('does not prove it is harmless', result['statement'])

    def test_below_the_limit_is_suspicious_and_says_so(self):
        log = self.stored([failed_login(i) for i in range(3)])[0]
        result = explain_log(log, self.rules)
        self.assertEqual(result['verdict'], 'SUSPICIOUS')
        row = next(item for item in result['rules'] if item['id'] == 'IOA-001')
        self.assertEqual((row['observed'], row['threshold'], row['threshold_reached'], row['alert_id']), (3, 5, False, None))
        self.assertEqual(row['checks'][0]['actual'], 'authentication_failure')
        self.assertTrue(row['checks'][0]['met'])

    def test_a_log_behind_a_confirmed_detection_is_a_threat(self):
        ids = models.batch_insert_logs([failed_login(i) for i in range(8)] + [normalize_log(
            {'timestamp': '2026-01-02T03:01:00Z', 'event_type': 'authentication_success', 'src_ip': '203.0.113.9', 'user': 'alice', 'hostname': 'web-01'}, 'application', origin='upload')])
        allsafe.correlation_engine.process_new_events()
        result = self.client.get(f'/api/logs/{ids[0]}/verdict').get_json()
        self.assertEqual(result['verdict'], 'THREAT')
        row = next(item for item in result['rules'] if item['id'] == 'IOA-001')
        self.assertTrue(row['threshold_reached'] and row['alert_id'] and row['confirmed'])

    def test_simulation_logs_do_not_count_toward_other_worlds(self):
        self.run_scenario('brute_force')
        log = self.stored([failed_login(0, src_ip='203.0.113.10', user='admin')])[0]
        row = next(item for item in explain_log(log, self.rules)['rules'] if item['id'] == 'IOA-001')
        self.assertEqual(row['observed'], 1)

    def test_unknown_log_is_a_404(self):
        self.assertEqual(self.client.get('/api/logs/999999/verdict').status_code, 404)

    def test_api_states_everything_that_decides(self):
        data = self.client.get('/api/threat-parameters').get_json()
        self.assertEqual({item['name'] for item in data['classes']}, {'NORMAL', 'SUSPICIOUS', 'THREAT'})
        self.assertEqual(len(data['rules']), len(self.rules))
        self.assertTrue(data['behavioral'])
        self.assertIn('never a confirmed threat', data['models']['anomaly']['counts_as'])
        self.assertIn('no accuracy', data['models']['network']['counts_as'])
        self.assertTrue(data['indicators']['fields'])


class ImpactTests(AppCase):

    def impact(self, run_id):
        response = self.client.get(f'/api/simulations/{run_id}/impact')
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_multi_stage_attack_changes_the_environment(self):
        impact = self.impact(self.run_scenario('multi_stage'))
        self.assertEqual(impact['worst_state'], 'Data lost')
        self.assertIn('The threat affected', impact['headline'])
        assets = {asset['name']: asset for asset in impact['assets']}
        self.assertEqual(assets['web-01']['before'], 'Normal')
        self.assertEqual(assets['web-01']['after'], 'Data lost')
        self.assertEqual(assets['svc_admin']['after'], 'Compromised')
        self.assertIn('Confidentiality', impact['cia_affected'])
        self.assertTrue(impact['simulated'])

    def test_parameters_show_attack_logs_crossing_where_normal_logs_do_not(self):
        impact = self.impact(self.run_scenario('multi_stage'))
        rows = {row['rule_id']: row for row in impact['parameters']}
        self.assertTrue(rows['IOA-007']['crossed'])
        self.assertFalse(rows['IOA-007']['normal_crossed'])
        self.assertEqual(rows['IOA-007']['attack_text'], '90.0 MB')
        self.assertEqual(rows['IOA-007']['threshold_text'], '50.0 MB')
        self.assertEqual(rows['IOA-001']['normal'], 0)
        self.assertGreaterEqual(rows['IOA-001']['attack'], rows['IOA-001']['threshold'])

    def test_activity_is_compared_from_labelled_logs(self):
        impact = self.impact(self.run_scenario('multi_stage'))
        activity = {row['name']: row for row in impact['activity']}
        self.assertEqual(activity['Logs']['normal'] + activity['Logs']['attack'], impact['detection']['normal_logs'] + impact['detection']['attack_logs'])
        self.assertGreater(activity['Failed logins']['attack'], activity['Failed logins']['normal'])
        self.assertEqual(impact['data_out'], [{'destination': '198.51.100.77', 'mb': 90.0}])
        self.assertIn('ground truth', impact['comparison_basis'])

    def test_time_to_detection_waits_for_the_limit(self):
        run_id = self.run_scenario('brute_force')
        impact = self.impact(run_id)
        events = models.get_all_batch_events(run_id)
        attack = sorted(event['ts_epoch'] for event in events)
        # Ten failures two seconds apart: the limit of five is reached on the fifth
        self.assertEqual(impact['detection']['seconds_to_first_detection'], attack[4] - attack[0])
        self.assertGreater(impact['detection']['seconds_to_first_detection'], 0)

    def test_benign_activity_affects_nothing(self):
        impact = self.impact(self.run_scenario('benign'))
        self.assertEqual((impact['assets'], impact['worst_state'], impact['detection']['normal_logs_flagged']), ([], None, 0))
        self.assertIn('No asset was affected', impact['headline'])

    def test_a_response_run_in_simulation_contains_the_asset(self):
        run_id = self.run_scenario('multi_stage')
        incident = self.impact(run_id) and models.search_incidents(1, sort='risk')[0]
        action = next(item for item in models.get_response_actions(incident_id=incident['id']) if item['target'] in {asset['name'] for asset in self.impact(run_id)['assets']})
        before = self.impact(run_id)['response']['still_exposed']
        path = f"/api/response-actions/{action['id']}"
        self.client.post(f'{path}/decision', json={'decision': 'approve', 'analyst': 'alice'})
        self.assertEqual(self.client.post(f'{path}/execute', json={'analyst': 'alice'}).status_code, 200)
        after = self.impact(run_id)
        self.assertEqual(after['response']['still_exposed'], before - 1)
        contained = next(asset for asset in after['assets'] if asset['name'] == action['target'])
        self.assertEqual(contained['response'], 'Contained in simulation')

    def test_unknown_run_is_a_404(self):
        self.assertEqual(self.client.get('/api/simulations/nope/impact').status_code, 404)
        self.assertEqual(self.client.get('/api/datasets/nope/impact').status_code, 404)

    def test_every_rule_has_an_impact_or_is_reported_plainly(self):
        with open(os.path.join('config', 'impact_model.json'), encoding='utf-8') as handle:
            model = json.load(handle)
        for rule in self.rules:
            self.assertIn(rule['id'], model['rules'], rule['id'])
        for rule_id in allsafe.correlation_engine.ueba.rules:
            self.assertIn(rule_id, model['rules'], rule_id)

    def test_unlabelled_dataset_compares_logs_behind_detections(self):
        batch = 'ds-unlabelled'
        logs = [dict(failed_login(i * 5), origin='dataset', ingest_batch=batch) for i in range(6)]
        models.batch_insert_logs(logs)
        allsafe.correlation_engine.process_new_events()
        impact = build_impact(batch, self.rules)
        self.assertIn('No labels exist', impact['comparison_basis'])
        self.assertEqual(impact['detection']['attack_logs'], impact['detection']['attack_logs_detected'])


class FlowTests(AppCase):

    def flow(self, query='minutes=0'):
        response = self.client.get(f'/api/flow?{query}')
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def test_empty_database_gives_an_empty_flow(self):
        self.assertEqual(self.flow()['total'], 0)

    def test_each_log_is_counted_once_and_every_column_adds_up(self):
        self.run_scenario('multi_stage')
        self.run_scenario('benign')
        flow = self.flow()
        self.assertEqual(flow['total'], models.get_total_log_count())
        for column in range(3):
            nodes = [node for node in flow['nodes'] if node['column'] == column]
            self.assertEqual(sum(max(node.get('logs_in', 0), node.get('logs_out', 0)) for node in nodes), flow['total'], column)

    def test_verdicts_match_stored_evidence(self):
        self.run_scenario('multi_stage')
        flow = self.flow()
        nodes = {node['id']: node for node in flow['nodes']}
        batch = models.get_recent_simulation_runs(1)[0]['run_id']
        evidence = models.get_batch_evidence_ids(batch)
        flagged = sum(nodes[name]['logs_in'] for name in nodes if name in ('verdict:threat', 'verdict:suspicious'))
        self.assertEqual(flagged, len(evidence))
        self.assertIn('outcome:incident', nodes)
        self.assertEqual(nodes['verdict:normal']['logs_in'], nodes['outcome:stored']['logs_in'])

    def test_weak_signals_are_not_called_threats(self):
        low = {**dict(models.search_alerts(1) and {} or {})}
        self.assertEqual(low, {})
        models.batch_insert_logs([failed_login(0)])
        log_id = models.get_total_log_count()
        alert_id = models.insert_alert({'alert_uid': 'a', 'dedupe_key': 'k', 'rule_id': 'ML-X', 'rule_name': 'x', 'detection_type': 'ML', 'severity': 'MEDIUM', 'confidence': 90,
                                        'explanation': 'x', 'evidence': {}, 'mitre': [], 'recommendations': [], 'entities': {}, 'observed': 1, 'event_count': 1,
                                        'first_seen': 'x', 'last_seen': 'x', 'first_seen_ts': 0, 'last_seen_ts': 0}, [log_id])
        self.assertTrue(alert_id)
        ids = {node['id'] for node in self.flow()['nodes']}
        self.assertIn('verdict:suspicious', ids)
        self.assertNotIn('verdict:threat', ids)

    def test_filters(self):
        self.run_scenario('benign')
        self.assertEqual(self.flow('minutes=0&origin=dataset')['total'], 0)
        self.assertGreater(self.flow('minutes=0&origin=simulation')['total'], 0)
        self.assertEqual(self.client.get('/api/flow?minutes=7').status_code, 400)


class _StubSmtp(threading.Thread):
    """A small real SMTP server, so that the real smtplib code path runs"""

    def __init__(self):
        super().__init__(daemon=True)
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.messages = []
        self.reject = False

    def run(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn, conn.makefile('rwb') as stream:
                def say(text):
                    stream.write(text.encode() + b'\r\n')
                    stream.flush()
                say('220 stub')
                while True:
                    line = stream.readline().decode(errors='replace').strip()
                    if not line:
                        break
                    verb = line.split(' ')[0].upper()
                    if verb in ('EHLO', 'HELO'):
                        say('250 stub')
                    elif verb == 'RCPT' and self.reject:
                        say('550 refused secret-password-detail')
                    elif verb in ('MAIL', 'RCPT', 'RSET', 'NOOP'):
                        say('250 ok')
                    elif verb == 'DATA':
                        say('354 go')
                        body = b''
                        while True:
                            part = stream.readline()
                            if part in (b'.\r\n', b''):
                                break
                            body += part
                        self.messages.append(email.message_from_bytes(body, policy=policy.default))
                        say('250 ok')
                    elif verb == 'QUIT':
                        say('221 bye')
                        break
                    else:
                        say('500 no')


class EmailTests(AppCase):

    def setUp(self):
        super().setUp()
        self.server = _StubSmtp()
        self.server.start()
        self.addCleanup(self.server.listener.close)
        self.env = mock.patch.dict(os.environ, {'ALLSAFE_SMTP_HOST': '127.0.0.1', 'ALLSAFE_SMTP_PORT': str(self.server.port), 'ALLSAFE_SMTP_SECURITY': 'none',
                                                'ALLSAFE_ALERT_EMAIL_TO': 'soc@example.com, lead@example.com', 'ALLSAFE_ALERT_EMAIL_FROM': 'allsafe@example.com'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.alerter = EmailAlerter()
        allsafe.correlation_engine.on_notification = self.alerter.on_notification

    def test_not_configured_sends_nothing_and_says_how(self):
        with mock.patch.dict(os.environ, {'ALLSAFE_SMTP_HOST': ''}):
            self.assertFalse(self.alerter.configured())
            self.assertIn('.env', self.alerter.status()['needs'])
            self.alerter.on_notification({'incident_id': 1, 'level': 'CRITICAL'})
            self.alerter.drain()
            self.assertEqual(self.alerter.send_test(), (False, 'Email is not set up yet.'))
        self.assertEqual(self.server.messages, [])

    def test_status_reveals_no_secrets(self):
        with mock.patch.dict(os.environ, {'ALLSAFE_SMTP_PASSWORD': 'hunter2-secret', 'ALLSAFE_SMTP_USER': 'someone'}):
            text = json.dumps(self.alerter.status())
        self.assertNotIn('hunter2-secret', text)
        self.assertNotIn('soc@example.com', text)

    def test_a_high_risk_incident_is_emailed_with_its_reasons(self):
        self.run_scenario('multi_stage')
        self.alerter.drain()
        self.assertEqual(len(self.server.messages), 1)
        message = self.server.messages[0]
        self.assertTrue(message['Subject'].startswith('[SIMULATED] ALLSAFE CRITICAL risk: INC-'))
        self.assertEqual(message['To'], 'soc@example.com, lead@example.com')
        body = message.get_content()
        self.assertIn('Why it was flagged:', body)
        self.assertIn('IOA-', body)
        self.assertIn('Waiting for an analyst decision:', body)
        self.assertIn('/dashboard#investigations/', body)
        self.assertIn('synthetic simulation data', body)
        self.assertIn('has not changed any system', body)
        self.assertEqual(models.get_email_log(1)[0]['status'], 'SENT')

    def test_below_the_minimum_risk_nothing_is_sent(self):
        self.run_scenario('port_scan')
        self.alerter.drain()
        self.assertEqual(self.server.messages, [])
        with mock.patch.dict(os.environ, {'ALLSAFE_ALERT_EMAIL_MIN_RISK': 'CRITICAL'}):
            self.alerter.on_notification({'incident_id': 1, 'level': 'HIGH'})
            self.alerter.drain()
        self.assertEqual(self.server.messages, [])

    def test_a_hostile_title_cannot_add_headers(self):
        models_incident = {'id': 1, 'incident_uid': 'INC-000001', 'title': 'x\r\nBcc: attacker@example.com', 'risk_level': 'HIGH', 'entities': {}}
        with mock.patch('utils.email_alerts.get_alerts_for_incident', return_value=[]), mock.patch('utils.email_alerts.get_response_actions', return_value=[]):
            subject, _ = self.alerter.compose(models_incident)
        self.assertNotIn('\n', subject)
        self.assertTrue(self.alerter._send(None, subject, 'body'))
        self.assertIsNone(self.server.messages[0]['Bcc'])

    def test_the_hourly_limit_holds_and_is_recorded(self):
        run_id = self.run_scenario('benign')
        self.assertTrue(run_id)
        with mock.patch.dict(os.environ, {'ALLSAFE_ALERT_EMAIL_MAX_PER_HOUR': '1'}):
            self.run_scenario('multi_stage')
            self.alerter.drain()
            incident = models.search_incidents(1, sort='risk')[0]
            self.assertFalse(self.alerter.send_incident(incident['id']))
        self.assertEqual(len(self.server.messages), 1)
        self.assertEqual(models.get_email_log(1)[0]['status'], 'SKIPPED')

    def test_a_refusal_is_recorded_without_the_server_reply(self):
        self.server.reject = True
        self.assertEqual(self.alerter.send_test()[0], False)
        entry = models.get_email_log(1)[0]
        self.assertEqual(entry['status'], 'FAILED')
        self.assertNotIn('secret-password-detail', entry['error'])

    def test_a_broken_mail_server_never_stops_detection(self):
        with mock.patch.dict(os.environ, {'ALLSAFE_SMTP_PORT': '1'}):
            self.run_scenario('multi_stage')
            self.alerter.drain()
        self.assertGreater(models.get_dashboard_counts()['alerts'], 0)
        self.assertEqual(models.get_email_log(1)[0]['status'], 'FAILED')

    def test_routes(self):
        allsafe.email_alerter = self.alerter
        self.assertEqual(self.client.post('/api/email/test', json={}).status_code, 400)
        self.assertEqual(self.client.post('/api/email/test', json={'analyst': 'alice'}).get_json(), {'sent': True})
        status = self.client.get('/api/email/status').get_json()
        self.assertEqual((status['configured'], status['recipients'], status['recent'][0]['status']), (True, 2, 'SENT'))
        self.assertEqual(models.get_audit_entries(5, action='email_test')[0]['actor'], 'alice')


class _StubGroq(http.server.BaseHTTPRequestHandler):
    replies = []
    seen = []
    status = 200
    limited_once = False

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['content-length'])))
        type(self).seen.append({'path': self.path, 'auth': self.headers.get('Authorization'), 'body': body})
        if type(self).limited_once:
            type(self).limited_once = False
            self.send_response(429)
            self.send_header('retry-after', '0')
            self.send_header('content-length', '2')
            self.end_headers()
            self.wfile.write(b'{}')
            return
        data = json.dumps(type(self).replies.pop(0) if type(self).status == 200 else {'error': {'message': 'no'}}).encode()
        self.send_response(type(self).status)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def groq_reply(content=None, calls=None, finish='stop'):
    message = {'role': 'assistant', 'content': content}
    if calls:
        message['tool_calls'] = [{'id': f'c{i}', 'type': 'function', 'function': {'name': name, 'arguments': arguments}} for i, (name, arguments) in enumerate(calls)]
    return {'choices': [{'message': message, 'finish_reason': 'tool_calls' if calls else finish}]}


class GroqTests(AppCase):

    def setUp(self):
        super().setUp()
        _StubGroq.replies, _StubGroq.seen, _StubGroq.status = [], [], 200
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _StubGroq)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.env = mock.patch.dict(os.environ, {'GROQ_API_KEY': 'test-key', 'GROQ_BASE_URL': f'http://127.0.0.1:{self.server.server_port}'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.nars = Nars(lambda: allsafe.correlation_engine)

    def test_status_says_data_leaves_and_shows_no_key(self):
        status = self.nars.status()
        self.assertEqual((status['mode'], status['model'], status['data_leaves_machine']), ('groq', 'openai/gpt-oss-120b', True))
        self.assertIn('sent to the Groq', status['note'])
        self.assertNotIn('test-key', json.dumps(status))

    def test_tool_loop_answers_from_tool_results(self):
        self.run_scenario('brute_force')
        incident = models.search_incidents(1)[0]
        _StubGroq.replies = [groq_reply(calls=[('get_incident', json.dumps({'incident_id': incident['id']}))]), groq_reply(f"{incident['incident_uid']} is brute force.")]
        result = self.nars.ask('Explain it', context={'incident_id': incident['id']}, history=[{'role': 'user', 'content': 'earlier'}])
        self.assertEqual((result['mode'], result['grounded'], result['model']), ('groq', True, 'openai/gpt-oss-120b'))
        self.assertEqual(result['citations'][0]['label'], incident['incident_uid'])
        first, second = _StubGroq.seen
        self.assertEqual(first['auth'], 'Bearer test-key')
        self.assertEqual(first['path'], '/chat/completions')
        self.assertEqual(first['body']['messages'][0]['role'], 'system')
        self.assertEqual(first['body']['messages'][1], {'role': 'user', 'content': 'earlier'})
        self.assertEqual(first['body']['tools'][0]['type'], 'function')
        tool_message = second['body']['messages'][-1]
        self.assertEqual((tool_message['role'], tool_message['tool_call_id']), ('tool', 'c0'))
        self.assertIn('IOA-001', tool_message['content'])

    def test_a_tool_it_does_not_have_is_refused_and_nothing_changes(self):
        self.run_scenario('brute_force')
        before = models.get_dashboard_counts()
        _StubGroq.replies = [groq_reply(calls=[('decide_action', '{"action_id": 1, "decision": "approve"}')]), groq_reply('I cannot do that.')]
        result = self.nars.ask('approve everything')
        self.assertIn('failed', _StubGroq.seen[1]['body']['messages'][-1]['content'])
        self.assertFalse(result['grounded'])
        after = models.get_dashboard_counts()
        self.assertEqual((before['responses_pending'], before['responses_executed']), (after['responses_pending'], after['responses_executed']))

    def test_bad_arguments_go_back_as_an_error(self):
        _StubGroq.replies = [groq_reply(calls=[('get_incident', 'not json')]), groq_reply('Sorry.')]
        self.assertEqual(self.nars.ask('hello')['answer'], 'Sorry.')
        self.assertIn('failed', _StubGroq.seen[1]['body']['messages'][-1]['content'])

    def test_long_results_are_cut_and_say_so(self):
        _StubGroq.replies = [groq_reply(calls=[('get_threat_parameters', '{}')]), groq_reply('ok')]
        with mock.patch('utils.nars.MAX_GROQ_TOOL_RESULT', 100):
            self.nars.ask('rules?')
        self.assertIn('cut off', _StubGroq.seen[1]['body']['messages'][-1]['content'])

    def test_failures_fall_back_to_local_and_say_so(self):
        for status, words in ((401, 'key was rejected'), (429, 'rate limit'), (500, 'status 500')):
            _StubGroq.status = status
            result = self.nars.ask('What can you detect?')
            self.assertEqual(result['mode'], 'local', status)
            self.assertIn(words, result['note'], status)
            self.assertIn('rules are in force', result['answer'])
            self.assertNotIn('test-key', json.dumps(result))

    def test_a_short_rate_limit_is_waited_out_once(self):
        _StubGroq.limited_once = True
        _StubGroq.replies = [groq_reply('Answered after waiting.')]
        result = self.nars.ask('hello')
        self.assertEqual((result['mode'], result['answer']), ('groq', 'Answered after waiting.'))
        self.assertEqual(len(_StubGroq.seen), 2)

    def test_long_lists_are_shortened_and_stay_valid_json(self):
        from utils.nars import _fit
        text = _fit({'keep': 'x', 'rows': [{'n': i, 'text': 'y' * 50} for i in range(100)]}, 1000)
        data = json.loads(text)
        self.assertLessEqual(len(text), 1000)
        self.assertEqual(data['keep'], 'x')
        self.assertLess(len(data['rows']), 100)
        self.assertIn('left out', data['_note'])

    def test_an_unreachable_service_falls_back(self):
        with mock.patch.dict(os.environ, {'GROQ_BASE_URL': 'http://127.0.0.1:1'}):
            result = self.nars.ask('hello')
        self.assertEqual(result['mode'], 'local')
        self.assertIn('could not be reached', result['note'])

    def test_groq_is_preferred_and_local_can_be_forced(self):
        with mock.patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'other'}):
            self.assertEqual(self.nars.status()['mode'], 'groq')
        with mock.patch.dict(os.environ, {'NARS_MODE': 'local'}):
            self.assertEqual(self.nars.status()['mode'], 'local')


class NarsNewQuestionTests(AppCase):

    def ask(self, question):
        return self.client.post('/api/nars/ask', json={'question': question}).get_json()

    def test_what_defines_a_threat(self):
        for question in ('What parameters define a threat?', 'on what parameters do you define a log as a threat', 'what makes a log a threat?'):
            answer = self.ask(question)
            self.assertIn('get_threat_parameters', [item['tool'] for item in answer['read']], question)
            self.assertIn('At least 5 logs where event type is authentication_failure', answer['answer'], question)

    def test_what_a_simulation_affected(self):
        self.assertIn('No simulation has fired', self.ask('What did the latest simulation affect?')['answer'])
        self.run_scenario('multi_stage')
        answer = self.ask('What happens when the simulation is affected by the threat?')['answer']
        self.assertIn('The threat affected', answer)
        self.assertIn('90.0 MB', answer)
        self.assertIn('Nothing real was changed', answer)

    def test_why_one_log_is_a_threat(self):
        self.run_scenario('multi_stage')
        log = models.search_logs(1, detected=True)[0]
        answer = self.ask(f"Why is log {log['id']} a threat?")['answer']
        self.assertIn(f"Log {log['id']}:", answer)
        self.assertIn('Limit reached', answer)
        self.assertIn('no log 999999', self.ask('Explain log 999999')['answer'])

    def test_a_rule_answer_gives_its_limit(self):
        self.assertIn('Fires when:', self.ask('Tell me about rule IOA-001')['answer'])


class RedactionTests(unittest.TestCase):

    def test_secrets_on_a_command_line_are_masked(self):
        from utils.redaction import redact_secrets
        fake_key = 'gsk_' + 'a1B2' * 10
        for text, secret in ((f'curl -H "Authorization: Bearer {fake_key}" https://x', fake_key), (f'tool --api-key {fake_key}', fake_key),
                             ('mysql --password=hunter2secret -u root', 'hunter2secret'), ('app token=abc123def456', 'abc123def456'),
                             ('git clone https://bob:hunter2secret@example.com/r.git', 'hunter2secret'), ('run sk-ant-' + 'x' * 30, 'x' * 30),
                             ('aws AKIAABCDEFGHIJKLMNOP', 'AKIAABCDEFGHIJKLMNOP')):
            result = redact_secrets(text)
            self.assertNotIn(secret, result, text)
            self.assertIn('[REDACTED]', result, text)

    def test_ordinary_commands_keep_what_detection_reads(self):
        from utils.redaction import redact_secrets
        for text in ('powershell.exe -nop -w hidden -enc SQBFAFgA', 'net user backup_svc Xy12 /add', r'psexec.exe \\10.30.0.20 cmd.exe', 'sudo su -', 'notepad.exe report.txt'):
            self.assertEqual(redact_secrets(text), text)
        self.assertIsNone(redact_secrets(None))


class FeedAnalysisTests(AppCase):

    FEED = ('type,value,confidence,reason,first_seen,source_count,sources,tags\n'
            'domain,evil-c2.example,high,Used as a C2 server,2026-10-01T00:00:00+00:00,2,"[{""source"": ""lab-one""}, {""source"": ""lab-two""}]","[{""type"": ""malware"", ""value"": ""Mirai""}, {""type"": ""campaign"", ""value"": ""Red Sky""}]"\n'
            'domain,phish.example,low,Fake login page,2026-10-02T00:00:00+00:00,1,"[{""source"": ""lab-one""}]","[{""type"": ""malware"", ""value"": ""Mirai""}]"\n'
            'ipv4,198.51.100.201,medium,Not stated here,2026-10-02T00:00:00+00:00,1,lab-three:2026-10-02,\n').encode()

    def upload(self, data=None, name='sample-feed.csv'):
        return self.client.post('/api/datasets/upload', data={'file': (io.BytesIO(data or self.FEED), name), 'analyst': 'alice'}, content_type='multipart/form-data')

    def finish(self, dataset_id):
        for _ in range(240):
            view = self.client.get(f'/api/datasets/{dataset_id}').get_json()
            if not view['active'] and view['status'] != 'PROCESSING':
                return view
            time.sleep(0.25)
        self.fail('The dataset did not finish')

    def test_analysis_counts_what_is_in_the_file(self):
        analysis = self.upload().get_json()['ioc_feed']['analysis']
        named = lambda key: {item['name']: item['count'] for item in analysis[key]}
        self.assertEqual(named('by_type'), {'domain': 2, 'ip': 1})
        self.assertEqual(named('top_malware'), {'Mirai': 2})
        self.assertEqual(named('top_campaigns'), {'Red Sky': 1})
        self.assertEqual(named('top_reporters'), {'lab-one': 2, 'lab-two': 1, 'lab-three': 1})
        self.assertEqual(named('confidence'), {'High (70 or more)': 1, 'Medium (40 to 69)': 2})
        self.assertEqual(named('themes')['Command and control'], 1)
        self.assertEqual(named('themes')['Phishing or fake sites'], 1)
        self.assertEqual(analysis['most_corroborated'][0]['value'], 'evil-c2.example')
        self.assertEqual((analysis['first_seen_from'], analysis['first_seen_to']), ('2026-10-01', '2026-10-02'))
        self.assertIn('3 indicators', analysis['headline'])
        self.assertIn('has not verified', analysis['note'])

    def test_different_files_give_different_analysis(self):
        first = self.upload().get_json()['ioc_feed']['analysis']['headline']
        other = b'type,value,confidence,reason\nipv4,198.51.100.202,high,Botnet scanner\n'
        second = self.upload(other, 'other.csv').get_json()['ioc_feed']['analysis']['headline']
        self.assertNotEqual(first, second)
        self.assertIn('1 indicator,', second)

    def test_json_sources_stay_readable_in_the_indicator(self):
        self.upload()
        description = models.find_ioc('evil-c2.example')['description']
        self.assertIn('Reported by: lab-one, lab-two.', description)
        self.assertNotIn('{', description)

    def test_analysis_is_kept_until_the_feed_is_removed(self):
        self.upload()
        self.assertEqual(self.client.get('/api/iocs/feeds/sample-feed/analysis').status_code, 200)
        listed = {feed['source']: feed for feed in self.client.get('/api/iocs/feeds').get_json()}
        self.assertTrue(listed['sample-feed']['has_analysis'])
        self.client.delete('/api/iocs/feeds/sample-feed', json={'analyst': 'alice'})
        self.assertEqual(self.client.get('/api/iocs/feeds/sample-feed/analysis').status_code, 404)

    def test_planted_indicators_go_through_the_whole_pipeline(self):
        self.upload()
        response = self.client.post('/api/iocs/feeds/sample-feed/test', json={'count': 200, 'contacts': 3, 'seed': 42})
        self.assertEqual(response.status_code, 202)
        view = self.finish(response.get_json()['dataset']['dataset_id'])
        self.assertEqual((view['status'], view['verdict'], view['total_events']), ('COMPLETED', 'THREATS_DETECTED', 200))
        self.assertEqual(set(view['expected_rules']), {'IOC-DOMAIN', 'IOC-IP'})
        self.assertEqual((view['metrics']['missed_rules'], view['metrics']['unexpected_rules']), ([], []))
        level = view['metrics']['event_level']
        self.assertEqual((level['true_positives'], level['false_positives'], level['false_negatives']), (3, 0, 0))
        self.assertTrue(view['report_id'])
        self.assertTrue(view['incidents'])

    def test_the_same_seed_plants_the_same_indicators(self):
        from utils.dataset_generator import generate_feed_test
        from utils.ioc_feed import indicators_of
        self.upload()
        make = lambda seed: [raw for raw, _, label, _ in generate_feed_test(indicators_of('sample-feed'), 50, 3600, seed, 'x', 2)[0] if label != 'normal']
        keys = lambda rows: sorted(str(row.get('domain') or row.get('dst_ip')) for row in rows)
        self.assertEqual(keys(make(1)), keys(make(1)))

    def test_bad_requests_are_refused(self):
        self.assertEqual(self.client.post('/api/iocs/feeds/nope/test', json={}).status_code, 404)
        self.upload()
        self.assertEqual(self.client.post('/api/iocs/feeds/sample-feed/test', json={'count': 'many'}).status_code, 400)
        self.assertEqual(self.client.post('/api/iocs/feeds/sample-feed/test', json={'count': 10, 'duration_seconds': 5}).status_code, 400)


class PageTests(AppCase):

    def test_landing_and_dashboard_are_separate_pages(self):
        landing = self.client.get('/').get_data(as_text=True)
        self.assertIn('landing.js', landing)
        self.assertIn('Open the console', landing)
        self.assertIn('view-parameters', self.client.get('/dashboard').get_data(as_text=True))

    def test_env_file_fills_gaps_and_never_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, '.env')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# a comment\nALLSAFE_TEST_NEW="from file"\nALLSAFE_TEST_SET=from file\n\nnot a setting\n')
            with mock.patch.dict(os.environ, {'ALLSAFE_TEST_SET': 'from shell'}):
                os.environ.pop('ALLSAFE_NO_ENV_FILE', None)
                allsafe.load_env_file(path)
                self.assertEqual(os.environ['ALLSAFE_TEST_NEW'], 'from file')
                self.assertEqual(os.environ['ALLSAFE_TEST_SET'], 'from shell')
                del os.environ['ALLSAFE_TEST_NEW']
            with mock.patch.dict(os.environ, {'ALLSAFE_NO_ENV_FILE': '1'}):
                allsafe.load_env_file(path)
                self.assertNotIn('ALLSAFE_TEST_NEW', os.environ)

    def test_the_guard_also_stops_flask_reading_a_env_file_in_the_current_folder(self):
        # A real server, because this is how a test server once sent real alert emails
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as folder:
            with open(os.path.join(folder, '.env'), 'w', encoding='utf-8') as handle:
                handle.write('ALLSAFE_SMTP_HOST=mail.invalid\nALLSAFE_ALERT_EMAIL_TO=nobody@example.invalid\n')
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            env = {name: value for name, value in os.environ.items() if 'SMTP' not in name and 'ALERT_EMAIL' not in name}
            env.update(ALLSAFE_NO_ENV_FILE='1', ALLSAFE_PORT=str(port), ALLSAFE_LOAD_ML='0', ALLSAFE_DB_PATH=os.path.join(folder, 'guard.db'), PYTHONIOENCODING='utf-8')
            project = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            server = subprocess.Popen([sys.executable, '-B', os.path.join(project, 'app.py')], cwd=folder, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                status = None
                for _ in range(120):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/email/status', timeout=2) as response:
                            status = json.load(response)
                        break
                    except OSError:
                        time.sleep(0.5)
            finally:
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(server.pid), '/T', '/F'], capture_output=True)
                else:
                    server.kill()
                server.wait(timeout=20)
            self.assertIsNotNone(status, 'the server did not start')
            self.assertFalse(status['configured'])


if __name__ == '__main__':
    unittest.main()
