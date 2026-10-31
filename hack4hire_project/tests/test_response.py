import os
import sqlite3
import unittest

os.environ['ALLSAFE_LOAD_ML'] = '0'

import app as allsafe
import models
from tests.helpers import TempDbTestCase
from utils.correlation_engine import CorrelationEngine, link_score
from utils.ioc_engine import load_synthetic_feed
from utils.normalizer import normalize_log
from utils.response_engine import PLAYBOOK, ResponseError, decide_action, execute_action, sync_recommendations, valid_target
from utils.risk_engine import load_scoring_config
from utils.simulator import SCENARIOS

SETTINGS = load_scoring_config()['correlation']


class ResponseBase(TempDbTestCase):

    def setUp(self):
        super().setUp()
        load_synthetic_feed()
        self.engine = CorrelationEngine()
        allsafe.correlation_engine = self.engine
        allsafe.app.config['TESTING'] = True
        self.client = allsafe.app.test_client()

    def incident(self, scenario='multi_stage'):
        return self.client.post(f'/api/simulate/{scenario}').get_json()['outcome']['incident_ids'][0]

    def action(self, incident_id, action_type):
        return next(a for a in models.get_response_actions(incident_id=incident_id) if a['action_type'] == action_type)


class WorkflowTests(ResponseBase):

    def test_recommendations_are_not_duplicated_when_an_incident_refreshes(self):
        incident_id = self.incident()
        before = len(models.get_response_actions(incident_id=incident_id))
        self.assertEqual(sync_recommendations(incident_id, models.get_alerts_for_incident(incident_id)), [])
        self.assertEqual(len(models.get_response_actions(incident_id=incident_id)), before)

    def test_nothing_runs_without_a_decision(self):
        actions = models.get_response_actions(incident_id=self.incident())
        self.assertTrue(actions)
        self.assertTrue(all(a['status'] == 'PENDING' and a['executed_at'] is None for a in actions))

    def test_full_approve_execute_verify(self):
        action = self.action(self.incident(), 'block_test_ip')
        decide_action(action['id'], {'decision': 'approve', 'analyst': 'priya'})
        done = execute_action(action['id'], {'analyst': 'priya'})
        self.assertEqual(done['status'], 'EXECUTED')
        self.assertFalse(done['result']['real_system_changed'])
        self.assertTrue(done['verification']['verified'])
        self.assertEqual(models.get_blocklist(), [])

    def test_every_rule_with_a_playbook_uses_a_known_action(self):
        for rule, steps in PLAYBOOK['rules'].items():
            for step in steps:
                self.assertIn(step['action'], PLAYBOOK['actions'], rule)

    def test_every_attack_scenario_gets_at_least_one_recommendation(self):
        for name, definition in SCENARIOS.items():
            # A lone low-risk signal opens no incident, so it has nothing to approve
            if definition['malicious'] and name != 'low_signal':
                with self.subTest(scenario=name):
                    self.assertTrue(models.get_response_actions(incident_id=self.incident(name)))

    def test_recommendations_skip_service_accounts_and_internal_block_targets(self):
        actions = models.get_response_actions(incident_id=self.incident('cred_dump'))
        self.assertNotIn('SYSTEM', [a['target'] for a in actions])
        lateral = models.get_response_actions(incident_id=self.incident('lateral'))
        self.assertNotIn('block_test_ip', [a['action_type'] for a in lateral])

    def test_protected_target_fails_transparently(self):
        action = self.action(self.incident(), 'block_test_ip')
        decide_action(action['id'], {'decision': 'modify', 'analyst': 'priya', 'target': '127.0.0.1'})
        done = execute_action(action['id'], {'analyst': 'priya'})
        self.assertEqual(done['status'], 'FAILED')
        self.assertIn('protected', done['result']['error'])
        self.assertFalse(done['verification']['verified'])

    def test_unexpected_failure_is_recorded_not_raised(self):
        action = self.action(self.incident(), 'block_test_ip')
        decide_action(action['id'], {'decision': 'approve', 'analyst': 'priya'})
        original = models.record_simulated_enforcement
        import utils.response_engine as engine
        engine.record_simulated_enforcement = lambda *_: (_ for _ in ()).throw(RuntimeError('boom'))
        try:
            done = execute_action(action['id'], {'analyst': 'priya'})
        finally:
            engine.record_simulated_enforcement = original
        self.assertEqual(done['status'], 'FAILED')
        self.assertNotIn('boom', str(done['result']))

    def test_two_analysts_cannot_both_decide(self):
        action = self.action(self.incident(), 'block_test_ip')
        decide_action(action['id'], {'decision': 'approve', 'analyst': 'a'})
        with self.assertRaises(ResponseError) as caught:
            decide_action(action['id'], {'decision': 'reject', 'analyst': 'b'})
        self.assertEqual(caught.exception.status, 409)

    def test_target_validation(self):
        self.assertEqual(valid_target('ip', '198.51.100.1'), '198.51.100.1')
        self.assertIsNone(valid_target('ip', 'x'))
        self.assertIsNone(valid_target('account', "a'; DROP TABLE x;--"))
        self.assertEqual(valid_target('process', 'psexec.exe'), 'psexec.exe')


class AuditTests(ResponseBase):

    def test_audit_log_is_append_only(self):
        self.incident()
        with models.get_db_connection() as conn:
            for statement in ('DELETE FROM audit_log', "UPDATE audit_log SET actor = 'x'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(statement)

    def test_refused_attempt_is_audited(self):
        action = self.action(self.incident(), 'block_test_ip')
        with self.assertRaises(ResponseError):
            execute_action(action['id'], {'analyst': 'mallory'})
        entry = models.get_audit_entries(action='response_refused')[0]
        self.assertEqual((entry['actor'], entry['entity_id']), ('mallory', action['id']))


class ApiAccessTests(ResponseBase):

    def test_decisions_are_refused_from_other_machines(self):
        action = self.action(self.incident(), 'block_test_ip')
        remote = {'REMOTE_ADDR': '192.0.2.10'}
        for path, body in ((f"/api/response-actions/{action['id']}/decision", {'decision': 'approve', 'analyst': 'x'}),
                           (f"/api/response-actions/{action['id']}/execute", {'analyst': 'x'}),
                           (f"/api/incidents/{action['incident_id']}/status", {'status': 'RESOLVED', 'analyst': 'x'})):
            self.assertEqual(self.client.post(path, json=body, environ_base=remote).status_code, 403, path)
        self.assertEqual(self.action(action['incident_id'], 'block_test_ip')['status'], 'PENDING')

    def test_status_change_is_validated_and_audited(self):
        incident_id = self.incident()
        path = f'/api/incidents/{incident_id}/status'
        self.assertEqual(self.client.post(path, json={'status': 'NOPE', 'analyst': 'x'}).status_code, 400)
        self.assertEqual(self.client.post(path, json={'status': 'RESOLVED'}).status_code, 400)
        self.assertEqual(self.client.post('/api/incidents/999/status', json={'status': 'RESOLVED', 'analyst': 'x'}).status_code, 404)
        response = self.client.post(path, json={'status': 'RESOLVED', 'analyst': 'priya', 'reason': 'Contained'})
        self.assertEqual(response.get_json()['status'], 'RESOLVED')
        entry = models.get_audit_entries(incident_id=incident_id, action='incident_status_changed')[0]
        self.assertEqual((entry['actor'], entry['details']['to']), ('priya', 'RESOLVED'))
        self.assertEqual(self.client.get('/api/stats').get_json()['incidents_resolved'], 1)


class IntegrationFixTests(ResponseBase):
    """Each of these reproduces a failure the black-box pipeline test found"""

    def failures(self, start, count=6, ip='203.0.113.70'):
        return [normalize_log({'timestamp': f'2026-01-02T03:{start + i:02d}:00Z', 'event_type': 'authentication_failure',
                               'src_ip': ip, 'hostname': 'crm-01', 'user': 'sales'}, 'application') for i in range(count)]

    def test_activity_after_closure_opens_a_new_incident(self):
        models.batch_insert_logs([normalize_log({'timestamp': f'2026-01-02T03:00:0{i}Z', 'event_type': 'authentication_failure',
                                                 'src_ip': '203.0.113.70', 'user': 'sales'}, 'application') for i in range(6)])
        self.engine.process_new_events()
        first = models.get_recent_incidents()[0]
        models.set_incident_status(first['id'], 'RESOLVED')
        models.batch_insert_logs([normalize_log({'timestamp': f'2026-01-02T03:00:1{i}Z', 'event_type': 'authentication_failure',
                                                 'src_ip': '203.0.113.70', 'user': 'sales'}, 'application') for i in range(6)])
        self.engine.process_new_events()
        incidents = {i['id']: i for i in models.get_recent_incidents()}
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[first['id']]['event_count'], 6)
        self.assertEqual(incidents[first['id']]['status'], 'RESOLVED')

    def test_investigating_incident_keeps_collecting_activity(self):
        models.batch_insert_logs([normalize_log({'timestamp': f'2026-01-02T03:00:0{i}Z', 'event_type': 'authentication_failure',
                                                 'src_ip': '203.0.113.70', 'user': 'sales'}, 'application') for i in range(6)])
        self.engine.process_new_events()
        first = models.get_recent_incidents()[0]
        models.set_incident_status(first['id'], 'INVESTIGATING')
        models.batch_insert_logs([normalize_log({'timestamp': '2026-01-02T03:00:20Z', 'event_type': 'authentication_failure',
                                                 'src_ip': '203.0.113.70', 'user': 'sales'}, 'application')])
        self.engine.process_new_events()
        self.assertEqual(len(models.get_recent_incidents()), 1)
        self.assertEqual(models.get_recent_incidents()[0]['event_count'], 7)

    def test_asset_list_links_a_host_to_its_address_in_both_directions(self):
        for alert, incident in (({'src_ip': ['10.10.3.10']}, {'hostname': ['web-03']}),
                                ({'hostname': ['web-03']}, {'src_ip': ['10.10.3.10']})):
            score, reasons = link_score(alert, incident, SETTINGS)
            self.assertGreaterEqual(score, SETTINGS['min_link_score'])
            self.assertEqual(reasons[0]['type'], 'asset_mapping')

    def test_a_host_and_an_unlisted_address_do_not_link(self):
        self.assertEqual(link_score({'src_ip': ['10.99.0.1']}, {'hostname': ['web-03']}, SETTINGS)[0], 0)

    def test_encoded_powershell_matches_with_or_without_other_arguments(self):
        for command in ('powershell.exe -enc AAAA', 'powershell -nop -enc AAAA', 'powershell.exe -EncodedCommand AAAA'):
            with self.subTest(command=command):
                models.batch_insert_logs([normalize_log({'timestamp': '2026-01-02T03:00:00Z', 'event_type': 'process_start',
                                                         'hostname': 'h', 'process_name': 'powershell.exe', 'command_line': command}, 'endpoint')])
                self.engine.process_new_events()
                self.assertEqual(models.get_recent_alerts(rule_id='IOA-008')[0]['rule_id'], 'IOA-008')
                TempDbTestCase.setUp(self)
                self.engine = CorrelationEngine()

    def test_upload_report_is_right_even_if_the_background_engine_ran_first(self):
        """The bug: the route reported only what its own engine call did, which could be nothing"""
        import io
        import json
        original = allsafe.correlation_engine.process_new_events
        engine = allsafe.correlation_engine
        # Simulate the background thread winning the race: all work is done before the route's call returns 0
        calls = []

        def background_first():
            calls.append(1)
            original()
            return original()

        engine.process_new_events = background_first
        data = json.dumps([{'timestamp': f'2026-01-02T03:00:0{i}Z', 'source': 'application', 'event_type': 'authentication_failure',
                            'src_ip': '203.0.113.5', 'hostname': 'x'} for i in range(6)]).encode()
        body = self.client.post('/api/ingest/upload', data={'file': (io.BytesIO(data), 'a.json')},
                                content_type='multipart/form-data').get_json()
        self.assertEqual(body['detection']['alerts_created'], 1)
        self.assertEqual(len(body['detection']['incidents_created']), 1)
        self.assertEqual(body['detection']['events'], 6)


if __name__ == '__main__':
    unittest.main()
