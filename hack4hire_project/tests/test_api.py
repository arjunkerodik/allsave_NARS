import io
import json
import threading
import os
import unittest

# The ML model is not used by the P0 pipeline and takes seconds to load
os.environ['ALLSAFE_LOAD_ML'] = '0'

import app as allsafe
import models
from tests.helpers import TempDbTestCase
from utils.normalizer import normalize_log
from utils.correlation_engine import CorrelationEngine
from utils.ioc_engine import load_synthetic_feed

TS = '2026-01-02T03:04:05Z'


class ApiTestCase(TempDbTestCase):

    def setUp(self):
        super().setUp()
        load_synthetic_feed()
        allsafe.correlation_engine = CorrelationEngine(None, allsafe.fetch_stats)
        allsafe.app.config['TESTING'] = True
        self.client = allsafe.app.test_client()


class ReadApiTests(ApiTestCase):

    def test_dashboard_page_loads(self):
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_empty_database_gives_real_zeros(self):
        stats = self.client.get('/api/stats').get_json()
        self.assertEqual((stats['total'], stats['incidents'], stats['alerts'], stats['critical_alerts']), (0, 0, 0, 0))

    def test_negative_limit_cannot_dump_the_table(self):
        models.batch_insert_logs([models_log(i) for i in range(5)])
        self.assertEqual(len(self.client.get('/api/logs?limit=-1').get_json()), 1)
        self.assertEqual(len(self.client.get('/api/logs?limit=2').get_json()), 2)

    def test_log_lists_omit_raw_payload(self):
        models.batch_insert_logs([models_log(0)])
        self.assertNotIn('raw_event', self.client.get('/api/logs').get_json()[0])

    def test_unknown_routes_and_ids_return_json_errors(self):
        self.assertEqual(self.client.get('/api/nope').status_code, 404)
        self.assertIn('error', self.client.get('/api/nope').get_json())
        self.assertEqual(self.client.get('/api/incidents/999').status_code, 404)
        self.assertEqual(self.client.get('/api/alerts/999').status_code, 404)

    def test_rules_are_exposed_without_internals(self):
        body = self.client.get('/api/rules').get_json()
        self.assertEqual(len(body['rules']), 18)
        self.assertNotIn('_pattern', json.dumps(body))

    def test_health_reports_ml_as_unvalidated(self):
        health = self.client.get('/api/health').get_json()
        self.assertEqual(health['rules_loaded'], 18)
        self.assertFalse(health['ml_model_validated'])

    def test_unexpected_errors_do_not_leak_details(self):
        original = allsafe.search_incidents
        allsafe.search_incidents = lambda *_: (_ for _ in ()).throw(RuntimeError('secret path C:\\x'))
        allsafe.app.config['TESTING'] = False
        allsafe.app.config['PROPAGATE_EXCEPTIONS'] = False
        try:
            response = self.client.get('/api/incidents')
        finally:
            allsafe.search_incidents = original
            allsafe.app.config['TESTING'] = True
        self.assertEqual(response.status_code, 500)
        self.assertNotIn('secret', response.get_data(as_text=True))


class SimulationApiTests(ApiTestCase):

    def test_multi_stage_full_flow(self):
        response = self.client.post('/api/simulate/multi_stage')
        self.assertEqual(response.status_code, 200)
        outcome = response.get_json()['outcome']
        self.assertEqual((outcome['missed_rules'], outcome['unexpected_rules']), ([], []))
        self.assertEqual(len(outcome['incident_ids']), 1)

        listed = self.client.get('/api/incidents').get_json()[0]
        self.assertEqual(listed['severity'], 'CRITICAL')
        self.assertIsInstance(listed['remediation'], list)

        detail = self.client.get(f"/api/incidents/{outcome['incident_ids'][0]}").get_json()
        self.assertTrue(detail['timeline'])
        self.assertEqual(len(detail['alerts']), 11)
        self.assertTrue(all(alert['explanation'] and alert['evidence'] for alert in detail['alerts']))
        self.assertTrue(detail['incident']['score_breakdown']['risk']['components'])

        stats = self.client.get('/api/stats').get_json()
        self.assertEqual(stats['incidents_open'], 1)
        self.assertEqual(stats['alerts'], 11)
        self.assertGreater(stats['critical_alerts'], 0)
        self.assertEqual(stats['high_risk_incidents'], 1)

    def test_benign_scenario_creates_nothing(self):
        outcome = self.client.post('/api/simulate/benign').get_json()['outcome']
        self.assertEqual(outcome['fired_rules'], [])
        self.assertEqual(self.client.get('/api/stats').get_json()['alerts'], 0)

    def test_get_cannot_trigger_a_simulation(self):
        self.assertEqual(self.client.get('/api/simulate/brute_force').status_code, 405)
        self.assertEqual(models.get_total_log_count(), 0)

    def test_unknown_scenario(self):
        self.assertEqual(self.client.post('/api/simulate/rm_rf').status_code, 400)

    def test_scenario_list_shows_ground_truth(self):
        self.client.post('/api/simulate/port_scan')
        body = self.client.get('/api/simulate').get_json()
        self.assertTrue(any(s['id'] == 'benign' and s['expected_rules'] == [] for s in body['scenarios']))
        self.assertEqual(body['recent_runs'][0]['fired_rules'], ['IOA-005'])


class IngestApiTests(ApiTestCase):

    def upload(self, name, data, **form):
        return self.client.post('/api/ingest/upload', data=dict(form, file=(io.BytesIO(data), name)),
                                content_type='multipart/form-data')

    def test_upload_detects_attack_in_historical_log(self):
        text = ''.join(f'Jan  2 03:04:{i:02d} srv1 sshd[7]: Failed password for root from 203.0.113.5 port 42 ssh2\n'
                       for i in range(6))
        body = self.upload('auth.log', text.encode()).get_json()
        self.assertEqual(body['stored'], 6)
        self.assertEqual(body['detection']['alerts_created'], 1)
        self.assertEqual(self.client.get('/api/alerts').get_json()[0]['rule_id'], 'IOA-001')

    def test_bad_uploads_are_refused_with_clear_errors(self):
        self.assertEqual(self.upload('x.exe', b'MZ').status_code, 400)
        self.assertEqual(self.upload('a.json', b'{').status_code, 400)
        self.assertEqual(self.client.post('/api/ingest/upload').status_code, 400)

    def test_oversized_request_is_refused(self):
        response = self.upload('a.log', b'x' * (allsafe.app.config['MAX_CONTENT_LENGTH'] + 1))
        self.assertEqual(response.status_code, 413)
        self.assertIn('error', response.get_json())

    def test_traversal_filename_is_handled(self):
        data = json.dumps([{'timestamp': TS, 'source': 'network'}]).encode()
        self.assertEqual(self.upload('../../evil.json', data).status_code, 200)

    def test_event_api_accepts_good_and_rejects_bad_records(self):
        response = self.client.post('/api/ingest/events', json={'events': [
            {'timestamp': TS, 'source': 'network', 'src_ip': '10.0.0.1'},
            {'source': 'network'},
            'junk',
        ]})
        body = response.get_json()
        self.assertEqual((body['stored'], body['rejected']), (1, 2))

    def test_event_api_refuses_non_list(self):
        self.assertEqual(self.client.post('/api/ingest/events', json={'a': 1}).status_code, 400)
        self.assertEqual(self.client.post('/api/ingest/events', data='nope').status_code, 400)

    def test_ioc_import_then_match(self):
        report = self.client.post('/api/iocs', json=[{'ioc_type': 'ip', 'value': '198.51.100.123', 'source': 't'}]).get_json()
        self.assertEqual(report['added'], 1)
        body = self.client.post('/api/ingest/events', json=[
            {'timestamp': TS, 'source': 'network', 'src_ip': '10.0.0.1', 'dst_ip': '198.51.100.123'}]).get_json()
        self.assertEqual(body['detection']['alerts_created'], 1)

    def test_ioc_import_refuses_non_list(self):
        self.assertEqual(self.client.post('/api/iocs', json={'x': 1}).status_code, 400)


class ViewApiTests(ApiTestCase):
    """The dashboard's data sources: every number it shows must be computed from stored data"""

    def setUp(self):
        super().setUp()
        self.outcome = self.client.post('/api/simulate/multi_stage').get_json()['outcome']

    def test_overview_counts_match_the_stored_rows(self):
        body = self.client.get('/api/overview?minutes=60').get_json()
        alerts = models.get_recent_alerts(1000)
        self.assertEqual(sum(body['alerts_by_severity'].values()), len(alerts))
        self.assertEqual(sum(body['alerts_by_type'].values()), len(alerts))
        self.assertEqual(sum(r['alerts'] for r in body['top_rules']), min(len(alerts), sum(r['alerts'] for r in body['top_rules'])))
        charted = sum(point['network'] + point['endpoint'] + point['application'] for point in body['timeline'])
        self.assertEqual(charted, body['events_in_range'])
        # All 44 arrived just now, including the 9 whose own timestamps are baseline history
        self.assertEqual(body['events_in_range'], 44)

    def test_the_chart_and_its_total_agree_while_logs_keep_arriving(self):
        stop = threading.Event()

        def keep_inserting():
            while not stop.is_set():
                models.batch_insert_logs([normalize_log({'source': 'network', 'src_ip': '10.0.0.1'}, 'network', origin='live')])

        writer = threading.Thread(target=keep_inserting)
        writer.start()
        try:
            for _ in range(60):
                body = models.get_overview(60)
                charted = sum(point['network'] + point['endpoint'] + point['application'] for point in body['timeline'])
                self.assertEqual(charted, body['events_in_range'])
        finally:
            stop.set()
            writer.join()

    def test_overview_on_an_empty_database_is_all_zeros(self):
        TempDbTestCase.setUp(self)
        for minutes in (0, 15, 60, 360, 1440):
            body = self.client.get(f'/api/overview?minutes={minutes}').get_json()
            self.assertEqual(body['events_in_range'], 0)
            self.assertEqual(body['top_rules'], [])

    def test_overview_rejects_other_ranges(self):
        self.assertEqual(self.client.get('/api/overview?minutes=7').status_code, 400)

    def test_an_old_log_counts_when_it_arrives_not_when_it_was_written(self):
        self.client.post('/api/ingest/events', json=[{'timestamp': '2020-01-01T00:00:00Z', 'source': 'network'}])
        self.assertEqual(self.client.get('/api/overview?minutes=60').get_json()['events_in_range'], 45)
        self.assertEqual(self.client.get('/api/overview?minutes=0').get_json()['events_in_range'], 45)

    def test_event_search_and_filters(self):
        logs = lambda query: self.client.get('/api/logs?limit=1000&' + query).get_json()
        self.assertEqual(len(logs('source=network')), 19)
        self.assertTrue(all(log['event_type'] == 'process_start' for log in logs('event_type=process_start')))
        self.assertEqual(len(logs('q=psexec')), 1)
        self.assertEqual(logs('origin=upload'), [])
        self.assertTrue(all(log['detections'] for log in logs('detected=1')))
        self.assertEqual(logs('q=%25'), [])

    def test_event_paging_returns_older_events(self):
        first = self.client.get('/api/logs?limit=5').get_json()
        older = self.client.get(f"/api/logs?limit=5&before_id={first[-1]['id']}").get_json()
        self.assertTrue(all(log['id'] < first[-1]['id'] for log in older))

    def test_event_detail_has_raw_record(self):
        log_id = self.client.get('/api/logs?q=psexec').get_json()[0]['id']
        detail = self.client.get(f'/api/logs/{log_id}').get_json()
        self.assertEqual(detail['raw_event']['process_name'], 'psexec.exe')
        self.assertEqual(detail['detections'][0]['rule_id'], 'IOA-010')
        self.assertEqual(self.client.get('/api/logs/999999').status_code, 404)

    def test_facets_come_from_the_data(self):
        facets = self.client.get('/api/logs/facets').get_json()
        self.assertEqual(facets['origins'], ['simulation'])
        self.assertIn('process_start', facets['event_types'])

    def test_alert_filters(self):
        alerts = lambda query: self.client.get('/api/alerts?' + query).get_json()
        self.assertTrue(all(a['severity'] == 'HIGH' for a in alerts('severity=HIGH')))
        self.assertEqual([a['rule_id'] for a in alerts('detection_type=IOC')], ['IOC-IP'])
        self.assertEqual([a['rule_id'] for a in alerts('q=psexec')], ['IOA-010'])

    def test_incident_filters_and_sort(self):
        incidents = lambda query: self.client.get('/api/incidents?' + query).get_json()
        self.assertEqual(len(incidents('status=OPEN')), 1)
        self.assertEqual(incidents('status=RESOLVED'), [])
        self.assertEqual(len(incidents('q=web-01')), 1)
        self.client.post('/api/simulate/port_scan')
        ranked = incidents('sort=risk')
        self.assertGreaterEqual(ranked[0]['risk_score'], ranked[1]['risk_score'])
        high_risk = self.client.get('/api/stats').get_json()['high_risk_incidents']
        self.assertEqual(len(incidents('risk=HIGH_PLUS')), high_risk)

    def test_rule_list_reports_real_activity(self):
        rules = {r['id']: r for r in self.client.get('/api/rules').get_json()['rules']}
        self.assertEqual(rules['IOA-001']['alerts'], 1)
        self.assertEqual(rules['IOA-006']['alerts'], 0)
        self.assertIsNone(rules['IOA-006']['last_fired'])

    def test_indicator_list_reports_real_matches(self):
        indicators = {i['value']: i for i in self.client.get('/api/iocs').get_json()}
        self.assertEqual(indicators['198.51.100.77']['alerts'], 1)
        self.assertEqual(indicators['203.0.113.99']['alerts'], 0)

    def test_simulation_validation_summary(self):
        self.client.post('/api/simulate/benign')
        validation = self.client.get('/api/simulate').get_json()['validation']
        self.assertEqual(validation['runs'], 2)
        self.assertEqual(validation['expected_detections'], 11)
        self.assertEqual((validation['missed_detections'], validation['unexpected_detections']), (0, 0))
        self.assertEqual((validation['benign_runs'], validation['benign_runs_with_alerts']), (1, 0))

    def test_incident_detail_includes_potential_impact(self):
        detail = self.client.get(f"/api/incidents/{self.outcome['incident_ids'][0]}").get_json()
        self.assertIn('Exfiltration', [i['tactic'] for i in detail['potential_impact']])


class SecurityTests(ApiTestCase):

    def test_cross_origin_writes_are_refused(self):
        for path in ('/api/simulate/brute_force', '/api/block', '/api/ingest/events', '/api/iocs'):
            response = self.client.post(path, json=[], headers={'Origin': 'https://evil.example'})
            self.assertEqual(response.status_code, 403, path)
        self.assertEqual(models.get_total_log_count(), 0)

    def test_same_origin_writes_are_allowed(self):
        response = self.client.post('/api/simulate/benign', headers={'Origin': 'http://localhost'})
        self.assertEqual(response.status_code, 200)

    def test_block_validates_the_address(self):
        for bad in ('null', 'None', '', '1.2.3', "1.1.1.1'; DROP TABLE logs;--"):
            self.assertEqual(self.client.post('/api/block', json={'ip': bad}).status_code, 400, bad)
        self.assertEqual(self.client.post('/api/block', json={}).status_code, 400)
        self.assertEqual(self.client.get('/api/blocklist').get_json(), [])

    def test_block_records_and_says_it_changes_no_firewall(self):
        body = self.client.post('/api/block', json={'ip': '198.51.100.9'}).get_json()
        self.assertIn('blocklist', body['status'])
        self.assertEqual(self.client.get('/api/stats').get_json()['blocked_ips'], 1)

    def test_ticket_validates_the_incident_id(self):
        self.assertEqual(self.client.post('/api/ticket', json={'incident_id': 'x'}).status_code, 400)
        self.assertEqual(self.client.post('/api/ticket', json={'incident_id': 1}).status_code, 200)

    def test_sql_metacharacters_in_filters_are_harmless(self):
        self.assertEqual(self.client.get("/api/logs?source=' OR 1=1 --").get_json(), [])
        self.assertEqual(self.client.get("/api/alerts?severity=' OR 1=1 --").get_json(), [])

    def test_secret_key_is_not_the_old_hardcoded_value(self):
        self.assertNotEqual(allsafe.app.config['SECRET_KEY'], 'security_monitoring_secret_key')


def models_log(i):
    from utils.normalizer import normalize_log
    return normalize_log({'timestamp': TS, 'event_id': f'e{i}'}, 'network')


if __name__ == '__main__':
    unittest.main()
