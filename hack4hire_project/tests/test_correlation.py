import datetime
import unittest

import models
from tests.helpers import TempDbTestCase
from utils.correlation_engine import CorrelationEngine, link_score
from utils.investigation import build_timeline, get_incident_detail
from utils.ioc_engine import load_synthetic_feed
from utils.normalizer import normalize_log
from utils.risk_engine import load_scoring_config, score_incident

BASE = datetime.datetime(2026, 1, 2, 3, 0, 0, tzinfo=datetime.timezone.utc)
SETTINGS = load_scoring_config()['correlation']


def at(seconds):
    return (BASE + datetime.timedelta(seconds=seconds)).isoformat()


def failures(start, ip, host, user='admin', count=5):
    return [{'timestamp': at(start + i), 'source': 'application', 'event_type': 'authentication_failure',
             'src_ip': ip, 'hostname': host, 'user': user} for i in range(count)]


def process(offset, host, user, name, command):
    return {'timestamp': at(offset), 'source': 'endpoint', 'event_type': 'process_start', 'hostname': host,
            'user': user, 'process_name': name, 'command_line': command}


class EngineHarness(TempDbTestCase):

    def setUp(self):
        super().setUp()
        self.engine = CorrelationEngine()

    def ingest(self, events):
        models.batch_insert_logs([normalize_log(dict(e), e.get('source', 'application')) for e in events])
        return self.engine.process_new_events()

    def incidents(self):
        return models.get_recent_incidents(100)


class CorrelationTests(EngineHarness):

    def test_related_stages_become_one_incident(self):
        summary = self.ingest(failures(0, '203.0.113.1', 'web-01') + [
            {'timestamp': at(10), 'event_type': 'authentication_success', 'src_ip': '203.0.113.1',
             'hostname': 'web-01', 'user': 'admin'},
            process(60, 'web-01', 'admin', 'net.exe', 'net user backdoor x /add'),
            {'timestamp': at(120), 'source': 'network', 'hostname': 'web-01', 'src_ip': '10.0.0.5',
             'dst_ip': '198.51.100.5', 'dst_port': 443, 'bytes': 80 * 1024 * 1024},
        ])
        self.assertEqual(len(summary['incidents_created']), 1)
        incident = self.incidents()[0]
        self.assertEqual(incident['alert_count'], 4)
        self.assertEqual(incident['incident_uid'], f"INC-{incident['id']:06d}")
        self.assertIn('Multi-Stage Attack', incident['title'])

    def test_unrelated_simultaneous_activity_stays_separate(self):
        self.ingest(failures(0, '203.0.113.1', 'web-01') + failures(0, '203.0.113.2', 'mail-07', user='carol'))
        self.assertEqual(len(self.incidents()), 2)

    def test_same_time_alone_never_correlates(self):
        self.ingest(failures(0, '203.0.113.1', 'web-01') +
                    [process(1, 'db-09', 'dave', 'mimikatz.exe', 'mimikatz.exe')])
        self.assertEqual(len(self.incidents()), 2)

    def test_shared_external_destination_alone_does_not_link(self):
        conn = lambda src, host: {'timestamp': at(0), 'source': 'network', 'src_ip': src, 'hostname': host,
                                  'dst_ip': '198.51.100.5', 'dst_port': 4444}
        self.ingest([conn('10.0.0.1', 'pc-1'), conn('10.0.0.2', 'pc-2')])
        self.assertEqual(len(self.incidents()), 2)

    def test_related_activity_outside_the_window_is_a_new_incident(self):
        self.ingest(failures(0, '203.0.113.1', 'web-01'))
        self.ingest(failures(100000, '203.0.113.1', 'web-01'))
        self.assertEqual(len(self.incidents()), 2)

    def test_service_accounts_and_loopback_do_not_link_incidents(self):
        score, _ = link_score({'user': ['SYSTEM'], 'src_ip': ['127.0.0.1']},
                              {'user': ['SYSTEM'], 'src_ip': ['127.0.0.1']}, SETTINGS)
        self.assertEqual(score, 0)

    def test_pivot_links_a_host_that_was_previously_a_destination(self):
        score, reasons = link_score({'src_ip': ['10.0.0.9']}, {'dst_ip': ['10.0.0.9']}, SETTINGS)
        self.assertGreaterEqual(score, SETTINGS['min_link_score'])
        self.assertEqual(reasons[0]['type'], 'pivot')

    def test_replaying_engine_does_not_duplicate_incidents(self):
        """The old engine re-fired every 60s while logs stayed in its 2-minute window"""
        self.ingest(failures(0, '203.0.113.1', 'web-01'))
        for _ in range(3):
            self.assertEqual(self.engine.process_new_events()['events'], 0)
        self.assertEqual(len(self.incidents()), 1)
        self.assertEqual(len(models.get_recent_alerts()), 1)

    def test_more_events_update_the_same_incident(self):
        self.ingest(failures(0, '203.0.113.1', 'web-01'))
        summary = self.ingest(failures(10, '203.0.113.1', 'web-01'))
        self.assertEqual(summary['incidents_created'], [])
        self.assertEqual(self.incidents()[0]['event_count'], 10)

    def test_cursor_survives_a_restart(self):
        self.ingest(failures(0, '203.0.113.1', 'web-01'))
        self.engine = CorrelationEngine()
        self.assertEqual(self.engine.process_new_events()['events'], 0)

    def test_low_severity_alert_alone_opens_no_incident(self):
        self.ingest([{'timestamp': at(0), 'source': 'endpoint', 'event_type': 'file_access', 'hostname': 'h1',
                      'user': 'u1', 'file_path': 'C:\\data\\holiday.zip'}])
        self.assertEqual(len(models.get_recent_alerts()), 1)
        self.assertEqual(self.incidents(), [])

    def test_low_severity_alert_is_adopted_when_a_related_incident_appears(self):
        self.ingest([{'timestamp': at(0), 'source': 'endpoint', 'event_type': 'file_access', 'hostname': 'web-01',
                      'user': 'u1', 'file_path': 'C:\\data\\finance.zip'}])
        self.ingest(failures(60, '203.0.113.1', 'web-01'))
        self.assertEqual(self.incidents()[0]['alert_count'], 2)

    def test_events_without_a_valid_timestamp_do_not_stall_the_engine(self):
        with models.get_db_connection() as conn:
            conn.execute("INSERT INTO logs (source, event_type, timestamp, event_id) VALUES ('network','x','garbage','bad-1')")
            conn.commit()
        summary = self.engine.process_new_events()
        self.assertEqual(summary['events'], 1)
        self.assertEqual(self.ingest(failures(0, '203.0.113.1', 'web-01'))['alerts_created'], 1)

    def test_broken_rule_does_not_stop_other_rules(self):
        self.engine.detection.rules.insert(0, dict(self.engine.detection.rules[0], id='BROKEN', group_by=None))
        self.assertEqual(self.ingest(failures(0, '203.0.113.1', 'web-01'))['alerts_created'], 1)


class ScoringTests(unittest.TestCase):

    def alert(self, rule, severity, confidence, link=None, detection='IOA', tactic='Credential Access', **entities):
        return {'rule_id': rule, 'rule_name': rule, 'severity': severity, 'confidence': confidence,
                'correlation_score': link, 'detection_type': detection, 'entities': entities,
                'first_seen_ts': 0, 'mitre': [{'tactic': tactic}] if tactic else []}

    def test_severity_confidence_and_risk_are_separate_values(self):
        weak_critical = score_incident([self.alert('a', 'CRITICAL', 10)])
        strong_medium = score_incident([self.alert('b', 'MEDIUM', 95)])
        self.assertEqual(weak_critical['severity'], 'CRITICAL')
        self.assertEqual(weak_critical['confidence'], 10)
        self.assertEqual(strong_medium['severity'], 'MEDIUM')
        self.assertEqual(strong_medium['confidence'], 95)

    def test_exact_scoring_from_documented_config(self):
        # Severity 25 x 0.5 = 12.5. Evidence 25 x 0.70 = 17.5. One rule: 20 x 0.8 x 2/3 = 10.7. Total 40.7.
        result = score_incident([self.alert('a', 'MEDIUM', 70)])
        self.assertEqual((result['confidence'], result['risk_score'], result['risk_level']), (70, 41, 'MEDIUM'))
        self.assertEqual(result['score_breakdown']['risk']['subtotal'], 40.7)

    def test_every_component_has_a_reason_and_points_add_up(self):
        risk = score_incident([self.alert('a', 'HIGH', 80), self.alert('b', 'HIGH', 80, link=0.8, tactic='Exfiltration')])['score_breakdown']['risk']
        self.assertTrue(all(c['reason'] for c in risk['components']))
        self.assertAlmostEqual(sum(c['points'] for c in risk['components']), risk['subtotal'], places=1)
        self.assertEqual({c['factor'] for c in risk['components']},
                         {'severity', 'evidence_confidence', 'ioc_ioa_signals', 'behavioral_anomalies', 'asset_importance', 'attack_progression'})

    def test_no_behavioral_signal_says_so_and_adds_nothing(self):
        risk = score_incident([self.alert('a', 'HIGH', 80)])['score_breakdown']['risk']
        behavior = next(c for c in risk['components'] if c['factor'] == 'behavioral_anomalies')
        self.assertEqual(behavior['points'], 0)
        self.assertIn('No behavioral anomaly', behavior['reason'])

    def test_a_behavioral_anomaly_raises_risk(self):
        base = score_incident([self.alert('a', 'HIGH', 80)])['risk_score']
        both = score_incident([self.alert('a', 'HIGH', 80), self.alert('u', 'MEDIUM', 60, link=0.8, detection='UEBA', tactic=None)])['risk_score']
        self.assertGreater(both, base)

    def test_risk_says_it_is_a_priority_not_a_probability(self):
        self.assertIn('not the probability', score_incident([self.alert('a', 'HIGH', 80)])['score_breakdown']['risk']['note'])

    def test_repeats_of_one_rule_do_not_inflate_confidence(self):
        once = score_incident([self.alert('a', 'HIGH', 70)])
        many = score_incident([self.alert('a', 'HIGH', 70) for _ in range(5)])
        self.assertEqual(once['confidence'], many['confidence'])

    def test_independent_rules_raise_confidence(self):
        self.assertGreater(score_incident([self.alert('a', 'HIGH', 70), self.alert('b', 'HIGH', 70, link=0.8)])['confidence'], 70)

    def test_weak_link_counts_less(self):
        strong = score_incident([self.alert('a', 'HIGH', 70), self.alert('b', 'HIGH', 70, link=1.0)])
        weak = score_incident([self.alert('a', 'HIGH', 70), self.alert('b', 'HIGH', 70, link=0.5)])
        self.assertGreater(strong['confidence'], weak['confidence'])

    def test_ioc_and_asset_and_progression_raise_risk(self):
        base = score_incident([self.alert('a', 'HIGH', 80)])['risk_score']
        ioc = score_incident([self.alert('a', 'HIGH', 80), self.alert('i', 'MEDIUM', 70, link=0.8, detection='IOC', tactic=None)])['risk_score']
        asset = score_incident([self.alert('a', 'HIGH', 80, hostname=['db-01'])])['risk_score']
        self.assertGreater(ioc, base)
        self.assertGreater(asset, base)

    def test_risk_never_exceeds_100(self):
        tactics = ['Credential Access', 'Execution', 'Persistence', 'Lateral Movement', 'Exfiltration']
        alerts = [self.alert(f'r{i}', 'CRITICAL', 95, link=1.0, tactic=t, hostname=['db-01']) for i, t in enumerate(tactics)]
        alerts += [self.alert('i', 'HIGH', 100, link=1.0, detection='IOC', tactic=None), self.alert('u', 'HIGH', 100, link=1.0, detection='UEBA', tactic=None)]
        self.assertEqual(score_incident(alerts)['risk_score'], 100)


class InvestigationTests(EngineHarness):

    def test_detail_links_events_rules_and_timeline(self):
        load_synthetic_feed()
        self.ingest(failures(0, '203.0.113.1', 'web-01') + [
            {'timestamp': at(10), 'event_type': 'authentication_success', 'src_ip': '203.0.113.1',
             'hostname': 'web-01', 'user': 'admin'},
            {'timestamp': at(30), 'source': 'network', 'hostname': 'web-01', 'src_ip': '10.0.0.5',
             'dst_ip': '198.51.100.77', 'dst_port': 443, 'bytes': 100},
        ])
        detail = get_incident_detail(self.incidents()[0]['id'])
        self.assertEqual({a['rule_id'] for a in detail['alerts']}, {'IOA-001', 'IOA-002', 'IOC-IP'})
        timeline = detail['timeline']
        self.assertEqual([t['count'] for t in timeline], [5, 1, 1])
        self.assertEqual(timeline[0]['rule_ids'], ['IOA-001', 'IOA-002'])
        self.assertEqual(timeline[-1]['rule_ids'], ['IOC-IP'])
        self.assertEqual(detail['related_events_total'], 7)
        self.assertEqual(detail['related_events'][0]['raw_event']['src_ip'], '203.0.113.1')
        reasons = {r['type'] for a in detail['alerts'] for r in (a['correlation_reasons'] or [])}
        self.assertIn('shared_entity', reasons)

    def test_unknown_incident(self):
        self.assertIsNone(get_incident_detail(999))

    def test_timeline_does_not_merge_different_activity(self):
        events = [{'id': 1, 'ts_epoch': 1, 'event_type': 'a', 'src_ip': 'x'},
                  {'id': 2, 'ts_epoch': 2, 'event_type': 'b', 'src_ip': 'x'},
                  {'id': 3, 'ts_epoch': 3, 'event_type': 'a', 'src_ip': 'x'}]
        self.assertEqual(len(build_timeline(events, {})), 3)


if __name__ == '__main__':
    unittest.main()
