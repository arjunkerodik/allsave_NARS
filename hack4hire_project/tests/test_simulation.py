import unittest

import models
from tests.helpers import TempDbTestCase
from utils.correlation_engine import CorrelationEngine
from utils.investigation import get_incident_detail
from utils.ioc_engine import load_synthetic_feed
from utils.simulator import SCENARIOS, AttackSimulator


class ScenarioTests(TempDbTestCase):
    """Each scenario runs through the real engine and is compared with its recorded ground truth"""

    def setUp(self):
        super().setUp()
        load_synthetic_feed()
        self.engine = CorrelationEngine()
        self.simulator = AttackSimulator()

    def run_scenario(self, name):
        run = self.simulator.run_scenario(name)
        self.engine.process_new_events()
        return models.get_simulation_outcome(run['run_id'])

    def test_every_scenario_fires_exactly_its_expected_rules(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                TempDbTestCase.setUp(self)
                load_synthetic_feed()
                self.engine = CorrelationEngine()
                outcome = self.run_scenario(name)
                self.assertEqual(outcome['missed_rules'], [])
                self.assertEqual(outcome['unexpected_rules'], [])

    def test_all_required_scenarios_exist(self):
        required = {'brute_force', 'credential_abuse', 'port_scan', 'privilege_escalation', 'lateral',
                    'suspicious_process', 'exfil', 'multi_stage', 'benign'}
        self.assertTrue(required <= set(SCENARIOS))

    def test_scenarios_only_use_reserved_addresses(self):
        import ipaddress
        for name, definition in SCENARIOS.items():
            for _, _, fields in definition['build']():
                for key in ('src_ip', 'dst_ip'):
                    if fields.get(key):
                        address = ipaddress.ip_address(fields[key])
                        documentation = any(address in ipaddress.ip_network(n) for n in
                                            ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))
                        self.assertTrue(address.is_private or documentation, (name, fields[key]))

    def test_events_carry_ground_truth_labels(self):
        run = self.simulator.run_scenario('brute_force')
        logs = models.get_recent_logs(50)
        self.assertEqual(len(logs), run['event_count'])
        self.assertTrue(all(log['origin'] == 'simulation' and log['ingest_batch'] == run['run_id'] for log in logs))
        self.assertTrue(all(log['event_id'].startswith(run['run_id']) for log in logs))

    def test_all_three_sources_are_normalized(self):
        self.run_scenario('multi_stage')
        self.assertEqual(set(models.get_log_counts()), {'application', 'endpoint', 'network'})

    def test_multi_stage_is_one_incident_with_the_expected_story(self):
        outcome = self.run_scenario('multi_stage')
        self.assertEqual(len(outcome['incident_ids']), 1)
        self.assertEqual(len(models.get_recent_incidents()), 1)

        detail = get_incident_detail(outcome['incident_ids'][0])
        incident = detail['incident']
        self.assertEqual(incident['severity'], 'CRITICAL')
        self.assertEqual(incident['source_ip'], '203.0.113.50')
        self.assertIn('Multi-Stage Attack on web-01', incident['title'])
        self.assertGreaterEqual(incident['confidence'], 90)
        self.assertEqual(incident['risk_level'], 'CRITICAL')
        self.assertTrue(incident['remediation'])

        tactics = [t['tactic'] for t in incident['mitre']]
        for expected in ('Credential Access', 'Privilege Escalation', 'Persistence', 'Lateral Movement', 'Exfiltration'):
            self.assertIn(expected, tactics)

        # The timeline reads in attack order
        order = [entry['rule_ids'][0] for entry in detail['timeline'] if entry['rule_ids']]
        positions = [order.index(rule) for rule in ('IOA-001', 'IOA-003', 'IOA-004', 'IOA-009', 'IOA-016', 'IOA-007')]
        self.assertEqual(positions, sorted(positions))

        ioc = next(a for a in detail['alerts'] if a['rule_id'] == 'IOC-IP')
        self.assertEqual(ioc['evidence']['matched_indicator'], '198.51.100.77')
        self.assertEqual(incident['score_breakdown']['risk']['value'], incident['risk_score'])

    def test_benign_activity_raises_nothing(self):
        outcome = self.run_scenario('benign')
        self.assertEqual(outcome['fired_rules'], [])
        self.assertEqual(models.get_recent_alerts(), [])
        self.assertEqual(models.get_recent_incidents(), [])

    def test_benign_activity_stays_separate_from_a_concurrent_attack(self):
        self.run_scenario('multi_stage')
        self.run_scenario('benign')
        self.assertEqual(len(models.get_recent_incidents()), 1)

    def test_different_scenarios_do_not_merge(self):
        self.run_scenario('brute_force')
        self.run_scenario('port_scan')
        self.run_scenario('webshell')
        self.assertEqual(len(models.get_recent_incidents()), 3)

    def test_repeated_benign_runs_never_add_up_to_an_alert(self):
        """Each run has 2 failed logins from one IP. Three runs must not look like a brute force."""
        for _ in range(5):
            self.assertEqual(self.run_scenario('benign')['fired_rules'], [])
        self.assertEqual(models.get_recent_alerts(), [])

    def test_each_rerun_gets_its_own_clean_incident(self):
        first = self.run_scenario('multi_stage')
        second = self.run_scenario('multi_stage')
        self.assertEqual((second['missed_rules'], second['unexpected_rules']), ([], []))
        self.assertEqual(len(second['incident_ids']), 1)
        self.assertNotEqual(first['incident_ids'], second['incident_ids'])
        # Same timeline as the first run, not two runs interleaved
        for outcome in (first, second):
            incident = get_incident_detail(outcome['incident_ids'][0])['incident']
            # Baseline history is in the run, but no alert cites it, so it is not in the incident
            self.assertEqual((incident['alert_count'], incident['event_count']), (11, 25))

    def test_synthetic_events_never_join_a_real_incident(self):
        from utils.normalizer import normalize_log
        real = [normalize_log({'timestamp': '2026-10-30T10:00:00Z', 'event_type': 'authentication_failure',
                               'src_ip': '203.0.113.10', 'hostname': 'app-01', 'user': 'admin',
                               'event_id': f'real-{i}'}, 'application') for i in range(5)]
        models.batch_insert_logs(real)
        self.engine.process_new_events()
        from datetime import datetime, timezone
        run = self.simulator.run_scenario('brute_force', end_time=datetime(2026, 10, 30, 10, 1, tzinfo=timezone.utc))
        self.engine.process_new_events()
        self.assertEqual(len(models.get_recent_incidents()), 2)
        self.assertEqual(models.get_simulation_outcome(run['run_id'])['fired_rules'], ['IOA-001', 'IOA-002'])

    def test_scenario_is_reproducible(self):
        first = [fields for _, _, fields in SCENARIOS['multi_stage']['build']()]
        self.assertEqual(first, [fields for _, _, fields in SCENARIOS['multi_stage']['build']()])

    def test_legacy_method_names_still_work(self):
        for method in ('simulate_brute_force', 'simulate_lateral_movement', 'simulate_exfiltration',
                       'simulate_c2_beaconing', 'simulate_webshell', 'simulate_cred_dump', 'simulate_account_creation'):
            self.assertIn('run_id', getattr(self.simulator, method)())


if __name__ == '__main__':
    unittest.main()
