import io
import json
import re
import time
import unittest
from unittest import mock

import models
from tests.test_api import ApiTestCase
from utils import job_runner as job_module
from utils.dataset_engine import prepare_dataset
from utils.dataset_generator import PROFILES, expected_rules_for, generate_dataset
from utils.log_ingest import UploadRejected
from utils.report_engine import render_pdf
from utils.risk_engine import score_incident, validate_settings
from utils.simulator import SCENARIOS

CSV_HEADER = 'event_time,source,src_ip,user,action,label\n'


def csv_upload(text, name='data.csv', **form):
    return {'file': (io.BytesIO(text.encode()), name), **form}


class JobTestCase(ApiTestCase):

    def setUp(self):
        super().setUp()
        # A job from one test must not still be holding the slot in the next
        import app as allsafe
        self.runner = allsafe.job_runner

    def start(self, scenario, **params):
        return self.client.post('/api/simulations', json={'scenario': scenario, 'speed': 'instant', **params})

    def wait_for_simulation(self, run_id, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            view = self.client.get(f'/api/simulations/{run_id}').get_json()
            if not view['active'] and view['status'] not in ('RUNNING', 'PAUSED'):
                return view
            time.sleep(0.05)
        self.fail(f'Simulation {run_id} did not finish')

    def wait_for_dataset(self, dataset_id, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            dataset = self.client.get(f'/api/datasets/{dataset_id}').get_json()
            if dataset['status'] != 'PROCESSING' and not dataset['active']:
                return dataset
            time.sleep(0.05)
        self.fail(f'Dataset {dataset_id} did not finish')

    def run_simulation(self, scenario, **params):
        response = self.start(scenario, **params)
        self.assertEqual(response.status_code, 202, response.get_json())
        return self.wait_for_simulation(response.get_json()['run_id'])


class SimulationRunTests(JobTestCase):

    def test_multi_stage_goes_through_the_real_pipeline(self):
        view = self.run_simulation('multi_stage')
        self.assertEqual(view['status'], 'COMPLETED')
        self.assertEqual((view['missed_rules'], view['unexpected_rules']), ([], []))
        self.assertEqual(view['processed_count'], view['event_count'])
        self.assertEqual(view['failed_count'], 0)
        self.assertEqual(len(view['incidents']), 1)
        self.assertEqual(view['incidents'][0]['risk_level'], 'CRITICAL')
        # Stored as ordinary logs, with alerts citing them: nothing was inserted around the pipeline
        logs = self.client.get(f"/api/simulations/{view['run_id']}/events?limit=1000").get_json()
        self.assertEqual(len(logs), view['event_count'])
        self.assertTrue(all(log['origin'] == 'simulation' for log in logs))
        detail = self.client.get(f"/api/incidents/{view['incidents'][0]['id']}").get_json()
        self.assertTrue(all(alert['evidence']['sample_events'] for alert in detail['alerts']))

    def test_results_hold_everything_the_lab_displays(self):
        view = self.run_simulation('multi_stage')
        for key in ('run_id', 'started_at', 'completed_at', 'event_count', 'processed_count', 'failed_count',
                    'alert_count', 'alert_risk_distribution', 'status', 'name'):
            self.assertIsNotNone(view.get(key), key)
        self.assertEqual(view['metrics']['event_level']['false_positives'], 0)
        self.assertIsNotNone(view['metrics']['detection_latency_seconds'])

    def test_a_second_start_is_refused_while_one_runs(self):
        with mock.patch.dict(job_module.SPEEDS, {'slow': 0.2}):
            first = self.start('multi_stage', speed='slow')
            self.assertEqual(first.status_code, 202)
            second = self.start('brute_force')
            self.assertEqual(second.status_code, 409)
            self.assertIn('still running', second.get_json()['error'])
            run_id = first.get_json()['run_id']
            self.client.post(f'/api/simulations/{run_id}/stop')
            self.wait_for_simulation(run_id)

    def test_stop_keeps_what_was_processed_and_says_so(self):
        with mock.patch.dict(job_module.SPEEDS, {'slow': 0.2}):
            run_id = self.start('multi_stage', speed='slow').get_json()['run_id']
            time.sleep(0.3)
            self.assertEqual(self.client.post(f'/api/simulations/{run_id}/stop').status_code, 200)
            view = self.wait_for_simulation(run_id)
        self.assertEqual(view['status'], 'STOPPED')
        self.assertLess(view['processed_count'], view['event_count'])

    def test_pause_holds_the_run_until_resume(self):
        with mock.patch.dict(job_module.SPEEDS, {'slow': 0.1}):
            run_id = self.start('multi_stage', speed='slow').get_json()['run_id']
            self.client.post(f'/api/simulations/{run_id}/pause')
            time.sleep(0.3)
            held = self.client.get(f'/api/simulations/{run_id}').get_json()
            self.assertEqual(held['status'], 'PAUSED')
            time.sleep(0.4)
            self.assertEqual(self.client.get(f'/api/simulations/{run_id}').get_json()['processed_count'], held['processed_count'])
            self.client.post(f'/api/simulations/{run_id}/resume')
            view = self.wait_for_simulation(run_id)
        self.assertEqual((view['status'], view['processed_count']), ('COMPLETED', view['event_count']))

    def test_controls_refuse_a_run_that_is_not_active(self):
        view = self.run_simulation('benign')
        self.assertEqual(self.client.post(f"/api/simulations/{view['run_id']}/stop").status_code, 409)
        self.assertEqual(self.client.post('/api/simulations/nope/stop').status_code, 409)
        self.assertEqual(self.client.post(f"/api/simulations/{view['run_id']}/explode").status_code, 404)

    def test_bad_parameters_are_refused(self):
        self.assertEqual(self.start('nope').status_code, 400)
        self.assertEqual(self.start('benign', intensity='extreme').status_code, 400)
        self.assertEqual(self.start('benign', speed='warp').status_code, 400)
        self.assertEqual(self.start('benign', background_events=-1).status_code, 400)
        self.assertEqual(self.start('benign', background_events=999999).status_code, 400)
        self.assertEqual(self.start('benign', seed='abc').status_code, 400)

    def test_background_noise_does_not_change_what_an_attack_detects(self):
        view = self.run_simulation('multi_stage', background_events=300, seed=7)
        self.assertEqual((view['missed_rules'], view['unexpected_rules']), ([], []))
        self.assertEqual(len(view['incidents']), 1)
        self.assertEqual(view['metrics']['event_level']['false_positives'], 0)
        self.assertEqual(view['event_count'], 44 + 300)

    def test_an_internal_failure_is_reported_and_frees_the_slot(self):
        with mock.patch.object(job_module, 'ingest_records', side_effect=RuntimeError('disk full at C:\\secret')):
            view = self.run_simulation('brute_force')
        self.assertEqual(view['status'], 'FAILED')
        self.assertIn('RuntimeError', view['error'])
        self.assertNotIn('secret', view['error'])
        self.assertEqual(self.start('benign').status_code, 202)
        self.wait_for_simulation(self.client.get('/api/simulations').get_json()['runs'][0]['run_id'])

    def test_a_restart_marks_unfinished_runs_as_interrupted(self):
        models.insert_simulation_run({'run_id': 'sim-cut', 'scenario': 'benign', 'is_malicious': False, 'expected_rules': [],
                                      'event_count': 5, 'started_at': '2026-01-01T00:00:00+00:00', 'status': 'RUNNING'})
        self.assertEqual(models.mark_interrupted_jobs(), 1)
        view = self.client.get('/api/simulations/sim-cut').get_json()
        self.assertEqual(view['status'], 'INTERRUPTED')
        self.assertIn('restarted', view['error'])

    def test_a_run_from_the_older_route_reports_its_counts(self):
        outcome = self.client.post('/api/simulate/brute_force').get_json()['outcome']
        view = self.client.get(f"/api/simulations/{outcome['run_id']}").get_json()
        self.assertEqual((view['status'], view['processed_count']), ('COMPLETED', view['event_count']))
        self.assertIsNotNone(view['completed_at'])

    def test_a_report_is_generated_when_a_run_completes(self):
        view = self.run_simulation('multi_stage')
        reports = [r for r in self.client.get('/api/reports').get_json() if r['subject_id'] == view['run_id']]
        self.assertEqual(len(reports), 1)


class EveryScenarioTests(JobTestCase):

    def test_each_scenario_produces_its_ground_truth(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                view = self.run_simulation(name)
                self.assertEqual(view['status'], 'COMPLETED')
                self.assertEqual((view['missed_rules'], view['unexpected_rules']), ([], []))

    def test_benign_activity_creates_nothing_across_seeds(self):
        for seed in (1, 2, 3):
            view = self.run_simulation('benign', background_events=400, seed=seed)
            self.assertEqual((view['alert_count'], view['incidents']), (0, []), f'seed {seed}')


class RiskTierTests(JobTestCase):
    """Part 10, test 3: one scenario in each tier, handled as the policy says"""

    def automation_steps(self, subject):
        return {step['step'] for step in models.get_automation_log(subject=subject)}

    def test_low_risk_is_enriched_automatically_and_opens_no_incident(self):
        view = self.run_simulation('low_signal')
        self.assertEqual((view['alert_risk_distribution'], view['incidents']), ({'LOW': 1}, []))
        alert = self.client.get(f"/api/simulations/{view['run_id']}/alerts").get_json()[0]
        self.assertEqual(self.automation_steps(f"alert:{alert['id']}"), {'enrich', 'group_duplicates', 'update_monitoring_record'})
        self.assertIn('risk:low', alert['tags'])

    def test_medium_risk_is_prioritized_without_notification(self):
        incident = self.run_simulation('port_scan')['incidents'][0]
        self.assertEqual((incident['risk_level'], incident['priority']), ('MEDIUM', 'P3'))
        self.assertIn('collect_evidence', self.automation_steps(f"incident:{incident['id']}"))
        self.assertIn('create_investigation_task', self.automation_steps(f"incident:{incident['id']}"))
        self.assertEqual(self.client.get('/api/notifications').get_json(), [])

    def assert_needs_approval(self, incident_id):
        actions = self.client.get(f'/api/incidents/{incident_id}/response-actions').get_json()
        disruptive = [action for action in actions if action['disruptive']]
        self.assertTrue(disruptive)
        self.assertTrue(all(action['status'] == 'PENDING' and action['expected_impact'] for action in disruptive))
        self.assertEqual(models.has_simulated_enforcement(disruptive[0]['id'], disruptive[0]['action_type'], disruptive[0]['target']), False)
        return disruptive

    def test_high_risk_notifies_and_waits_for_approval(self):
        incident = self.run_simulation('exfil')['incidents'][0]
        self.assertEqual((incident['risk_level'], incident['priority']), ('HIGH', 'P2'))
        self.assert_needs_approval(incident['id'])
        self.assertEqual([n['level'] for n in self.client.get('/api/notifications').get_json()], ['HIGH'])

    def test_critical_risk_notifies_and_waits_for_approval(self):
        incident = self.run_simulation('multi_stage')['incidents'][0]
        self.assertEqual((incident['risk_level'], incident['priority']), ('CRITICAL', 'P1'))
        self.assert_needs_approval(incident['id'])
        self.assertEqual([n['level'] for n in self.client.get('/api/notifications').get_json()], ['CRITICAL'])

    def test_every_automatic_step_is_in_the_audit_log(self):
        incident = self.run_simulation('multi_stage')['incidents'][0]
        audited = [e for e in models.get_audit_entries(limit=500, incident_id=incident['id']) if e['actor'] == 'automation']
        self.assertEqual({e['details'].get('step') for e in audited if e['action'] == 'automation_applied'},
                         self.automation_steps(f"incident:{incident['id']}"))
        self.assertIn('analyst_notified', {e['action'] for e in audited})

    def test_automation_never_runs_or_closes_anything(self):
        incident = self.run_simulation('multi_stage')['incidents'][0]
        actions = self.client.get(f"/api/incidents/{incident['id']}/response-actions").get_json()
        self.assertEqual({action['status'] for action in actions}, {'PENDING'})
        self.assertEqual(incident['status'], 'ACTIVE')
        self.assertEqual(self.client.get('/api/blocklist').get_json(), [])

    def test_marking_for_investigation_keeps_the_action_open(self):
        incident = self.run_simulation('multi_stage')['incidents'][0]
        action = self.assert_needs_approval(incident['id'])[0]
        path = f"/api/response-actions/{action['id']}"
        marked = self.client.post(f'{path}/decision', json={'decision': 'investigate', 'analyst': 'priya', 'reason': 'Need more logs'})
        self.assertEqual(marked.get_json()['status'], 'NEEDS_INVESTIGATION')
        self.assertEqual(self.client.post(f'{path}/execute', json={'analyst': 'priya'}).status_code, 409)
        self.assertEqual(self.client.post(f'{path}/decision', json={'decision': 'approve', 'analyst': 'priya'}).get_json()['status'], 'APPROVED')
        self.assertEqual(self.client.post(f'{path}/execute', json={'analyst': 'priya'}).get_json()['status'], 'EXECUTED')
        recorded = [e['action'] for e in models.get_audit_entries(limit=500, incident_id=incident['id'])]
        self.assertIn('response_marked_for_investigation', recorded)

    def test_a_lone_weak_indicator_is_never_critical(self):
        alert = {'rule_id': 'a', 'rule_name': 'a', 'severity': 'CRITICAL', 'confidence': 30, 'detection_type': 'IOA', 'entities': {}, 'mitre': []}
        self.assertNotIn(score_incident([alert])['risk_level'], ('CRITICAL', 'HIGH'))


class RiskSettingsTests(JobTestCase):

    def settings(self, **levels):
        return {'analyst': 'priya', 'weights': {'severity': 25, 'evidence_confidence': 25, 'ioc_ioa_signals': 20, 'behavioral_anomalies': 15, 'attack_progression': 15},
                'levels': {'CRITICAL': 90, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 0, **levels}}

    def test_settings_are_shown_with_the_policy(self):
        body = self.client.get('/api/risk').get_json()
        self.assertEqual(body['levels'], {'CRITICAL': 90, 'HIGH': 70, 'MEDIUM': 40, 'LOW': 0})
        self.assertEqual(sum(body['weights'].values()), 100)
        self.assertEqual(set(body['policy']), {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'})
        self.assertIn('block_test_ip', [a['action'] for a in body['approval_required_actions']])

    def test_new_thresholds_rescore_open_incidents_and_are_audited(self):
        incident = self.run_simulation('port_scan')['incidents'][0]
        self.assertEqual(incident['risk_level'], 'MEDIUM')
        response = self.client.put('/api/risk/settings', json=self.settings(CRITICAL=60, HIGH=50, MEDIUM=30))
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['incidents_rescored'], 1)
        self.assertEqual(self.client.get(f"/api/incidents/{incident['id']}").get_json()['incident']['risk_level'], 'HIGH')
        self.assertIn('risk_settings_changed', [e['action'] for e in models.get_audit_entries()])

    def test_lowered_threshold_changes_the_tier_of_an_open_incident(self):
        incident = self.run_simulation('exfil')['incidents'][0]
        self.client.put('/api/risk/settings', json=self.settings(CRITICAL=75, HIGH=60, MEDIUM=30))
        self.assertEqual(self.client.get(f"/api/incidents/{incident['id']}").get_json()['incident']['risk_level'], 'CRITICAL')

    def test_saved_settings_survive_a_restart(self):
        self.client.put('/api/risk/settings', json=self.settings(CRITICAL=88))
        self.assertIn('"CRITICAL": 88', models.get_engine_state('risk_overrides'))

    def test_bad_settings_are_refused(self):
        bad = self.settings()
        bad['weights']['severity'] = 90
        self.assertEqual(self.client.put('/api/risk/settings', json=bad).status_code, 400)
        self.assertEqual(self.client.put('/api/risk/settings', json=self.settings(CRITICAL=10)).status_code, 400)
        no_name = self.settings()
        del no_name['analyst']
        self.assertEqual(self.client.put('/api/risk/settings', json=no_name).status_code, 400)
        self.assertEqual(self.client.put('/api/risk/settings', data='nope').status_code, 400)
        with self.assertRaises(ValueError):
            validate_settings({'weights': {}, 'levels': {}})

    def test_settings_changes_are_local_only(self):
        response = self.client.put('/api/risk/settings', json=self.settings(), environ_base={'REMOTE_ADDR': '10.0.0.9'})
        self.assertEqual(response.status_code, 403)


class DatasetValidationTests(unittest.TestCase):

    def prepare(self, text, name='data.csv', **kwargs):
        return prepare_dataset(name, text.encode(), **kwargs)

    def test_valid_rows_and_field_mapping(self):
        result = self.prepare('when,kind,who\n2026-01-02T03:04:05Z,application,bob\n',
                              mapping={'when': 'timestamp', 'kind': 'source', 'who': 'username'})
        self.assertEqual(result['summary']['valid_records'], 1)
        self.assertEqual(result['rows'][0]['raw']['username'], 'bob')

    def test_a_file_with_no_times_is_kept_with_a_warning(self):
        timeless = self.prepare('source,user\nnetwork,bob\n')
        self.assertEqual(timeless['summary']['valid_records'], 1)
        self.assertTrue(any('time' in warning for warning in timeless['summary']['warnings']))
        # A file where only some rows lack a time: those rows are refused, and say why
        mixed = self.prepare('timestamp,source\n2026-01-02T03:04:05Z,network\n,network\n')
        self.assertEqual((mixed['summary']['valid_records'], mixed['summary']['invalid_records']), (1, 1))
        self.assertIn('timestamp', mixed['invalid'][0]['errors'][0])

    def test_empty_and_unsupported_files_are_refused(self):
        with self.assertRaisesRegex(UploadRejected, 'empty'):
            self.prepare('')
        with self.assertRaisesRegex(UploadRejected, 'unsupported'):
            self.prepare('MZ', name='evil.exe')
        with self.assertRaisesRegex(UploadRejected, 'not valid JSON'):
            self.prepare('{broken', name='d.json')

    def test_each_invalid_row_says_why(self):
        result = self.prepare('timestamp,source,src_ip\n'
                              'not-a-date,network,10.0.0.1\n'
                              '2026-01-02T03:04:05Z,network,999.1.1.1\n'
                              '2026-01-02T03:04:05Z,martian,10.0.0.1\n'
                              '2026-01-02T03:04:06Z,network,10.0.0.1\n')
        self.assertEqual((result['summary']['total_rows'], result['summary']['valid_records'], result['summary']['invalid_records']), (4, 2, 2))
        reasons = ' '.join(reason for row in result['invalid'] for reason in row['errors'])
        for part in ('timestamp cannot be read', 'not an IP address'):
            self.assertIn(part, reasons)
        self.assertEqual([row['row'] for row in result['invalid']], [1, 2])

    def test_duplicates_are_skipped_and_counted(self):
        row = '2026-01-02T03:04:05Z,network,10.0.0.1\n'
        result = self.prepare('timestamp,source,src_ip\n' + row * 3)
        self.assertEqual((result['summary']['valid_records'], result['summary']['skipped_duplicates']), (1, 2))

    def test_labels_are_taken_out_before_detection_can_see_them(self):
        result = self.prepare('timestamp,source,user,label,attack_type\n2026-01-02T03:04:05Z,application,bob,malicious,brute\n')
        row = result['rows'][0]
        self.assertEqual((row['label'], row['attack_type']), ('malicious', 'brute'))
        self.assertNotIn('label', row['raw'])
        self.assertNotIn('attack_type', row['raw'])
        self.assertEqual(result['summary']['labels'], {'malicious': 1})

    def test_any_other_label_counts_as_an_attack_class(self):
        result = self.prepare('timestamp,source,label\n2026-01-02T03:04:05Z,network,spooky\n')
        self.assertEqual(result['summary']['invalid_records'], 0)
        self.assertEqual(result['summary']['labels'], {'malicious': 1})

    def test_malformed_files_are_refused_with_a_reason(self):
        with self.assertRaisesRegex(UploadRejected, 'not a text file'):
            prepare_dataset('data.csv', b'timestamp,source\n\xff\xfe\x00,network\n')
        with self.assertRaisesRegex(UploadRejected, 'array of objects'):
            self.prepare('12345', name='d.json')

    def test_a_header_with_no_rows_has_no_valid_records(self):
        result = self.prepare('timestamp,source,src_ip\n')
        self.assertEqual((result['summary']['total_rows'], result['rows']), (0, []))

    def test_formula_text_is_never_executed_or_altered(self):
        result = self.prepare('timestamp,source,details\n2026-01-02T03:04:05Z,network,"=cmd|\' /C calc\'!A0"\n')
        self.assertTrue(result['rows'][0]['raw']['details'].startswith('=cmd'))


class GeneratorTests(unittest.TestCase):

    def test_same_seed_gives_the_same_dataset(self):
        from datetime import datetime, timezone
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertEqual(generate_dataset('mixed', 300, 3600, 42, 'x', end), generate_dataset('mixed', 300, 3600, 42, 'x', end))
        self.assertNotEqual(generate_dataset('mixed', 300, 3600, 42, 'x', end), generate_dataset('mixed', 300, 3600, 43, 'x', end))

    def test_requested_count_and_labels(self):
        built = generate_dataset('mixed', 500, 3600, 1, 'x')
        self.assertEqual(len(built), 500)
        self.assertEqual({label for _, _, label, _ in built}, {'normal', 'malicious'})

    def test_labels_are_not_in_the_event(self):
        for raw, _, _, _ in generate_dataset('mixed', 200, 3600, 1, 'x'):
            self.assertFalse({'label', 'attack_type', 'ground_truth'} & set(raw))

    def test_bad_parameters_are_refused(self):
        for args in (('nope', 100, 3600), ('normal', 0, 3600), ('normal', 10 ** 6, 3600), ('normal', 100, 5)):
            with self.assertRaises(ValueError):
                generate_dataset(*args, 1, 'x')


class DatasetJobTests(JobTestCase):

    def generate(self, profile='mixed', count=400, seed=1):
        response = self.client.post('/api/datasets/generate', json={'profile': profile, 'count': count, 'duration_seconds': 7200, 'seed': seed})
        self.assertEqual(response.status_code, 202, response.get_json())
        return self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])

    def test_generated_mixed_data_is_detected_and_measured(self):
        dataset = self.generate()
        self.assertEqual(dataset['status'], 'COMPLETED')
        self.assertEqual(dataset['processed_events'], 400)
        metrics = dataset['metrics']
        self.assertEqual(metrics['missed_rules'], [])
        self.assertEqual(metrics['unexpected_rules'], [])
        self.assertEqual(metrics['event_level']['false_positives'], 0)
        self.assertEqual(metrics['incident_level']['false_positives'], 0)
        self.assertGreater(metrics['event_level']['true_positives'], 0)
        self.assertEqual(len(dataset['incidents']), 4)
        self.assertTrue(dataset['severity_distribution'])
        self.assertTrue(dataset['detection_distribution'])

    def test_every_profile_finds_exactly_what_it_should(self):
        for index, profile in enumerate(PROFILES):
            with self.subTest(profile=profile):
                metrics = self.generate(profile, 150, 10 + index)['metrics']
                self.assertEqual((metrics['missed_rules'], metrics['unexpected_rules']), ([], []))
                self.assertEqual(metrics['event_level']['false_positives'], 0)

    def test_normal_only_data_stays_quiet_at_volume(self):
        for seed in (1, 2):
            dataset = self.generate('normal', 2000, seed)
            self.assertEqual((dataset['metrics']['alerts'], dataset['incidents']), (0, []), f'seed {seed}')

    def test_upload_with_labels_is_scored_against_them(self):
        lines = [f'2026-01-02T03:04:{i:02d}Z,application,203.0.113.9,root,authentication_failure,malicious' for i in range(6)]
        lines += [f'2026-01-02T04:00:{i:02d}Z,application,10.0.0.{i + 1},user{i},authentication_success,normal' for i in range(4)]
        response = self.client.post('/api/datasets/upload', data=csv_upload(CSV_HEADER + '\n'.join(lines) + '\n'), content_type='multipart/form-data')
        self.assertEqual(response.status_code, 202, response.get_json())
        dataset = self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])
        self.assertEqual(dataset['status'], 'COMPLETED')
        event_level = dataset['metrics']['event_level']
        self.assertEqual((event_level['true_positives'], event_level['false_positives'], event_level['true_negatives'], event_level['false_negatives']), (6, 0, 4, 0))
        self.assertEqual(event_level['precision'], 1.0)
        self.assertEqual(event_level['recall'], 1.0)
        # The original record is preserved, but not the label
        logs = self.client.get(f"/api/datasets/{dataset['dataset_id']}/events?limit=20").get_json()
        detail = self.client.get(f"/api/logs/{logs[0]['id']}").get_json()
        self.assertNotIn('label', json.dumps(detail['raw_event']))
        self.assertNotIn('malicious', json.dumps(detail))

    def test_unlabelled_upload_reports_descriptive_counts_only(self):
        text = 'timestamp,source,src_ip\n' + ''.join(f'2026-01-02T03:04:{i:02d}Z,network,10.0.0.1\n' for i in range(5))
        response = self.client.post('/api/datasets/upload', data=csv_upload(text), content_type='multipart/form-data')
        dataset = self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])
        self.assertFalse(dataset['metrics']['has_ground_truth'])
        self.assertNotIn('event_level', dataset['metrics'])
        self.assertIn('no ground truth', dataset['metrics']['note'])

    def test_the_same_file_is_not_processed_twice_unless_asked(self):
        text = 'timestamp,source,src_ip\n2026-01-02T03:04:05Z,network,10.0.0.1\n'
        first = self.client.post('/api/datasets/upload', data=csv_upload(text), content_type='multipart/form-data').get_json()
        self.wait_for_dataset(first['dataset']['dataset_id'])
        total = self.client.get('/api/stats').get_json()['total']
        again = self.client.post('/api/datasets/upload', data=csv_upload(text), content_type='multipart/form-data')
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.get_json()['duplicate_of'], first['dataset']['dataset_id'])
        self.assertEqual(self.client.get('/api/stats').get_json()['total'], total)
        redo = self.client.post('/api/datasets/upload', data=csv_upload(text, reanalyze='1'), content_type='multipart/form-data')
        self.assertEqual(redo.status_code, 202)
        self.wait_for_dataset(redo.get_json()['dataset']['dataset_id'])
        self.assertEqual(self.client.get('/api/stats').get_json()['total'], total + 1)

    def test_validation_stores_nothing(self):
        text = 'timestamp,source,src_ip\n2026-01-02T03:04:05Z,network,bad-ip\n2026-01-02T03:04:06Z,network,10.0.0.1\n'
        response = self.client.post('/api/datasets/validate', data=csv_upload(text), content_type='multipart/form-data')
        body = response.get_json()
        self.assertEqual((body['summary']['valid_records'], body['summary']['invalid_records']), (1, 1))
        self.assertEqual(self.client.get('/api/stats').get_json()['total'], 0)

    def test_bad_uploads_fail_with_a_useful_message(self):
        cases = {
            'malformed mapping': (csv_upload('a,b\n1,2\n', mapping='{bad'), 'not valid JSON'),
            'unknown mapping target': (csv_upload('a\n1\n', mapping='{"a": "nonsense"}'), 'Unknown target field'),
            'all rows invalid': (csv_upload('timestamp,source\nnever,network\n'), 'No valid events'),
            'no file': ({}, 'No file'),
        }
        for name, (form, expected) in cases.items():
            with self.subTest(case=name):
                response = self.client.post('/api/datasets/upload', data=form, content_type='multipart/form-data')
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected, response.get_json()['error'])

    def test_a_processing_failure_is_recorded_safely(self):
        text = 'timestamp,source,src_ip\n2026-01-02T03:04:05Z,network,10.0.0.9\n'
        with mock.patch.object(job_module, 'ingest_records', side_effect=RuntimeError('db locked at C:\\secret')):
            response = self.client.post('/api/datasets/upload', data=csv_upload(text), content_type='multipart/form-data')
            dataset = self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])
        self.assertEqual(dataset['status'], 'FAILED')
        self.assertNotIn('secret', dataset['error'])

    def test_generate_refuses_bad_input(self):
        for body in ({'profile': 'nope'}, {'profile': 'normal', 'count': 'many'}, {'profile': 'normal', 'count': 10 ** 7}):
            self.assertEqual(self.client.post('/api/datasets/generate', json=body).status_code, 400)


class ReportTests(JobTestCase):

    def report_for(self, scenario='multi_stage'):
        view = self.run_simulation(scenario)
        report_id = next(r['report_id'] for r in self.client.get('/api/reports').get_json() if r['subject_id'] == view['run_id'])
        return view, report_id

    def test_the_report_has_every_required_section(self):
        _, report_id = self.report_for()
        text = self.client.get(f'/api/reports/{report_id}?format=md').get_data(as_text=True)
        for section in ('Executive summary', 'Threat overview', 'Processing summary', 'Detection results', 'IOA rule matches', 'IOC matches',
                        'UEBA findings', 'Evidence:', 'Incident investigation', 'Why this score', 'Timeline', 'Risk analysis', 'Recommended actions', 'Analyst decisions',
                        'Model performance', 'Known limitations'):
            self.assertIn(section, text)
        self.assertIn(report_id, text)

    def test_the_report_comes_from_stored_results(self):
        view, report_id = self.report_for()
        content = self.client.get(f'/api/reports/{report_id}').get_json()['content']
        self.assertEqual(content['detection_results']['alerts'], view['alert_count'])
        self.assertEqual(content['processing_summary']['total'], view['event_count'])
        self.assertEqual(content['incidents'][0]['uid'], view['incidents'][0]['incident_uid'])
        self.assertEqual(content['detection_results']['incident_risk_distribution']['CRITICAL'], 1)
        self.assertEqual(content['analyst_decisions'], [])

    def test_a_new_report_includes_analyst_decisions(self):
        view, _ = self.report_for()
        action = self.client.get(f"/api/incidents/{view['incidents'][0]['id']}/response-actions").get_json()[0]
        self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'reject', 'analyst': 'priya', 'reason': 'Not needed'})
        created = self.client.post('/api/reports', json={'subject_type': 'simulation', 'subject_id': view['run_id']})
        self.assertEqual(created.status_code, 201)
        content = self.client.get(f"/api/reports/{created.get_json()['report_id']}").get_json()['content']
        self.assertEqual(content['analyst_decisions'][0]['decided_by'], 'priya')

    def test_a_benign_run_reports_no_findings_rather_than_inventing_any(self):
        _, report_id = self.report_for('benign')
        text = self.client.get(f'/api/reports/{report_id}?format=md').get_data(as_text=True)
        self.assertIn('No incident was created', text)

    def test_csv_export_neutralizes_formulas(self):
        _, report_id = self.report_for()
        response = self.client.get(f'/api/reports/{report_id}?format=csv')
        self.assertEqual(response.mimetype, 'text/csv')
        self.assertIn('event_level', response.get_data(as_text=True))
        lines = response.get_data(as_text=True).splitlines()[1:]
        self.assertFalse([line for line in lines if re.search(r'(^|,)[=+@]', line)])

    def test_pdf_export_is_a_well_formed_pdf(self):
        _, report_id = self.report_for()
        pdf = self.client.get(f'/api/reports/{report_id}?format=pdf').get_data()
        self.assertTrue(pdf.startswith(b'%PDF-1.4'))
        self.assertTrue(pdf.rstrip().endswith(b'%%EOF'))
        # Every entry in the cross-reference table points at the object it claims to
        start = int(re.search(rb'startxref\n(\d+)', pdf).group(1))
        entries = pdf[start:].split(b'\n')[2:]
        offsets = [int(line[:10]) for line in entries if line.endswith(b' n ')]
        for number, offset in enumerate(offsets, 1):
            self.assertTrue(pdf[offset:].startswith(b'%d 0 obj' % number), number)

    def test_pdf_text_escaping_survives_hostile_text(self):
        pdf = render_pdf('(unbalanced \\ text) \u2603 ' * 40)
        self.assertTrue(pdf.startswith(b'%PDF'))

    def test_unknown_reports_and_formats_are_refused(self):
        self.assertEqual(self.client.get('/api/reports/nope').status_code, 400)
        _, report_id = self.report_for('benign')
        self.assertEqual(self.client.get(f'/api/reports/{report_id}?format=exe').status_code, 400)
        self.assertEqual(self.client.post('/api/reports', json={'subject_type': 'x', 'subject_id': 'y'}).status_code, 400)
        self.assertEqual(self.client.post('/api/reports', json={'subject_type': 'simulation', 'subject_id': 'y'}).status_code, 400)

    def test_incident_report_can_be_a_pdf(self):
        view, _ = self.report_for()
        response = self.client.get(f"/api/incidents/{view['incidents'][0]['id']}/report?format=pdf")
        self.assertEqual(response.mimetype, 'application/pdf')


class SecurityHeaderTests(JobTestCase):

    def test_pages_and_apis_carry_security_headers(self):
        for path in ('/', '/api/stats'):
            headers = self.client.get(path).headers
            self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
            self.assertEqual(headers['X-Frame-Options'], 'DENY')
            self.assertIn("script-src 'self'", headers['Content-Security-Policy'])


class BehavioralTests(JobTestCase):

    def login(self, offset, ip, user='asha', ok=True):
        return {'timestamp': f'2026-01-02T{3 + offset // 60:02d}:{offset % 60:02d}:00Z', 'source': 'application',
                'event_type': 'authentication_success' if ok else 'authentication_failure', 'src_ip': ip, 'user': user}

    def fired(self):
        return {a['rule_id'] for a in models.get_recent_alerts(100)}

    def test_a_new_source_is_flagged_only_after_a_history_exists(self):
        self.client.post('/api/ingest/events', json=[self.login(0, '203.0.113.20')])
        self.assertNotIn('UEBA-001', self.fired())
        self.client.post('/api/ingest/events', json=[self.login(i + 1, '10.0.0.5') for i in range(5)])
        self.assertNotIn('UEBA-001', self.fired())
        self.client.post('/api/ingest/events', json=[self.login(30, '10.0.0.5')])
        self.assertNotIn('UEBA-001', self.fired())
        self.client.post('/api/ingest/events', json=[self.login(40, '203.0.113.21')])
        self.assertIn('UEBA-001', self.fired())
        alert = next(a for a in models.get_recent_alerts(100) if a['rule_id'] == 'UEBA-001')
        self.assertEqual(alert['detection_type'], 'UEBA')
        self.assertIn('203.0.113.21', alert['explanation'])

    def test_a_simulated_baseline_never_counts_for_real_telemetry(self):
        self.run_simulation('multi_stage')
        self.client.post('/api/ingest/events', json=[{**self.login(0, '203.0.113.22', 'svc_admin')}])
        self.assertEqual(sum(1 for a in models.get_recent_alerts(100) if a['rule_id'] == 'UEBA-001'), 1)

    def test_behavior_rules_are_listed_with_their_activity(self):
        self.run_simulation('multi_stage')
        rules = {rule['id']: rule for rule in self.client.get('/api/rules').get_json()['behavioral_rules']}
        self.assertEqual(rules['UEBA-001']['alerts'], 1)
        self.assertTrue(rules['UEBA-002']['logic'])


if __name__ == '__main__':
    unittest.main()
