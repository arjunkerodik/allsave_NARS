import csv
import io
import json
import os
import unittest
from unittest import mock

import app as allsafe
import models
from tests.test_jobs import JobTestCase
from utils import nids_engine as nids_module
from utils.anomaly_engine import AnomalyEngine
from utils.dataset_analysis import NO_THREAT_STATEMENT
from utils.dataset_engine import decode_text, detect_structure, inspect_file, prepare_dataset
from utils.dataset_generator import generate_dataset
from utils.log_ingest import UploadRejected
from utils.nids_engine import FLOW_FEATURES, NidsEngine, feature_row
from utils.source_parsers import identify_and_map

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'samples')


def sample(name):
    with open(os.path.join(SAMPLES, name), 'rb') as handle:
        return handle.read()


class AnalysisTestCase(JobTestCase):

    def upload(self, name, data=None, **form):
        data = sample(name) if data is None else data
        return self.client.post('/api/datasets/upload', data={'file': (io.BytesIO(data), name), **form}, content_type='multipart/form-data')

    def analyze(self, name, data=None, **form):
        response = self.upload(name, data, **form)
        self.assertEqual(response.status_code, 202, response.get_json())
        return self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])

    def report_text(self, dataset, file_format='md'):
        response = self.client.get(f"/api/reports/{dataset['report_id']}?format={file_format}")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def assert_verdict(self, dataset, status):
        self.assertEqual(dataset['verdict'], status, dataset.get('analysis', {}).get('verdict'))

    def rules(self, dataset):
        return {alert['rule_id'] for alert in dataset['alerts']}

    def engine(self, dataset, name):
        return next(row for row in dataset['analysis']['engines'] if row['engine'] == name)


class ModuleElevenCases(AnalysisTestCase):
    """The twelve dataset cases named in the brief, each through the real upload path"""

    def test_01_clean_dataset_gets_a_no_threat_report(self):
        dataset = self.analyze('clean_activity.csv')
        self.assert_verdict(dataset, 'NO_THREATS_DETECTED')
        verdict = dataset['analysis']['verdict']
        self.assertEqual(verdict['headline'], 'NO THREATS DETECTED')
        self.assertEqual(verdict['statement'], NO_THREAT_STATEMENT)
        self.assertEqual(dataset['alerts'], [])
        self.assertEqual(dataset['incidents'], [])
        for engine in ('IOC', 'IOA', 'UEBA', 'ANOMALY'):
            self.assertEqual(self.engine(dataset, engine)['status'], 'COMPLETED', engine)
            self.assertGreater(self.engine(dataset, engine)['evaluated'], 0, engine)
        text = self.report_text(dataset)
        for part in ('NO THREATS DETECTED', NO_THREAT_STATEMENT, 'Total uploaded records', 'Successfully processed records', 'Detection engines',
                     'IOC matches (0)', 'IOA rule matches (0)', 'Unusual activity windows:** 0', 'Rejected records:** 0', 'No known indicator was matched'):
            self.assertIn(part, text)
        # A clean result must never be claimed as a guarantee
        for claim in ('dataset is safe', 'environment is safe', 'no threats exist', 'is clean'):
            self.assertNotIn(claim, text)

    def test_02_brute_force_from_a_windows_export(self):
        dataset = self.analyze('brute_force_windows.csv')
        self.assert_verdict(dataset, 'THREATS_DETECTED')
        self.assertEqual(dataset['summary']['dataset_type'], 'Windows authentication events')
        self.assertTrue({'IOA-001', 'IOA-002'} <= self.rules(dataset))
        self.assertEqual(self.engine(dataset, 'IOA')['status'], 'COMPLETED')
        incident = dataset['incidents'][0]
        self.assertIsNotNone(incident['risk_score'])
        self.assertTrue(incident['risk_reasons'])
        self.assertEqual(incident['hosts'], ['dc-01.corp.example'])
        self.assertIn('svc_backup', incident['users'])
        self.assertTrue(incident['timeline'])
        # Record-level evidence, with the original record untouched
        alert_id = next(a['id'] for a in dataset['alerts'] if a['rule_id'] == 'IOA-001')
        alert = self.client.get(f'/api/alerts/{alert_id}').get_json()
        self.assertEqual(alert['supporting_event_count'], 9)
        event = self.client.get(f"/api/logs/{alert['supporting_log_ids'][0]}").get_json()
        self.assertEqual(event['raw_event']['EventID'], '4625')
        self.assertIn('TimeCreated', event['raw_event'])
        self.assertNotIn('event_type', event['raw_event'])
        self.assertEqual(event['event_type'], 'authentication_failure')
        self.assertEqual(event['normalized_fields']['source_file'], 'brute_force_windows.csv')

    def test_02b_brute_force_from_a_linux_auth_log(self):
        dataset = self.analyze('linux_auth.log')
        self.assert_verdict(dataset, 'THREATS_DETECTED')
        self.assertIn('Linux authentication events', dataset['summary']['log_types'])
        self.assertTrue({'IOA-001', 'IOA-002'} <= self.rules(dataset))

    def test_03_suspicious_network_traffic_is_not_called_confirmed(self):
        dataset = self.analyze('suspicious_network.csv')
        self.assert_verdict(dataset, 'SUSPICIOUS_ACTIVITY')
        self.assertIn('IOA-006', self.rules(dataset))
        self.assertEqual(dataset['analysis']['classification']['confirmed_detections']['alerts'], 0)
        self.assertGreater(dataset['analysis']['classification']['suspicious_activity']['alerts'], 0)
        self.assertNotIn(NO_THREAT_STATEMENT, self.report_text(dataset))

    def test_03b_a_firewall_log_shows_a_port_scan(self):
        dataset = self.analyze('firewall_ufw.log')
        self.assertEqual(dataset['summary']['dataset_type'], 'Firewall events')
        self.assertIn('IOA-005', self.rules(dataset))

    def test_04_ioc_matches_record_where_they_came_from(self):
        dataset = self.analyze('ioc_match.jsonl')
        self.assertTrue({'IOC-IP', 'IOC-HASH'} <= self.rules(dataset), self.rules(dataset))
        self.assertGreater(dataset['analysis']['ioc']['matches'], 0)
        self.assertIsNone(dataset['analysis']['ioc']['note'])
        text = self.report_text(dataset)
        for part in ('Matched indicator: 198.51.100.77', 'allsafe-synthetic-demo-feed', 'Context:', 'Supporting event IDs'):
            self.assertIn(part, text)

    def test_05_privilege_escalation(self):
        dataset = self.analyze('privilege_escalation.jsonl')
        self.assert_verdict(dataset, 'THREATS_DETECTED')
        self.assertIn('IOA-003', self.rules(dataset))
        self.assertIn('T1548', {t['id'] for t in dataset['analysis']['mitre']})
        self.assertTrue(dataset['analysis']['remediation'])

    def test_06_data_exfiltration(self):
        dataset = self.analyze('exfiltration.csv')
        self.assert_verdict(dataset, 'THREATS_DETECTED')
        self.assertTrue({'IOA-007', 'UEBA-002'} <= self.rules(dataset), self.rules(dataset))
        anomaly_rule = next(a for a in dataset['alerts'] if a['rule_id'] == 'UEBA-002')
        self.assertFalse(anomaly_rule['confirmed'])
        self.assertIn('Investigate', ' '.join(f"{a['label']}" for i in dataset['incidents'] for a in i['actions']))

    def test_07_malformed_records_do_not_reject_the_good_ones(self):
        dataset = self.analyze('malformed_records.csv')
        self.assertEqual(dataset['status'], 'COMPLETED')
        summary = dataset['summary']
        self.assertEqual((summary['valid_records'], summary['invalid_records']), (6, 5))
        self.assertEqual(dataset['processed_events'], 6)
        reasons = ' '.join(reason for row in dataset['invalid_records'] for reason in row['errors'])
        for part in ('timestamp cannot be read', 'not an IP address', 'fewer columns', 'more columns'):
            self.assertIn(part, reasons)
        self.assertIn('Rejected records:** 5', self.report_text(dataset))

    def test_08_duplicates_are_counted_and_not_processed(self):
        dataset = self.analyze('duplicate_records.csv')
        self.assertEqual((dataset['summary']['valid_records'], dataset['summary']['skipped_duplicates']), (5, 5))
        self.assertEqual(dataset['processed_events'], 5)
        self.assertIn('Duplicate records:** 5', self.report_text(dataset))

    def test_09_unsupported_fields_are_kept_and_named(self):
        dataset = self.analyze('unsupported_fields.csv')
        self.assertEqual(dataset['status'], 'COMPLETED')
        self.assertEqual(set(dataset['summary']['unsupported_fields']), {'vendor_score', 'tenant_ref', 'risk_note'})
        self.assertTrue(any('no equivalent' in warning for warning in dataset['summary']['warnings']))
        logs = self.client.get(f"/api/datasets/{dataset['dataset_id']}/events?limit=1").get_json()
        detail = self.client.get(f"/api/logs/{logs[0]['id']}").get_json()
        self.assertIn('vendor_score', detail['raw_event'])
        self.assertIn('vendor_score', detail['normalized_fields'])

    def test_09b_a_damaged_evtx_fails_validation_rather_than_looking_clean(self):
        response = self.upload('security.evtx', b'ElfFile\x00' + b'\x00' * 100)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['analysis_status'], 'VALIDATION_FAILED')

    def test_10_empty_dataset_fails_validation_and_says_so(self):
        for name, data in (('empty.csv', b''), ('blank.jsonl', b'\n\n  \n'), ('header_only.csv', b'timestamp,source,src_ip\n')):
            with self.subTest(file=name):
                response = self.upload(name, data)
                self.assertEqual(response.status_code, 400, response.get_json())
                self.assertEqual(response.get_json()['analysis_status'], 'VALIDATION_FAILED')
        listed = self.client.get('/api/datasets').get_json()['datasets']
        self.assertEqual({row['status'] for row in listed}, {'VALIDATION_FAILED'})
        self.assertEqual({row['verdict'] for row in listed}, {'VALIDATION_FAILED'})

    def test_11_large_dataset(self):
        built = generate_dataset('mixed', 15000, 7200, 3, 'large')
        columns = sorted({key for raw, _, _, _ in built for key in raw} | {'source', 'label'})
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns)
        writer.writeheader()
        for raw, source, label, _ in built:
            writer.writerow({**raw, 'source': source, 'label': label})
        dataset = self.analyze('large.csv', buffer.getvalue().encode())
        self.assertEqual(dataset['status'], 'COMPLETED')
        self.assertEqual(dataset['processed_events'], 15000)
        self.assert_verdict(dataset, 'THREATS_DETECTED')
        self.assertEqual(dataset['metrics']['event_level']['false_positives'], 0)
        self.assertEqual(len(dataset['incidents']), 4)
        self.assertLess(dataset['metrics']['processing_seconds'], 240)

    def test_12_records_with_no_timestamp_are_rejected_and_reported(self):
        dataset = self.analyze('missing_timestamps.csv')
        self.assertEqual(dataset['status'], 'COMPLETED')
        self.assertEqual(dataset['summary']['missing_timestamps'], 3)
        self.assertEqual(dataset['summary']['valid_records'], 6)
        self.assertIn('Missing timestamps:** 3', self.report_text(dataset))

    def test_12b_a_file_with_no_times_is_analyzed_but_never_called_clean(self):
        dataset = self.analyze('none.csv', b'source,user\napplication,bob\napplication,amy\n')
        self.assertEqual(dataset['status'], 'COMPLETED')
        self.assertEqual(dataset['summary']['valid_records'], 2)
        self.assert_verdict(dataset, 'ANALYSIS_INCOMPLETE')
        self.assertTrue(any('time' in warning for warning in dataset['summary']['warnings']))


class FailureIsNeverCleanTests(AnalysisTestCase):
    """If an engine failed or could not run, the result must say so, and never look clean"""

    def assert_incomplete(self, dataset):
        self.assert_verdict(dataset, 'ANALYSIS_INCOMPLETE')
        self.assertEqual(dataset['analysis']['verdict']['headline'], 'ANALYSIS INCOMPLETE')
        self.assertTrue(dataset['analysis']['verdict']['reasons'])
        text = self.report_text(dataset)
        self.assertIn('ANALYSIS INCOMPLETE', text)
        self.assertNotIn(NO_THREAT_STATEMENT, text)
        self.assertNotIn('NO THREATS DETECTED', text)

    def test_a_crashing_engine_is_reported(self):
        with mock.patch.object(allsafe.correlation_engine.ioc_engine, 'evaluate', side_effect=RuntimeError('boom')):
            dataset = self.analyze('clean_activity.csv')
        self.assert_incomplete(dataset)
        self.assertEqual(self.engine(dataset, 'IOC')['status'], 'FAILED')

    def test_a_single_failing_rule_is_reported(self):
        broken = dict(allsafe.correlation_engine.detection.rules[0], group_by=None)
        allsafe.correlation_engine.detection.rules.append(broken)
        self.assert_incomplete(self.analyze('clean_activity.csv'))

    def test_a_finding_that_cannot_be_stored_is_reported(self):
        with mock.patch('utils.correlation_engine.persist_finding', side_effect=RuntimeError('db locked')):
            dataset = self.analyze('brute_force_windows.csv')
        self.assert_incomplete(dataset)

    def test_a_job_that_dies_is_reported(self):
        with mock.patch('utils.job_runner.ingest_records', side_effect=RuntimeError('disk full')):
            dataset = self.analyze('clean_activity.csv')
        self.assertEqual(dataset['status'], 'FAILED')
        self.assert_incomplete(dataset)

    def test_flow_data_no_engine_can_read_is_not_clean(self):
        dataset = self.analyze('network_flows_cicids.csv')
        self.assert_incomplete(dataset)
        self.assertEqual(self.engine(dataset, 'NIDS')['status'], 'SKIPPED')
        self.assertIn('ALLSAFE_LOAD_ML', self.engine(dataset, 'NIDS')['reason'])
        self.assertEqual(dataset['analysis']['counts']['not_evaluated_events'], 200)
        self.assertTrue(dataset['analysis']['classification']['detection_limitations'])

    def test_a_restart_during_processing_is_reported(self):
        models.insert_dataset({'dataset_id': 'ds-cut', 'name': 'x.csv', 'kind': 'upload', 'status': 'PROCESSING', 'total_events': 5})
        models.mark_interrupted_jobs()
        dataset = self.client.get('/api/datasets/ds-cut').get_json()
        self.assertEqual((dataset['status'], dataset['verdict']), ('INTERRUPTED', 'ANALYSIS_INCOMPLETE'))


class NetworkModelTests(AnalysisTestCase):

    def use_real_model(self):
        allsafe.correlation_engine.nids = _real_engine()

    def test_the_real_model_classifies_compatible_flows(self):
        self.use_real_model()
        dataset = self.analyze('network_flows_cicids.csv')
        self.assertEqual(self.engine(dataset, 'NIDS')['status'], 'COMPLETED')
        ml = dataset['analysis']['ml']
        self.assertEqual(ml['flows_classified'], 200)
        self.assertEqual(sum(ml['distribution'].values()), 200)
        self.assertTrue(ml['model_version'])
        self.assertIsNone(ml['confidence'])
        self.assertFalse(ml['calibrated'])
        # The label is ground truth, used only to measure afterwards
        self.assertEqual(dataset['metrics']['ml_level']['flows_compared'], 200)
        text = self.report_text(dataset)
        self.assertIn('ML classification results', text)
        self.assertIn('not reported, because the model is not calibrated', text)
        # Time-based rules could not run on these, and the report says so
        self.assertEqual(self.engine(dataset, 'IOA')['status'], 'SKIPPED')
        self.assertIn('usable timestamp', self.engine(dataset, 'IOA')['reason'])

    def test_labels_never_reach_the_model(self):
        rows = {name: 1 for name in FLOW_FEATURES}
        self.assertEqual(feature_row({**rows, 'Label': 'DDoS'}), feature_row(rows))
        self.assertEqual(len(feature_row(rows)), 78)

    def test_other_logs_never_reach_the_model(self):
        engine = NidsEngine(enabled=True)
        allsafe.correlation_engine.nids = engine
        with mock.patch.object(engine, 'predict') as predict, mock.patch.object(engine, '_load') as load:
            for name in ('brute_force_windows.csv', 'linux_auth.log', 'exfiltration.csv'):
                dataset = self.analyze(name)
                self.assertEqual(self.engine(dataset, 'NIDS')['status'], 'SKIPPED')
                self.assertIn('never fed', self.engine(dataset, 'NIDS')['reason'])
        predict.assert_not_called()
        load.assert_not_called()

    def test_flows_missing_features_are_explained_not_guessed(self):
        columns = list(FLOW_FEATURES[:50])
        text = 'Timestamp,Source IP,' + ','.join(columns) + '\n' + '\n'.join(f"2026-01-15T10:00:{i:02d}Z,10.0.0.1," + ','.join('1' for _ in columns) for i in range(5)) + '\n'
        engine = NidsEngine(enabled=True)
        allsafe.correlation_engine.nids = engine
        with mock.patch.object(engine, 'predict') as predict:
            dataset = self.analyze('partial.csv', text.encode())
        predict.assert_not_called()
        self.assertEqual(dataset['summary']['flows_without_model_features'], 5)
        self.assertEqual(self.engine(dataset, 'NIDS')['status'], 'SKIPPED')
        self.assertTrue(any('lack some of the features' in warning for warning in dataset['summary']['warnings']))

    def test_a_predicted_attack_is_suspicious_and_not_critical_alone(self):
        engine = NidsEngine(enabled=True)
        engine._model, engine.version = object(), 'test-version'
        allsafe.correlation_engine.nids = engine
        with mock.patch.object(engine, 'predict', side_effect=lambda rows: ['DDoS'] * len(rows)):
            dataset = self.analyze('network_flows_cicids_with_addresses.csv')
        self.assertIn('ML-DOS', self.rules(dataset))
        self.assert_verdict(dataset, 'SUSPICIOUS_ACTIVITY')
        for incident in dataset['incidents']:
            self.assertNotIn(incident['risk_level'], ('CRITICAL', 'HIGH'))
        for alert in dataset['alerts']:
            self.assertFalse(alert['confirmed'])

    def test_compatible_flows_are_marked_only_when_complete(self):
        self.assertTrue(identify_and_map({name: 1 for name in FLOW_FEATURES})['model_features'])
        self.assertFalse(identify_and_map({name: 1 for name in FLOW_FEATURES[:60]})['model_features'])
        self.assertTrue(identify_and_map({f' {name}'.replace('_', ' '): 1 for name in FLOW_FEATURES})['model_features'])


_REAL_ENGINE = None


def _real_engine():
    """Loading takes a few seconds, so the tests share one"""
    global _REAL_ENGINE
    if _REAL_ENGINE is None:
        _REAL_ENGINE = NidsEngine(enabled=True)
    return _REAL_ENGINE


class AnomalyModelTests(AnalysisTestCase):

    def test_an_attack_burst_is_flagged_with_its_reason(self):
        dataset = self.analyze('brute_force_windows.csv')
        findings = dataset['analysis']['anomalies']['findings']
        self.assertTrue(findings)
        self.assertEqual(findings[0]['entity'], '203.0.113.44')
        self.assertIn('failed logins', findings[0]['explanation'])
        self.assertIn('not a confirmed attack', findings[0]['explanation'])

    def test_an_anomaly_alone_is_suspicious_and_creates_no_incident(self):
        with mock.patch.object(AnomalyEngine, '_is_flagged', return_value=True):
            dataset = self.analyze('clean_activity.csv')
        self.assert_verdict(dataset, 'SUSPICIOUS_ACTIVITY')
        self.assertGreater(dataset['analysis']['anomalies']['windows'], 0)
        self.assertEqual((dataset['alerts'], dataset['incidents']), ([], []))

    def test_live_telemetry_is_not_scored(self):
        engine = AnomalyEngine()
        self.assertFalse(engine.applicable({'ts_epoch': 1, 'origin': 'live', 'src_ip': '10.0.0.1'}))
        self.assertTrue(engine.applicable({'ts_epoch': 1, 'origin': 'dataset', 'src_ip': '10.0.0.1'}))

    def test_measured_performance_comes_from_data_it_did_not_train_on(self):
        body = self.client.get('/api/ml').get_json()
        evaluation = body['anomaly_model']['evaluation']
        self.assertGreater(evaluation['held_out_normal_windows'], 1000)
        self.assertLess(evaluation['false_alarm_rate'], 0.02)
        self.assertGreater(evaluation['attack_windows_flagged'], 0)
        self.assertIn('does not predict performance', evaluation['note'])
        self.assertFalse(body['network_model']['validated'])
        self.assertFalse(body['network_model']['calibrated'])

    def test_training_is_reproducible(self):
        first, second = AnomalyEngine(), AnomalyEngine()
        first.prepare()
        second.prepare()
        self.assertEqual(first.threshold, second.threshold)


class ValidationAndIdentificationTests(unittest.TestCase):

    def prepare(self, data, name='data.csv', **kwargs):
        return prepare_dataset(name, data if isinstance(data, bytes) else data.encode(), **kwargs)

    def test_content_must_match_the_name(self):
        for data, name, expected in ((b'MZ\x90\x00', 'data.csv', 'Windows executable'), (b'PK\x03\x04abc', 'logs.json', 'ZIP archive'),
                                     (b'%PDF-1.4', 'logs.txt', 'PDF'), (b'\xd4\xc3\xb2\xa1abc', 'data.csv', 'packet capture'), (b'hello', 'data.pcap', 'not a packet capture')):
            with self.subTest(file=name), self.assertRaisesRegex(UploadRejected, expected):
                inspect_file(name, data)

    def test_encodings(self):
        self.assertEqual(decode_text(b'\xef\xbb\xbfabc')[:2], ('abc', 'UTF-8 with BOM'))
        self.assertEqual(decode_text('abc'.encode('utf-16'))[0], 'abc')
        text, name, warnings = decode_text('caf\xe9'.encode('cp1252'))
        self.assertEqual((text, name), ('caf\xe9', 'Windows-1252'))
        self.assertTrue(warnings)
        with self.assertRaisesRegex(UploadRejected, 'not a text file'):
            decode_text(b'abc\x00def')

    def test_a_utf16_windows_export_is_read(self):
        text = 'TimeCreated,EventID,Computer,TargetUserName,IpAddress\n2026-01-15T10:00:00Z,4625,dc-01,bob,203.0.113.4\n'
        result = self.prepare(text.encode('utf-16'))
        self.assertEqual(result['summary']['file']['encoding'], 'UTF-16 LE')
        self.assertEqual(result['rows'][0]['raw']['event_type'], 'authentication_failure')

    def test_content_decides_the_structure(self):
        self.assertEqual(detect_structure('{"a": 1}\n{"a": 2}\n', 'log'), 'jsonl')
        self.assertEqual(detect_structure('[{"a": 1}]', 'txt'), 'json')
        self.assertEqual(detect_structure('a,b,c\n1,2,3\n4,5,6\n', 'txt'), 'csv')
        self.assertEqual(detect_structure('just some words\nmore words\n', 'log'), 'text')
        result = self.prepare('[{"timestamp": "2026-01-15T10:00:00Z", "source": "network", "src_ip": "10.0.0.1"}]', name='data.csv')
        self.assertEqual(result['summary']['file']['structure'], 'json')
        self.assertTrue(any('named .csv' in warning for warning in result['summary']['warnings']))

    def test_other_delimiters_are_read(self):
        result = self.prepare('timestamp;source;src_ip\n2026-01-15T10:00:00Z;network;10.0.0.1\n')
        self.assertEqual(result['summary']['valid_records'], 1)

    def test_columns_are_profiled(self):
        result = self.prepare('timestamp,source,src_ip,bytes,vendor\n2026-01-15T10:00:00Z,network,10.0.0.1,5,x\n2026-01-15T10:00:01Z,network,,7,y\n')
        columns = {column['name']: column for column in result['summary']['columns']}
        self.assertEqual(columns['timestamp']['type'], 'timestamp')
        self.assertEqual(columns['src_ip']['type'], 'ip address')
        self.assertEqual(columns['src_ip']['missing'], 1)
        self.assertEqual(columns['bytes']['type'], 'number')
        self.assertFalse(columns['vendor']['mapped'])
        self.assertEqual(result['summary']['timestamp_fields'], ['timestamp'])
        self.assertEqual(result['summary']['unsupported_fields'], ['vendor'])

    def test_the_original_record_is_never_modified(self):
        original = {'TimeCreated': '2026-01-15T10:00:00Z', 'EventID': '4625', 'Computer': 'dc-01', 'TargetUserName': 'bob', 'IpAddress': '-'}
        result = self.prepare(json.dumps(original), name='event.json')
        self.assertEqual(result['rows'][0]['raw']['_original'], original)
        # The placeholder '-' is not an address, so the field stays absent rather than invented
        self.assertNotIn('src_ip', result['rows'][0]['raw'])

    def test_removing_ground_truth_is_recorded_and_not_silent(self):
        result = self.prepare('timestamp,source,label\n2026-01-15T10:00:00Z,network,normal\n')
        raw = result['rows'][0]['raw']
        self.assertEqual(raw['ground_truth_columns_removed'], ['label'])
        self.assertNotIn('label', raw['_original'])

    def test_a_record_nothing_identifies_is_kept_as_other_and_says_so(self):
        result = self.prepare('timestamp,color\n2026-01-15T10:00:00Z,red\n')
        self.assertEqual(result['summary']['valid_records'], 1)
        self.assertEqual(result['summary']['invalid_records'], 0)
        self.assertEqual(result['rows'][0]['raw']['log_type'], 'other')

    def test_source_identification(self):
        cases = (
            ({'EventID': 4625, 'TimeCreated': 'x', 'Computer': 'a'}, 'windows_auth', 'endpoint', 'authentication_failure'),
            ({'EventID': 4688, 'TimeCreated': 'x', 'NewProcessName': r'C:\Windows\cmd.exe'}, 'endpoint_process', 'endpoint', 'process_start'),
            ({'EventID': 4720, 'TimeCreated': 'x', 'Computer': 'a'}, 'windows_auth', 'endpoint', 'account_created'),
            ({'EventID': 4672, 'TimeCreated': 'x', 'Computer': 'a'}, 'windows_auth', 'endpoint', 'special_privileges_assigned'),
            ({'EventID': 9999, 'TimeCreated': 'x', 'Computer': 'a'}, 'other', 'endpoint', 'windows_event_9999'),
            ({'timestamp': 'x', 'action': 'deny', 'src': '1.2.3.4', 'dst': '5.6.7.8'}, 'firewall', 'network', 'firewall_block'),
            ({'timestamp': 'x', 'process_name': 'ls', 'hostname': 'a'}, 'endpoint_process', 'endpoint', None),
            ({'timestamp': 'x', 'method': 'GET', 'path': '/'}, 'application', 'application', None),
            ({'timestamp': 'x', 'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8', 'bytes': 5}, 'network_flow', 'network', None),
        )
        for record, log_type, source, event_type in cases:
            with self.subTest(record=record):
                mapped = identify_and_map(record)
                self.assertEqual((mapped['log_type'], mapped['source']), (log_type, source))
                if event_type:
                    self.assertEqual(mapped['event_type'], event_type)

    def test_a_windows_process_path_is_split(self):
        mapped = identify_and_map({'EventID': 4688, 'TimeCreated': 'x', 'NewProcessName': r'C:\Windows\System32\cmd.exe'})
        self.assertEqual((mapped['process_name'], mapped['file_path']), ('cmd.exe', r'C:\Windows\System32\cmd.exe'))

    def test_an_unknown_source_name_is_kept_as_written(self):
        mapped = identify_and_map({'timestamp': 'x', 'source': 'martian', 'src_ip': '1.2.3.4'})
        self.assertEqual(mapped['source_name'], 'martian')


class FieldMappingAndRulesTests(AnalysisTestCase):

    def test_a_field_mapping_makes_an_unknown_file_readable(self):
        mapping = json.dumps({'when': 'timestamp', 'kind': 'source', 'origin_addr': 'src_ip', 'who': 'user', 'what': 'event_type', 'machine': 'hostname'})
        unmapped = self.analyze('custom_field_names.csv')
        self.assertNotIn('IOA-001', self.rules(unmapped))
        dataset = self.analyze('custom_field_names.csv', mapping=mapping, reanalyze='1')
        self.assertIn('IOA-001', self.rules(dataset))

    def test_suspicious_application_access_rule(self):
        dataset = self.analyze('application_access.csv')
        self.assertIn('IOA-017', self.rules(dataset))
        self.assertEqual(dataset['summary']['dataset_type'], 'Application security events')

    def test_unusual_login_time_needs_a_real_pattern(self):
        def login(day, hour, ip='10.0.0.5'):
            return {'timestamp': f'2026-01-{day:02d}T{hour:02d}:15:00Z', 'source': 'application', 'event_type': 'authentication_success', 'src_ip': ip, 'user': 'asha'}
        usual = [login(day, 9 + day % 3) for day in range(1, 13)]
        self.client.post('/api/ingest/events', json=usual)
        self.assertNotIn('UEBA-003', {a['rule_id'] for a in models.get_recent_alerts(100)})
        self.client.post('/api/ingest/events', json=[login(20, 3)])
        alert = next(a for a in models.get_recent_alerts(100) if a['rule_id'] == 'UEBA-003')
        self.assertIn('03:15 UTC', alert['explanation'])
        self.assertEqual(alert['severity'], 'LOW')

    def test_a_scattered_login_history_shows_no_pattern(self):
        logins = [{'timestamp': f'2026-01-{day:02d}T{(day * 5) % 24:02d}:00:00Z', 'source': 'application', 'event_type': 'authentication_success', 'src_ip': '10.0.0.5', 'user': 'ben'} for day in range(1, 20)]
        self.client.post('/api/ingest/events', json=logins)
        self.assertNotIn('UEBA-003', {a['rule_id'] for a in models.get_recent_alerts(100)})


class LiveUpdateTests(AnalysisTestCase):

    def run_with_socket(self, scenario):
        socket = mock.Mock()
        engine = allsafe.CorrelationEngine(socket, allsafe.fetch_stats)
        allsafe.correlation_engine = engine
        self.run_simulation(scenario)
        return [call.args[0] for call in socket.emit.call_args_list]

    def test_an_alert_with_no_incident_still_tells_open_pages(self):
        names = self.run_with_socket('low_signal')
        self.assertIn('alerts_changed', names)
        self.assertIn('stats_update', names)
        self.assertNotIn('new_incident', names)

    def test_an_incident_uses_its_own_update(self):
        names = self.run_with_socket('port_scan')
        self.assertIn('new_incident', names)
        self.assertNotIn('alerts_changed', names)


class HistoricalAnalysisIsReadOnlyTests(AnalysisTestCase):

    def test_nothing_is_acted_on_during_analysis(self):
        dataset = self.analyze('exfiltration.csv')
        actions = [action for incident in dataset['incidents'] for action in incident['actions']]
        self.assertTrue(actions)
        self.assertEqual({action['status'] for action in actions}, {'PENDING'})
        self.assertEqual(self.client.get('/api/blocklist').get_json(), [])
        self.assertEqual(dataset['incidents'][0]['status'], 'ACTIVE')
        self.assertIn('read-only', self.report_text(dataset))

    def test_unrelated_activity_stays_in_separate_incidents(self):
        response = self.client.post('/api/datasets/generate', json={'profile': 'mixed', 'count': 400, 'duration_seconds': 3600, 'seed': 5})
        dataset = self.wait_for_dataset(response.get_json()['dataset']['dataset_id'])
        self.assertEqual(len(dataset['incidents']), 4)
        hosts = [set(incident['hosts']) for incident in dataset['incidents']]
        for index, first in enumerate(hosts):
            for second in hosts[index + 1:]:
                self.assertFalse(first & second)


class ReportContentTests(AnalysisTestCase):

    def test_every_item_in_the_brief_is_in_the_report(self):
        dataset = self.analyze('exfiltration.csv')
        text = self.report_text(dataset)
        for part in ('ALLSAFE Security Analysis Report', 'Analysis ID', 'Log file:** exfiltration.csv', 'Log type', 'Analysis started', 'Analysis completed',
                     'Total uploaded records', 'Successfully processed records', 'Rejected records', 'Duplicate records', 'Data quality', '### Executed', '### Skipped or failed',
                     'Benign activity (normal events)', 'Suspicious activity', 'Confirmed detections', 'IOC matches', 'IOA rule matches', 'ML classification results',
                     'Anomaly detection results', 'Incident investigation', 'Affected users and hosts', 'Severity distribution', 'Confidence', 'Why this score', 'Evidence:',
                     'MITRE ATT&CK', 'Recommended remediation', 'Known limitations', 'Overall security assessment'):
            self.assertIn(part, text)

    def test_json_and_pdf_downloads(self):
        dataset = self.analyze('clean_activity.csv')
        document = self.client.get(f"/api/reports/{dataset['report_id']}?format=json&download=1")
        self.assertIn('attachment', document.headers['Content-Disposition'])
        content = document.get_json()['content']
        self.assertEqual(content['overall_assessment']['status'], 'NO_THREATS_DETECTED')
        self.assertEqual(content['dataset_filename'], 'clean_activity.csv')
        self.assertTrue(content['engines_executed'])
        pdf = self.client.get(f"/api/reports/{dataset['report_id']}?format=pdf").get_data()
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertIn(b'NO THREATS DETECTED', pdf)

    def test_report_numbers_match_the_stored_results(self):
        dataset = self.analyze('brute_force_windows.csv')
        content = self.client.get(f"/api/reports/{dataset['report_id']}").get_json()['content']
        self.assertEqual(content['detection_results']['alerts'], len(dataset['alerts']))
        self.assertEqual(content['processing_summary']['processed'], dataset['processed_events'])
        self.assertEqual(len(content['incidents']), len(dataset['incidents']))
        self.assertEqual(sum(content['detection_results']['severity_distribution'].values()), len(dataset['alerts']))
        finding = content['detection_results']['ioa_matches'][0]
        self.assertTrue(finding['supporting_event_ids'])
        self.assertTrue(finding['conditions'])
        self.assertTrue(finding['description'])


if __name__ == '__main__':
    unittest.main()
