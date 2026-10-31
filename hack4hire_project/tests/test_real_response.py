"""Real mode changes a real firewall, so these tests use a stand-in for netsh and must never reach the real one."""
import os
import subprocess
import unittest
from unittest import mock

import models
from tests.test_api import ApiTestCase
from tests.test_dataset_analysis import AnalysisTestCase
from utils import real_response
from utils.real_response import manual_commands, refusal_reason
from utils.response_engine import AUTOMATION_ACTOR, apply_response_policy, describe_actions, execute_action

BLOCK_TARGET = '203.0.113.50'
HOSTILE_VALUES = ('a&b', 'x y', '$(reboot)', '-rf', 'a;b', 'a|b', 'a\nb', '"quoted"', '%TEMP%', '`whoami`', 'a>b', "it's", '')


class FakeNetsh:
    """Stands in for netsh, and keeps its rules in memory"""

    def __init__(self):
        self.rules = {}
        self.calls = []
        self.options = []
        self.refuse_direction = None

    def __call__(self, arguments, **options):
        self.calls.append(arguments)
        self.options.append(options)
        if arguments[1] == 'interface':
            return subprocess.CompletedProcess(arguments, 0, 'Statically Configured DNS Servers: 192.0.2.53', '')
        verb = arguments[3]
        name = next(item for item in arguments if item.startswith('name='))[5:]
        if verb == 'show':
            return subprocess.CompletedProcess(arguments, 0 if name in self.rules else 1, '', '')
        if verb == 'add':
            if self.refuse_direction and f'dir={self.refuse_direction}' in arguments:
                return subprocess.CompletedProcess(arguments, 1, 'The requested operation requires elevation.', '')
            self.rules.setdefault(name, []).append(arguments)
            return subprocess.CompletedProcess(arguments, 0, 'Ok.', '')
        existed = self.rules.pop(name, None)
        return subprocess.CompletedProcess(arguments, 0 if existed else 1, '', '')

    def changes(self):
        return [call for call in self.calls if call[1] == 'advfirewall' and call[3] in ('add', 'delete')]


class RealModeCase(ApiTestCase):

    real_mode = True

    def setUp(self):
        super().setUp()
        self.netsh = FakeNetsh()
        settings = {'ALLSAFE_REAL_RESPONSE': '1'} if self.real_mode else {}
        environment = mock.patch.dict(os.environ, settings)
        environment.start()
        self.addCleanup(environment.stop)
        if not self.real_mode:
            os.environ.pop('ALLSAFE_REAL_RESPONSE', None)
        for name, value in (('subprocess.run', self.netsh), ('_is_windows', lambda: True), ('is_administrator', lambda: True)):
            patcher = mock.patch(f'utils.real_response.{name}', value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def incident(self, scenario='multi_stage'):
        return self.client.post(f'/api/simulate/{scenario}').get_json()['outcome']['incident_ids'][0]

    def action(self, incident_id, action_type='block_test_ip'):
        actions = self.client.get(f'/api/incidents/{incident_id}/response-actions').get_json()
        return next(item for item in actions if item['action_type'] == action_type)

    def decide(self, action, **fields):
        return self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'approve', 'analyst': 'amy', **fields})

    def run_action(self, action):
        return self.client.post(f"/api/response-actions/{action['id']}/execute", json={'analyst': 'amy'})

    def approve_and_run(self, action):
        self.assertEqual(self.decide(action).status_code, 200)
        response = self.run_action(action)
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()


class RealModeOffTests(RealModeCase):

    real_mode = False

    def test_with_real_mode_off_nothing_touches_the_firewall(self):
        action = self.action(self.incident())
        self.assertFalse(action['runs_for_real'])
        done = self.approve_and_run(action)
        self.assertEqual((done['status'], done['mode']), ('EXECUTED', 'simulated'))
        self.assertIs(done['result']['real_system_changed'], False)
        self.assertEqual(self.netsh.calls, [])

    def test_the_page_is_told_real_mode_is_off(self):
        self.assertEqual(self.client.get('/api/response-mode').get_json()['enabled'], False)


class RealBlockTests(RealModeCase):

    def test_a_real_block_adds_rules_both_ways_with_no_shell(self):
        action = self.action(self.incident())
        self.assertTrue(action['runs_for_real'])
        done = self.approve_and_run(action)
        name = f'name=ALLSAFE-block-{BLOCK_TARGET}'
        self.assertEqual(self.netsh.changes(), [
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule', name, 'dir=in', 'action=block', f'remoteip={BLOCK_TARGET}'],
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule', name, 'dir=out', 'action=block', f'remoteip={BLOCK_TARGET}'],
        ])
        self.assertFalse(any(options.get('shell') for options in self.netsh.options))
        self.assertEqual((done['status'], done['mode']), ('EXECUTED', 'real'))
        self.assertIs(done['result']['real_system_changed'], True)
        self.assertTrue(done['verification']['verified'])
        self.assertIn('Windows Firewall', done['result']['summary'])

    def test_running_it_needs_approval_first(self):
        action = self.action(self.incident())
        self.assertEqual(self.run_action(action).status_code, 409)
        self.assertEqual(self.netsh.changes(), [])

    def test_automation_never_makes_a_real_change(self):
        self.incident('suspicious_process')
        self.incident('port_scan')
        incident_id = self.incident()
        apply_response_policy(incident_id, 'LOW')
        self.assertEqual(self.action(incident_id)['status'], 'HELD')
        self.assertEqual(self.netsh.changes(), [])
        # Even if automation were handed an approved block, it stays in simulation
        action = self.action(incident_id)
        self.decide(action)
        done = execute_action(action['id'], {'analyst': AUTOMATION_ACTOR})
        self.assertEqual(done['mode'], 'simulated')
        self.assertEqual(self.netsh.changes(), [])

    def test_only_the_block_is_ever_real(self):
        incident_id = self.incident()
        for action_type in ('disable_test_account', 'terminate_test_process', 'investigate_source_ip', 'review_account'):
            with self.subTest(action=action_type):
                action = self.action(incident_id, action_type)
                self.assertFalse(action['runs_for_real'])
                done = self.approve_and_run(action)
                self.assertEqual(done['mode'], 'simulated')
        self.assertEqual(self.netsh.calls, [])

    def test_an_internal_address_is_refused(self):
        action = self.action(self.incident())
        self.assertEqual(self.decide(action, decision='modify', target='10.0.0.5').status_code, 200)
        done = self.run_action(action).get_json()
        self.assertEqual(done['status'], 'FAILED')
        self.assertIs(done['result']['real_system_changed'], False)
        self.assertIn('internal', done['result']['error'])
        self.assertEqual(self.netsh.changes(), [])

    def test_addresses_that_must_never_be_blocked(self):
        protected = ['198.51.100.10']
        for address in ('198.51.100.10', '10.1.2.3', '192.168.1.1', '172.16.0.9', '127.0.0.1', '::1', '169.254.1.1', '224.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1', '192.0.2.53', 'not an address'):
            with self.subTest(address=address):
                self.assertIsNotNone(refusal_reason(address, protected))
        self.assertIsNone(refusal_reason(BLOCK_TARGET, protected))

    def test_a_hostile_target_never_reaches_a_command(self):
        action = self.action(self.incident())
        response = self.decide(action, decision='modify', target=f'{BLOCK_TARGET} & calc.exe')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.netsh.changes(), [])

    def test_without_administrator_rights_it_is_refused_and_can_run_later(self):
        action = self.action(self.incident())
        self.assertEqual(self.decide(action).status_code, 200)
        with mock.patch('utils.real_response.is_administrator', lambda: False):
            refused = self.run_action(action)
        self.assertEqual(refused.status_code, 409)
        self.assertIn('administrator', refused.get_json()['error'])
        self.assertEqual(self.netsh.changes(), [])
        self.assertEqual(self.action(action['incident_id'])['status'], 'APPROVED')
        # After a restart as administrator, the same approved action runs
        self.assertEqual(self.run_action(action).get_json()['status'], 'EXECUTED')
        self.assertTrue(self.netsh.rules)

    def test_on_another_system_it_is_refused_and_says_why(self):
        action = self.action(self.incident())
        self.assertEqual(self.decide(action).status_code, 200)
        with mock.patch('utils.real_response._is_windows', lambda: False):
            refused = self.run_action(action)
        self.assertEqual(refused.status_code, 409)
        self.assertIn('Windows Firewall', refused.get_json()['error'])
        self.assertEqual(self.netsh.changes(), [])

    def test_a_refused_rule_leaves_nothing_behind(self):
        self.netsh.refuse_direction = 'out'
        done = self.approve_and_run(self.action(self.incident()))
        self.assertEqual(done['status'], 'FAILED')
        self.assertIn('refused', done['result']['error'])
        self.assertEqual(self.netsh.rules, {})

    def test_a_failed_real_block_never_looks_simulated_or_done(self):
        self.netsh.refuse_direction = 'in'
        done = self.approve_and_run(self.action(self.incident()))
        self.assertEqual((done['status'], done['mode']), ('FAILED', 'simulated'))
        self.assertIs(done['result']['simulated'], False)
        self.assertIs(done['verification']['verified'], False)

    def test_undo_removes_the_rule_and_is_recorded(self):
        incident_id = self.incident()
        action = self.action(incident_id)
        self.approve_and_run(action)
        self.assertTrue(self.netsh.rules)
        response = self.client.post(f"/api/response-actions/{action['id']}/undo", json={'analyst': 'amy'})
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()['status'], 'UNDONE')
        self.assertEqual(self.netsh.rules, {})
        audit = [entry['action'] for entry in self.client.get(f'/api/audit?incident_id={incident_id}&limit=500').get_json()]
        self.assertIn('response_undone', audit)
        self.assertEqual(self.client.post(f"/api/response-actions/{action['id']}/undo", json={'analyst': 'amy'}).status_code, 409)

    def test_a_block_can_still_be_undone_after_real_mode_is_turned_off(self):
        action = self.action(self.incident())
        self.approve_and_run(action)
        with mock.patch.dict(os.environ):
            os.environ.pop('ALLSAFE_REAL_RESPONSE')
            self.assertEqual(self.client.post(f"/api/response-actions/{action['id']}/undo", json={'analyst': 'amy'}).status_code, 200)
        self.assertEqual(self.netsh.rules, {})

    def test_a_simulated_action_cannot_be_undone(self):
        action = self.action(self.incident(), 'investigate_source_ip')
        self.approve_and_run(action)
        response = self.client.post(f"/api/response-actions/{action['id']}/undo", json={'analyst': 'amy'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.netsh.changes(), [])

    def test_undo_needs_a_name_and_this_machine(self):
        action = self.action(self.incident())
        self.approve_and_run(action)
        self.assertEqual(self.client.post(f"/api/response-actions/{action['id']}/undo", json={}).status_code, 400)
        refused = self.client.post(f"/api/response-actions/{action['id']}/undo", json={'analyst': 'amy'}, headers={'Origin': 'https://evil.example'})
        self.assertEqual(refused.status_code, 403)
        self.assertTrue(self.netsh.rules)

    def test_the_page_is_told_whether_it_can_run(self):
        self.assertEqual(self.client.get('/api/response-mode').get_json(), {'enabled': True, 'ready': True, 'reason': None})
        with mock.patch('utils.real_response.is_administrator', lambda: False):
            body = self.client.get('/api/response-mode').get_json()
        self.assertEqual((body['enabled'], body['ready']), (True, False))
        self.assertIn('administrator', body['reason'])


class UploadedLogTests(AnalysisTestCase):
    """Historical analysis stays read-only, even in real mode"""

    def test_an_uploaded_log_never_makes_a_real_change(self):
        dataset = self.analyze('exfiltration.csv')
        netsh = FakeNetsh()
        patches = [mock.patch.dict(os.environ, {'ALLSAFE_REAL_RESPONSE': '1'}), mock.patch('utils.real_response.subprocess.run', netsh),
                   mock.patch('utils.real_response._is_windows', lambda: True), mock.patch('utils.real_response.is_administrator', lambda: True)]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.assertTrue(dataset['processed_events'])
        actions = [item for item in self.client.get('/api/response-actions?limit=500').get_json() if item['action_type'] == 'block_test_ip']
        self.assertTrue(actions)
        for action in actions:
            self.assertFalse(action['runs_for_real'])
            self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'approve', 'analyst': 'amy'})
            done = self.client.post(f"/api/response-actions/{action['id']}/execute", json={'analyst': 'amy'}).get_json()
            self.assertEqual(done['mode'], 'simulated')
        self.assertEqual(netsh.calls, [])


class ManualCommandTests(unittest.TestCase):

    def test_each_action_has_commands_filled_in(self):
        cases = (
            ('block_test_ip', '203.0.113.50', 'netsh advfirewall firewall add rule name="ALLSAFE-block-203.0.113.50" dir=in action=block remoteip=203.0.113.50', 'iptables -I INPUT -s 203.0.113.50 -j DROP'),
            ('disable_test_account', 'svc_admin', 'net user svc_admin /active:no', 'usermod -L svc_admin'),
            ('terminate_test_process', 'psexec.exe', 'taskkill /IM psexec.exe /F', 'pkill -x psexec'),
            ('investigate_source_ip', '203.0.113.50', 'netstat -ano | findstr 203.0.113.50', 'ss -tunap | grep 203.0.113.50'),
            ('review_account', 'svc_admin', 'net user svc_admin', 'id svc_admin'),
            ('inspect_process', 'psexec.exe', 'tasklist /V /FI "IMAGENAME eq psexec.exe"', 'ps -C psexec -o pid,ppid,user,cmd'),
            ('collect_additional_logs', 'web-01', 'wevtutil qe Security /c:500 /rd:true /f:text > allsafe-web-01.txt', 'journalctl -n 500 > allsafe-web-01.log'),
        )
        for action_type, target, windows, linux in cases:
            with self.subTest(action=action_type):
                commands = manual_commands(action_type, target)
                self.assertTrue(commands['note'])
                self.assertIn(windows, commands['windows'][-1] if action_type == 'terminate_test_process' else commands['windows'][0])
                self.assertIn(linux, ' '.join(commands['linux']))

    def test_what_can_be_undone_says_how_and_what_cannot_says_nothing(self):
        self.assertIn('delete rule', manual_commands('block_test_ip', '203.0.113.50')['windows_undo'][0])
        self.assertIn('-D INPUT', manual_commands('block_test_ip', '203.0.113.50')['linux_undo'][0])
        self.assertIn('/active:yes', manual_commands('disable_test_account', 'bob')['windows_undo'][0])
        self.assertEqual(manual_commands('terminate_test_process', 'bad.exe')['windows_undo'], [])
        self.assertIn('cannot be undone', manual_commands('terminate_test_process', 'bad.exe')['note'])

    def test_an_ipv6_block_uses_ip6tables(self):
        self.assertIn('ip6tables', manual_commands('block_test_ip', '2001:db8::1')['linux'][0])

    def test_a_domain_prefix_is_dropped(self):
        self.assertEqual(manual_commands('review_account', 'CORP\\alice')['windows'], ['net user alice'])

    def test_a_hostile_value_from_a_log_gets_no_command(self):
        for action_type in ('disable_test_account', 'terminate_test_process', 'review_account', 'inspect_process', 'collect_additional_logs', 'block_test_ip', 'investigate_source_ip'):
            for value in HOSTILE_VALUES:
                with self.subTest(action=action_type, value=value):
                    self.assertIsNone(manual_commands(action_type, value))

    def test_an_unknown_action_has_no_commands(self):
        self.assertIsNone(manual_commands('something_new', 'web-01'))


class DescribeTests(RealModeCase):

    def test_a_protected_target_shows_no_disruptive_command(self):
        action = self.action(self.incident(), 'disable_test_account')
        described = describe_actions([{**action, 'target': 'Administrator'}])[0]
        self.assertIsNone(described['manual_commands'])

    def test_the_incident_page_gets_the_commands(self):
        incident_id = self.incident()
        detail = self.client.get(f'/api/incidents/{incident_id}').get_json()
        self.assertTrue(all('manual_commands' in action and 'runs_for_real' in action for action in detail['response_actions']))
        self.assertTrue(any(action['manual_commands'] for action in detail['response_actions']))
        self.assertEqual(models.get_dashboard_counts()['blocked_ips'], 0)


if __name__ == '__main__':
    unittest.main()
