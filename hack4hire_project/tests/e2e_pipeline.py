"""Black-box test of the whole pipeline against a real server process.

Starts `app.py` on a free loopback port with a throwaway database and drives it only from the
outside: HTTP, file uploads, Socket.IO and, for the live collector, a real local process.
Nothing is imported from the application, so a passing check means the parts work together.

    python tests/e2e_pipeline.py [--json results.json]

Exit code is the number of failed checks. Not part of `unittest discover` because it takes minutes.
"""
import base64
import concurrent.futures
import json
import os
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MB = 1024 * 1024
RESULTS = []


def check(stage, name, passed, detail=''):
    RESULTS.append({'stage': stage, 'check': name, 'passed': bool(passed), 'detail': str(detail)[:400]})
    print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f'  -> {str(detail)[:200]}' if detail and not passed else ''), flush=True)
    return bool(passed)


class Server:
    def __init__(self, workdir):
        self.workdir = workdir
        self.db = os.path.join(workdir, 'e2e.db')
        self.log = os.path.join(workdir, 'server.log')
        self.proc = None
        self.base = None

    def start(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        env = dict(os.environ, ALLSAFE_DB_PATH=self.db, ALLSAFE_PORT=str(port), PYTHONIOENCODING='utf-8', ALLSAFE_MAX_UPLOAD_MB='10', ALLSAFE_NO_ENV_FILE='1')
        for name in ('ALLSAFE_HOST', 'ALLSAFE_DEBUG', 'ALLSAFE_SIMULATED_TELEMETRY', 'ALLSAFE_LOAD_ML'):
            env.pop(name, None)
        log = open(self.log, 'a', encoding='utf-8')
        self.proc = subprocess.Popen([sys.executable, '-u', os.path.join(PROJECT, 'app.py')],
                                     cwd=self.workdir, env=env, stdout=log, stderr=subprocess.STDOUT)
        self.base = f'http://127.0.0.1:{port}'
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                if self.call('/api/health')[0] == 200:
                    return True
            except OSError:
                time.sleep(0.5)
        return False

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=30)
            self.proc = None

    def call(self, path, method='GET', body=None, headers=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        hdrs = dict(headers or {})
        if body is not None:
            hdrs['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, self._decode(response)
        except urllib.error.HTTPError as error:
            return error.code, self._decode(error)

    @staticmethod
    def _decode(response):
        payload = response.read()
        try:
            return json.loads(payload)
        except ValueError:
            return payload.decode('utf-8', 'replace')

    def upload(self, filename, data, source=None):
        boundary = uuid.uuid4().hex
        parts = b''
        if source:
            parts += (f'--{boundary}\r\nContent-Disposition: form-data; name="source"\r\n\r\n{source}\r\n').encode()
        parts += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                  'Content-Type: application/octet-stream\r\n\r\n').encode() + data + f'\r\n--{boundary}--\r\n'.encode()
        return self.call('/api/ingest/upload', 'POST', raw=parts,
                         headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})

    def simulate(self, scenario):
        return self.call(f'/api/simulate/{scenario}', 'POST')


class SocketClient:
    """Minimal Engine.IO v4 polling client, so the test needs no extra dependency"""

    def __init__(self, base):
        self.url = base + '/socket.io/?EIO=4&transport=polling'
        self.events = []
        self.running = True
        with urllib.request.urlopen(self.url, timeout=10) as response:
            opening = json.loads(response.read().decode().split('\x1e')[0][1:])
        self.url += '&sid=' + opening['sid']
        self._send('40')
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _send(self, packet):
        request = urllib.request.Request(self.url, data=packet.encode(), method='POST',
                                         headers={'Content-Type': 'text/plain;charset=UTF-8'})
        urllib.request.urlopen(request, timeout=10).read()

    def _loop(self):
        while self.running:
            try:
                with urllib.request.urlopen(self.url, timeout=40) as response:
                    payload = response.read().decode()
            except OSError:
                return
            for packet in payload.split('\x1e'):
                if packet == '2':
                    self._send('3')
                elif packet.startswith('42'):
                    self.events.append(json.loads(packet[2:]))

    def names(self):
        return [event[0] for event in self.events]

    def close(self):
        self.running = False


def wait_for(predicate, timeout=30, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def attack_files(now):
    """The same multi-stage story as logs a real organization would have: separate files from
    separate systems, where only the auth and host logs name the host and the flow data has only IPs."""
    attacker, host, ip, user = '203.0.113.60', 'web-03', '10.10.3.10', 'deploy'

    def ts(seconds):
        return now - timedelta(seconds=900 - seconds)

    def syslog(seconds):
        moment = ts(seconds).astimezone()
        return f"{moment.strftime('%b')} {moment.day:2d} {moment.strftime('%H:%M:%S')}"

    auth = ''.join(f'{syslog(i * 3)} {host} sshd[4{i:02d}]: Failed password for {user} from {attacker} port {50000 + i} ssh2\n'
                   for i in range(8))
    auth += f'{syslog(60)} {host} sshd[500]: Accepted password for {user} from {attacker} port 50100 ssh2\n'
    auth += f'{syslog(180)} {host} sudo:   {user} : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash\n'
    auth += f'{syslog(240)} {host} useradd[900]: new user: name=backup_svc, UID=1001, GID=1001\n'

    endpoint = json.dumps({'timestamp': ts(600).isoformat(), 'source': 'endpoint', 'event_type': 'process_start',
                           'hostname': host, 'user': user, 'process_name': 'tar', 'command_line': 'tar -czf /tmp/export.tgz /srv/data'}) + '\n'

    flows = 'timestamp,source,source_ip,destination_ip,destination_port,protocol,bytes\n'
    for i in range(3):
        flows += f'{ts(720 + i * 30).isoformat()},network,{ip},198.51.100.77,443,HTTPS,{30 * MB}\n'

    # Real packets for lateral movement. Flow data has addresses but no hostname.
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap
    packets = []
    for i, port in enumerate((445, 3389, 445, 22)):
        packet = IP(src=ip, dst=f'10.10.3.{20 + i}') / TCP(sport=40000 + i, dport=port, flags='S')
        packet.time = ts(420 + i * 10).timestamp()
        packets.append(packet)
    handle, path = tempfile.mkstemp(suffix='.pcap')
    os.close(handle)
    wrpcap(path, packets)
    with open(path, 'rb') as capture:
        pcap = capture.read()
    os.unlink(path)
    return {'auth.log': auth.encode(), 'endpoint.jsonl': endpoint.encode(), 'flows.csv': flows.encode(), 'lateral.pcap': pcap}


def stage_startup(server):
    print('\n[1] Startup from documented command')
    started = server.start()
    if not check('startup', 'server starts and answers /api/health', started):
        return False
    health = server.call('/api/health')[1]
    check('startup', 'all 18 rules load with no errors', health['rules_loaded'] == 18 and not health['rule_errors'], health)
    check('startup', 'health is honest about ML not being validated', health['ml_model_validated'] is False)
    status, page = server.call('/')
    check('startup', 'dashboard page is served', status == 200 and 'ALLSAFE' in page)
    stats = server.call('/api/stats')[1]
    check('startup', 'threat intelligence feed is loaded', len(server.call('/api/iocs')[1]) == 5)
    check('startup', 'no alerts or incidents on an empty database', stats['alerts'] == 0 and stats['incidents'] == 0, stats)
    return True


def stage_scenarios(server):
    print('\n[2] Synthetic generation -> ingestion -> detection, every scenario against its ground truth')
    scenarios = server.call('/api/simulate')[1]['scenarios']
    outcomes = {}
    for scenario in scenarios:
        status, body = server.simulate(scenario['id'])
        outcome = body.get('outcome', {}) if isinstance(body, dict) else {}
        outcomes[scenario['id']] = outcome
        check('detection', f"{scenario['id']}: fired exactly {scenario['expected_rules'] or 'nothing'}",
              status == 200 and not outcome.get('missed_rules') and not outcome.get('unexpected_rules')
              and sorted(outcome.get('fired_rules', [])) == sorted(scenario['expected_rules']),
              f"fired={outcome.get('fired_rules')}")
    return outcomes


def stage_normalization(server):
    print('\n[3] Normalization across sources')
    logs = server.call('/api/logs?limit=1000')[1]
    simulated = [log for log in logs if log.get('origin') == 'simulation']
    check('normalization', 'all three sources present', {log['source'] for log in simulated} == {'application', 'endpoint', 'network'})
    required = ('event_id', 'timestamp', 'ingestion_timestamp', 'source', 'event_type', 'event_category', 'normalized_fields')
    missing = [field for field in required if any(field not in log for log in simulated)]
    check('normalization', 'every event has the schema fields', not missing, missing)
    check('normalization', 'event ids are unique', len({log['event_id'] for log in logs}) == len(logs))
    check('normalization', 'timestamps are normalized to UTC', all(log['timestamp'].endswith('+00:00') for log in simulated))


def stage_investigation(server, incident_id):
    print('\n[4] Correlation, risk scoring and investigation of the multi-stage incident')
    status, detail = server.call(f'/api/incidents/{incident_id}')
    if not check('investigation', 'incident detail loads', status == 200, detail):
        return None
    incident, alerts, timeline = detail['incident'], detail['alerts'], detail['timeline']
    check('correlation', 'all 11 detections are in one incident', len(alerts) == 11, [a['rule_id'] for a in alerts])
    check('correlation', 'every alert states why it was linked', all(a['correlation_reasons'] for a in alerts))

    breakdown = incident['score_breakdown']
    risk = breakdown['risk']
    check('risk', 'severity is the highest alert severity', incident['severity'] == 'CRITICAL')
    check('risk', 'every risk component has a reason', all(c['reason'] for c in risk['components']))
    check('risk', 'risk components add up to the subtotal', abs(sum(c['points'] for c in risk['components']) - risk['subtotal']) < 0.05)
    recomputed = min(100, round(risk['subtotal']))
    check('risk', 'stored risk matches an independent recomputation', recomputed == incident['risk_score'], (recomputed, incident['risk_score']))

    # Independently recompute confidence from the alert values
    best = {}
    for alert in alerts:
        best[alert['rule_id']] = max(best.get(alert['rule_id'], 0), alert['confidence'] * alert['correlation_score'])
    doubt = 1.0
    for value in best.values():
        doubt *= 1 - value / 100
    check('risk', 'stored confidence matches an independent recomputation',
          min(99, round((1 - doubt) * 100)) == incident['confidence'], incident['confidence'])

    check('investigation', 'timeline is in time order', [t['timestamp'] for t in timeline] == sorted(t['timestamp'] for t in timeline))
    known = {event['event_id'] for event in detail['related_events']}
    check('investigation', 'every timeline event exists in the related events',
          all(event_id in known for entry in timeline for event_id in entry['event_ids']))
    sampled = [s['event_id'] for a in alerts for s in a['evidence']['sample_events']]
    check('investigation', 'every evidence sample points to a stored event', all(event_id in known for event_id in sampled))
    check('investigation', 'original raw events are preserved', all(isinstance(e['raw_event'], dict) for e in detail['related_events']))
    check('investigation', 'every rule alert shows its rule logic and matched group',
          all('rule_logic' in a['evidence'] and 'matched_group' in a['evidence'] for a in alerts if a['detection_type'] == 'IOA'))
    ioc = [a for a in alerts if a['detection_type'] == 'IOC']
    check('investigation', 'the IOC alert names the indicator and feed',
          ioc and ioc[0]['evidence']['matched_indicator'] == '198.51.100.77' and ioc[0]['evidence']['feed_source'])
    check('investigation', 'MITRE techniques and recommendations are present', incident['mitre'] and incident['remediation'])
    return detail


def stage_response(server, incident_id):
    print('\n[5] Analyst-approved simulated response')
    status, body = server.call(f'/api/incidents/{incident_id}/response-actions')
    if not check('response', 'incident has recommended actions', status == 200 and isinstance(body, list) and body, f'{status} {str(body)[:120]}'):
        return
    check('response', 'all actions start PENDING', all(a['status'] == 'PENDING' for a in body))
    check('response', 'all actions are simulated', all(a['mode'] == 'simulated' for a in body))
    check('response', 'each action states which detection recommended it', all(a['recommended_by'] and a['rationale'] for a in body))
    by_type = {a['action_type']: a for a in body}
    check('response', 'proportionate actions are recommended',
          {'block_test_ip', 'disable_test_account', 'investigate_source_ip'} <= set(by_type), sorted(by_type))

    block = by_type['block_test_ip']
    account = by_type['disable_test_account']
    review = by_type['investigate_source_ip']
    act = lambda action, verb, payload=None: server.call(f"/api/response-actions/{action['id']}/{verb}", 'POST', payload or {})

    check('response', 'execution before approval is refused', act(block, 'execute', {'analyst': 'e2e'})[0] == 409)
    check('response', 'a decision without an analyst name is refused', act(block, 'decision', {'decision': 'approve'})[0] == 400)
    check('response', 'an unknown decision is refused', act(block, 'decision', {'decision': 'maybe', 'analyst': 'e2e'})[0] == 400)
    check('response', 'an invalid modified target is refused',
          act(block, 'decision', {'decision': 'modify', 'analyst': 'e2e', 'target': 'not-an-ip'})[0] == 400)
    check('response', 'an unknown action id is a 404', server.call('/api/response-actions/999999/execute', 'POST', {'analyst': 'e2e'})[0] == 404)
    check('response', 'a cross-origin approval is refused',
          server.call(f"/api/response-actions/{block['id']}/decision", 'POST', {'decision': 'approve', 'analyst': 'x'},
                      headers={'Origin': 'https://evil.example'})[0] == 403)
    check('response', 'failed attempts did not change the action',
          server.call(f'/api/incidents/{incident_id}/response-actions')[1][0]['status'] == 'PENDING')

    status, approved = act(block, 'decision', {'decision': 'approve', 'analyst': 'e2e-analyst', 'reason': 'Confirmed by evidence'})
    check('response', 'an analyst can approve', status == 200 and approved['status'] == 'APPROVED' and approved['decided_by'] == 'e2e-analyst', approved)
    status, executed = act(block, 'execute', {'analyst': 'e2e-analyst'})
    check('response', 'the approved action runs in simulation', status == 200 and executed['status'] == 'EXECUTED', executed)
    result = executed.get('result') or {}
    check('response', 'the result says nothing real changed', result.get('simulated') is True and result.get('real_system_changed') is False, result)
    check('response', 'the action was verified', (executed.get('verification') or {}).get('verified') is True, executed.get('verification'))
    check('response', 'running it twice is refused', act(block, 'execute', {'analyst': 'e2e-analyst'})[0] == 409)
    check('response', 'a decided action cannot be decided again', act(block, 'decision', {'decision': 'reject', 'analyst': 'e2e'})[0] == 409)
    check('response', 'the real blocklist was not touched', server.call('/api/blocklist')[1] == [])

    status, rejected = act(account, 'decision', {'decision': 'reject', 'analyst': 'e2e-analyst', 'reason': 'Service account, verifying first'})
    check('response', 'an analyst can reject', status == 200 and rejected['status'] == 'REJECTED', rejected)
    check('response', 'a rejected action cannot run', act(account, 'execute', {'analyst': 'e2e-analyst'})[0] == 409)

    status, modified = act(review, 'decision', {'decision': 'modify', 'analyst': 'e2e-analyst', 'target': '203.0.113.51', 'reason': 'Also a related address'})
    check('response', 'an analyst can modify the target', status == 200 and modified['status'] == 'APPROVED' and modified['target'] == '203.0.113.51', modified)
    check('response', 'the original recommendation is kept', modified.get('original_target') == review['target'], modified.get('original_target'))
    status, done = act(review, 'execute', {'analyst': 'e2e-analyst'})
    check('response', 'the modified action runs', status == 200 and done['status'] == 'EXECUTED', done)

    # A failure must be recorded plainly: the playbook protects critical infrastructure
    protected = next((a for a in server.call(f'/api/incidents/{incident_id}/response-actions')[1]
                      if a['status'] == 'PENDING' and a['action_type'] in ('terminate_test_process', 'collect_additional_logs')), None)
    extra = server.simulate('brute_force')[1]['outcome']
    other = server.call(f"/api/incidents/{extra['incident_ids'][0]}/response-actions")[1]
    guarded = next(a for a in other if a['action_type'] == 'block_test_ip')
    act(guarded, 'decision', {'decision': 'modify', 'analyst': 'e2e-analyst', 'target': '198.51.100.10', 'reason': 'Testing the safeguard'})
    status, failed = act(guarded, 'execute', {'analyst': 'e2e-analyst'})
    check('response', 'blocking a protected address fails and says why',
          failed.get('status') == 'FAILED' and 'protected' in str(failed.get('result')).lower(), failed)
    check('response', 'a failed action has a verification result', (failed.get('verification') or {}).get('verified') is False, failed.get('verification'))
    check('response', 'other pending actions stay pending', protected is None or protected['status'] == 'PENDING')

    status, audit = server.call(f'/api/audit?incident_id={incident_id}&limit=200')
    if not check('audit', 'the audit trail is available', status == 200 and isinstance(audit, list) and audit, f'{status} {str(audit)[:120]}'):
        return
    trail = [(entry['action'], entry['actor']) for entry in audit if entry['entity_id'] == block['id']]
    names = [name for name, _ in sorted(trail, key=lambda item: 0)]
    for expected in ('response_recommended', 'response_approved', 'response_executed', 'response_verified'):
        check('audit', f'block action has {expected}', expected in names, names)
    check('audit', 'the approval records who approved',
          ('response_approved', 'e2e-analyst') in trail, trail)
    check('audit', 'the rejection and modification are recorded',
          any(e['action'] == 'response_rejected' for e in audit) and any(e['action'] == 'response_modified' for e in audit))
    check('audit', 'refused attempts are recorded too', any(e['action'] == 'response_refused' for e in audit))
    check('audit', 'entries have timestamps', all(e['timestamp'] for e in audit))

    detail = server.call(f'/api/incidents/{incident_id}')[1]
    check('investigation', 'the investigation view includes response actions and audit',
          detail.get('response_actions') and detail.get('audit_log'))
    db = sqlite3.connect(server.db)
    tampered = False
    try:
        db.execute('DELETE FROM audit_log')
        db.commit()
        tampered = True
    except sqlite3.DatabaseError:
        pass
    db.close()
    check('audit', 'the audit log refuses deletion', not tampered)


def stage_file_attack(server, now):
    print('\n[6] The same attack as real log files from separate systems')
    stats_before = server.call('/api/stats')[1]
    reports = {}
    for name, data in attack_files(now).items():
        status, report = server.upload(name, data)
        reports[name] = report
        check('upload', f'{name} accepted', status == 200 and report.get('stored', 0) > 0 and not report.get('rejected'), report)
    alerts = server.call('/api/alerts?limit=200')[1]
    fired = {a['rule_id'] for a in alerts if 'web-03' in json.dumps(a['entities']) or '10.10.3.10' in json.dumps(a['entities'])
             or '203.0.113.60' in json.dumps(a['entities'])}
    for rule, meaning in (('IOA-001', 'brute force from sshd log'), ('IOA-002', 'success after failures'),
                          ('IOA-003', 'privilege escalation from sudo log'), ('IOA-004', 'account creation from useradd log'),
                          ('IOA-009', 'lateral movement from PCAP'), ('IOA-007', 'exfiltration from flow CSV'),
                          ('IOC-IP', 'IOC match in flow CSV'), ('IOA-016', 'archive staging from endpoint JSONL')):
        check('upload', f'{meaning} ({rule})', rule in fired, sorted(fired))
    incidents = [i for i in server.call('/api/incidents?limit=200')[1]
                 if any(value in json.dumps(i.get('entities')) for value in ('web-03', '10.10.3.10', '203.0.113.60'))]
    check('correlation', 'separate files correlate into one incident', len(incidents) == 1,
          [(i['incident_uid'], sorted((i.get('entities') or {}).keys()), i['alert_count']) for i in incidents])
    return stats_before


def stage_socket(server):
    print('\n[7] Live updates over Socket.IO')
    try:
        client = SocketClient(server.base)
    except OSError as error:
        check('socket', 'client connects', False, error)
        return
    check('socket', 'client connects', True)
    time.sleep(1)
    check('socket', 'initial stats are pushed', 'stats_update' in client.names(), client.names()[:5])
    outcome = server.simulate('webshell')[1]['outcome']
    arrived = wait_for(lambda: 'new_incident' in client.names(), 10)
    check('socket', 'new_incident is pushed', arrived, sorted(set(client.names())))
    logs = [e[1] for e in client.events if e[0] == 'new_log']
    run_logs = [log for log in logs if log.get('ingest_batch') == outcome['run_id']]
    check('socket', 'scenario events are streamed with their detections', run_logs and any(log.get('detections') for log in run_logs), len(run_logs))
    check('socket', 'streamed events omit the raw payload', all('raw_event' not in log for log in logs))
    pushed = next((e[1] for e in client.events if e[0] == 'new_incident'), {})
    check('socket', 'the pushed incident matches the API', pushed.get('id') in outcome['incident_ids'] and pushed.get('risk_score') is not None, pushed.get('id'))
    client.close()


def stage_live_collector(server):
    print('\n[8] Real collector: a real local process detected without simulation')
    if platform.system() != 'Windows':
        check('live', 'skipped: this check uses PowerShell', True)
        return
    # Harmless: encoded form of "Start-Sleep 15". The encoding is what the rule looks for.
    encoded = base64.b64encode('Start-Sleep 15'.encode('utf-16-le')).decode()
    process = subprocess.Popen(['powershell.exe', '-enc', encoded], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    host = platform.node()
    try:
        alert = wait_for(lambda: next((a for a in server.call('/api/alerts?limit=200&rule_id=IOA-008')[1]
                                       if host in a['entities'].get('hostname', [])), None), 25)
    finally:
        process.terminate()
        process.wait(timeout=10)
    if not check('live', 'real encoded PowerShell raises IOA-008', alert, f'no alert within 25s on {host}'):
        return
    logs = [log for log in server.call('/api/logs?limit=1000&source=endpoint')[1]
            if log['event_type'] == 'process_start' and 'powershell' in (log.get('process_name') or '').lower()]
    check('live', 'the event is labelled as real telemetry', any(log['origin'] == 'live' for log in logs))
    check('live', 'the real command line was captured', any(encoded in (log.get('command_line') or '') for log in logs))
    check('live', 'the real hostname was captured', any(log.get('hostname') == host for log in logs))


def stage_reopen(server):
    print('\n[9] Activity after an incident is closed')
    now = datetime.now(timezone.utc)
    events = [{'timestamp': (now - timedelta(seconds=60 - i)).isoformat(), 'source': 'application',
               'event_type': 'authentication_failure', 'src_ip': '203.0.113.70', 'hostname': 'crm-01', 'user': 'sales'} for i in range(6)]
    body = server.call('/api/ingest/events', 'POST', {'events': events})[1]
    incident_id = body['detection']['incidents_created'][0]
    db = sqlite3.connect(server.db)
    db.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ?", (incident_id,))
    db.commit()
    db.close()
    more = [{'timestamp': (now - timedelta(seconds=10 - i)).isoformat(), 'source': 'application',
             'event_type': 'authentication_failure', 'src_ip': '203.0.113.70', 'hostname': 'crm-01', 'user': 'sales'} for i in range(6)]
    server.call('/api/ingest/events', 'POST', {'events': more})
    incidents = [i for i in server.call('/api/incidents?limit=500')[1] if '203.0.113.70' in json.dumps(i.get('entities'))]
    check('correlation', 'new attack activity after closure opens a new active incident',
          any(i['status'] == 'ACTIVE' for i in incidents), [(i['id'], i['status'], i['event_count']) for i in incidents])
    resolved = next((i for i in incidents if i['id'] == incident_id), {})
    check('correlation', 'the closed incident is left as it was', resolved.get('event_count') == 6, resolved.get('event_count'))


def stage_concurrency(server):
    print('\n[10] Concurrent load')
    names = ['brute_force', 'port_scan', 'exfil', 'lateral', 'benign', 'multi_stage', 'webshell', 'benign']
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        replies = list(pool.map(server.simulate, names))
    check('load', '8 parallel scenarios all succeed', all(status == 200 for status, _ in replies), [s for s, _ in replies])
    wrong = [(b['outcome']['scenario'], b['outcome']['missed_rules'], b['outcome']['unexpected_rules']) for s, b in replies
             if s == 200 and (b['outcome']['missed_rules'] or b['outcome']['unexpected_rules'])]
    check('load', 'each kept exactly its ground truth under concurrency', not wrong, wrong)

    now = datetime.now(timezone.utc)
    lines = []
    for i in range(20000):
        lines.append(json.dumps({'timestamp': (now - timedelta(seconds=20000 - i)).isoformat(), 'source': 'application',
                                 'event_type': 'http_request', 'src_ip': f'10.70.{i % 200}.{i % 250 + 1}', 'method': 'GET',
                                 'endpoint': f'/page/{i}', 'status_code': 200}))
    lines += [json.dumps({'timestamp': (now - timedelta(seconds=30 - i)).isoformat(), 'source': 'application',
                          'event_type': 'authentication_failure', 'src_ip': '203.0.113.80', 'hostname': 'bulk-01', 'user': 'root'}) for i in range(6)]
    started = time.time()
    status, report = server.upload('bulk.jsonl', '\n'.join(lines).encode())
    elapsed = time.time() - started
    check('load', f'20,006 event upload stored and analyzed in {elapsed:.1f}s', status == 200 and report.get('stored') == 20006, str(report)[:150])
    check('load', 'the attack hidden in bulk data was found', status == 200 and report['detection']['alerts_created'] >= 1, report.get('detection'))
    check('load', 'bulk benign traffic raised no extra incidents', status == 200 and len(report['detection']['incidents_created']) == 1, report.get('detection'))

    started = time.time()
    server.simulate('brute_force')
    check('load', f'a scenario still runs quickly after bulk load ({time.time() - started:.2f}s)', time.time() - started < 10)


def stage_hostile(server):
    print('\n[11] Malformed and hostile input')
    for name, data, reason in (('x.exe', b'MZ', 'executable'), ('a.json', b'{', 'broken JSON'), ('a.pcap', b'nope', 'fake capture'),
                               ('a.log', b'\xff\xfe\x00', 'binary as text'), ('a.json', b'', 'empty file')):
        check('hostile', f'{reason} is refused', server.upload(name, data)[0] == 400)
    check('hostile', 'an oversized upload is refused', server.upload('big.log', b'x' * (12 * MB))[0] == 413)
    poison = server.call('/api/ingest/events', 'POST', {'events': [
        {'timestamp': '2026-01-01T00:00:00Z', 'source': 'network', 'src_ip': "'; DROP TABLE logs;--", 'dst_port': 'x', 'bytes': 'lots'},
        {'timestamp': '2026-01-01T00:00:00Z', 'source': 'endpoint', 'event_type': 'process_start', 'process_name': '<script>alert(1)</script>'},
        {'timestamp': 'not a time', 'source': 'network'},
    ]})[1]
    check('hostile', 'poison records are contained', poison.get('stored') == 2 and poison.get('rejected') == 1, poison)
    check('hostile', 'the database survived', server.call('/api/stats')[1]['total'] > 0)
    outcome = server.simulate('brute_force')[1]['outcome']
    check('hostile', 'detection still works afterwards', not outcome['missed_rules'], outcome)
    check('hostile', 'the debugger console is not exposed', server.call('/console')[0] == 404)
    check('hostile', 'GET cannot trigger a simulation', server.call('/api/simulate/benign')[0] == 405)


def stage_restart(server):
    print('\n[12] Restart')
    db_counts = lambda: sqlite3.connect(server.db).execute(
        "SELECT (SELECT COUNT(*) FROM alerts WHERE rule_id LIKE 'IOA-00%'), (SELECT COUNT(*) FROM incidents),"
        " (SELECT COUNT(*) FROM logs WHERE origin = 'simulation')").fetchone()
    before = db_counts()
    health = server.call('/api/health')[1]
    server.stop()
    restarted = server.start()
    if not check('restart', 'server restarts on the same database', restarted):
        return
    time.sleep(6)
    after = db_counts()
    check('restart', 'nothing is reprocessed or duplicated', before == after, (before, after))
    check('restart', 'investigation data is still available', server.call('/api/incidents/1')[0] == 200)
    outcome = server.simulate('multi_stage')[1]['outcome']
    check('restart', 'the pipeline still works after restart', not outcome['missed_rules'] and not outcome['unexpected_rules'], outcome)
    actions = server.call(f"/api/incidents/{outcome['incident_ids'][0]}/response-actions")
    check('restart', 'response actions are still generated after restart', actions[0] == 200 and actions[1], actions[0])
    check('restart', 'the engine reported no internal errors before restart', health['engine']['errors'] == 0, health['engine'])


def main():
    workdir = tempfile.mkdtemp(prefix='allsafe-e2e-')
    server = Server(workdir)
    started = time.time()
    try:
        if stage_startup(server):
            outcomes = stage_scenarios(server)
            stage_normalization(server)
            incident_id = outcomes['multi_stage']['incident_ids'][0]
            stage_investigation(server, incident_id)
            for stage, *args in ((stage_response, server, incident_id),
                                 (stage_file_attack, server, datetime.now(timezone.utc)),
                                 (stage_socket, server), (stage_live_collector, server), (stage_reopen, server),
                                 (stage_concurrency, server), (stage_hostile, server), (stage_restart, server)):
                try:
                    stage(*args)
                except Exception as error:
                    check(stage.__name__, 'stage completed without crashing the test', False, f'{type(error).__name__}: {error}')
            health = server.call('/api/health')[1]
            check('final', 'the engine reported no internal errors', health['engine']['errors'] == 0, health['engine'])
    finally:
        server.stop()
    with open(server.log, encoding='utf-8', errors='replace') as handle:
        log = handle.read()
    tracebacks = log.count('Traceback (most recent call last)')
    check('final', 'no server tracebacks in the log', tracebacks == 0, f'{tracebacks} tracebacks')
    if tracebacks:
        print(log[log.index('Traceback'):][:2500])

    failed = [r for r in RESULTS if not r['passed']]
    print(f"\n{'=' * 60}\nTOTAL {len(RESULTS)} checks: {len(RESULTS) - len(failed)} passed, {len(failed)} failed, {time.time() - started:.0f}s")
    for result in failed:
        print(f"  FAIL [{result['stage']}] {result['check']}: {result['detail'][:300]}")
    if '--json' in sys.argv:
        with open(sys.argv[sys.argv.index('--json') + 1], 'w', encoding='utf-8') as out:
            json.dump(RESULTS, out, indent=1)
    shutil.rmtree(workdir, ignore_errors=True)
    return len(failed)


if __name__ == '__main__':
    sys.exit(main())
