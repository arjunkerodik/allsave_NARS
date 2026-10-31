"""Creates the sample datasets in data/samples. Run it again and you get the same files.

    python scripts/make_sample_datasets.py

Everything is synthetic. Addresses are private or from the RFC 5737 documentation ranges, and
domains use the reserved .example name. None of it describes a real system or a real attack.
The flow files use the CIC-IDS2017 column layout, but their values are random, so they show
that the model runs on compatible data. They say nothing about how accurate it is.
"""
import csv
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('ALLSAFE_LOAD_ML', '0')

from utils.dataset_generator import normal_events  # noqa: E402
from utils.nids_engine import FLOW_FEATURES  # noqa: E402

OUT = os.path.join(ROOT, 'data', 'samples')
START = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
MB = 1024 * 1024
FLOW_COLUMNS = [name.replace('_', ' ') if name not in ('Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward') else name for name in FLOW_FEATURES]


def at(seconds):
    return (START + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def syslog_at(seconds):
    moment = START + timedelta(seconds=seconds)
    return f"{moment.strftime('%b')} {moment.day:2d} {moment.strftime('%H:%M:%S')}"


def write_csv(name, rows, columns=None):
    columns = columns or list(dict.fromkeys(key for row in rows for key in row))
    with open(os.path.join(OUT, name), 'w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def write_lines(name, lines):
    with open(os.path.join(OUT, name), 'w', encoding='utf-8', newline='\n') as handle:
        handle.write('\n'.join(lines) + '\n')


def write_jsonl(name, rows):
    write_lines(name, [json.dumps(row) for row in rows])


def clean_activity():
    """Ordinary activity. Nothing here should trigger a detection."""
    rng = random.Random(7)
    rows = []
    start = START.timestamp()
    for when, source, fields in sorted(normal_events(rng, 400, start, start + 7200), key=lambda item: item[0]):
        row = {'timestamp': datetime.fromtimestamp(when, timezone.utc).isoformat(), 'source': source, 'label': 'normal'}
        row.update({key: value for key, value in fields.items() if value is not None})
        rows.append(row)
    write_csv('clean_activity.csv', rows)


def brute_force_windows():
    """A Windows Security log export: failed logons from one address, then a success"""
    rows = [{'TimeCreated': at(i * 8), 'EventID': 4625, 'Computer': 'dc-01.corp.example', 'TargetUserName': 'svc_backup',
             'IpAddress': '203.0.113.44', 'LogonType': 3, 'Channel': 'Security'} for i in range(9)]
    rows.append({'TimeCreated': at(90), 'EventID': 4624, 'Computer': 'dc-01.corp.example', 'TargetUserName': 'svc_backup',
                 'IpAddress': '203.0.113.44', 'LogonType': 3, 'Channel': 'Security'})
    rows += [{'TimeCreated': at(200 + i * 60), 'EventID': 4624, 'Computer': 'wks-12.corp.example', 'TargetUserName': f'user{i}',
              'IpAddress': f'10.0.5.{i + 10}', 'LogonType': 2, 'Channel': 'Security'} for i in range(5)]
    write_csv('brute_force_windows.csv', rows)


def linux_auth():
    lines = [f'{syslog_at(i * 6)} bastion-01 sshd[{4100 + i}]: Failed password for root from 203.0.113.61 port {42000 + i} ssh2' for i in range(7)]
    lines.append(f'{syslog_at(50)} bastion-01 sshd[4120]: Accepted password for root from 203.0.113.61 port 42100 ssh2')
    lines.append(f'{syslog_at(70)} bastion-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/su -')
    write_lines('linux_auth.log', lines)


def firewall_ufw():
    """A kernel firewall log: one address probing twenty ports"""
    write_lines('firewall_ufw.log', [
        f'{syslog_at(i * 2)} fw-01 kernel: [ 1234.{i:03d}] [UFW BLOCK] IN=eth0 OUT= MAC=00:00 SRC=203.0.113.70 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID={i} DF PROTO=TCP SPT={50000 + i} DPT={20 + i} WINDOW=1024 RES=0x00 SYN URGP=0'
        for i in range(20)])


def suspicious_network():
    """A workstation reaching an external address on a remote-access port. Weak on its own."""
    rows = [{'timestamp': at(i * 300), 'src_ip': '10.0.8.21', 'dst_ip': '198.51.100.66', 'dst_port': 4444, 'protocol': 'TCP', 'bytes': 1800 + i * 13, 'hostname': 'wks-21'} for i in range(4)]
    rows += [{'timestamp': at(i * 400 + 30), 'src_ip': f'10.0.8.{30 + i}', 'dst_ip': '198.51.100.44', 'dst_port': 443, 'protocol': 'TCP', 'bytes': 2000 + i * 7, 'hostname': f'wks-{30 + i}'} for i in range(6)]
    write_csv('suspicious_network.csv', rows)


def ioc_match():
    write_jsonl('ioc_match.jsonl', [
        {'timestamp': at(0), 'source': 'network', 'src_ip': '10.0.9.5', 'dst_ip': '198.51.100.77', 'dst_port': 443, 'protocol': 'TCP', 'bytes': 2400, 'hostname': 'wks-05'},
        {'timestamp': at(60), 'source': 'network', 'src_ip': '10.0.9.5', 'dst_ip': '198.51.100.45', 'dst_port': 443, 'protocol': 'TCP', 'bytes': 900, 'hostname': 'wks-05'},
        {'timestamp': at(120), 'source': 'endpoint', 'event_type': 'file_create', 'hostname': 'wks-06', 'user': 'asha', 'file_path': r'C:\Temp\tool.exe',
         'file_hash': 'a' * 64, 'details': 'New file written'},
        {'timestamp': at(180), 'source': 'application', 'event_type': 'http_request', 'src_ip': '10.0.9.7', 'method': 'GET',
         'url': 'http://update-check.malware-demo.example/check', 'status_code': 200, 'hostname': 'proxy-01'},
    ])


def privilege_escalation():
    write_jsonl('privilege_escalation.jsonl', [
        {'timestamp': at(0), 'hostname': 'app-07', 'user': 'deploy', 'process_name': 'sudo', 'command_line': 'sudo su -', 'event_type': 'process_start'},
        {'timestamp': at(40), 'hostname': 'app-07', 'user': 'deploy', 'process_name': 'usermod', 'command_line': 'usermod -aG sudo deploy', 'event_type': 'process_start'},
        {'timestamp': at(90), 'hostname': 'app-07', 'user': 'deploy', 'process_name': 'ls', 'command_line': 'ls -la /var/log', 'event_type': 'process_start'},
    ])


def exfiltration():
    rows = [{'timestamp': at(i * 300), 'source': 'network', 'src_ip': '10.0.7.9', 'dst_ip': '198.51.100.48', 'dst_port': 443, 'protocol': 'HTTPS', 'bytes': 15000 + i * 900, 'hostname': 'fin-09'} for i in range(12)]
    rows += [{'timestamp': at(3700 + i * 90), 'source': 'network', 'src_ip': '10.0.7.9', 'dst_ip': '198.51.100.222', 'dst_port': 443, 'protocol': 'HTTPS', 'bytes': 45 * MB, 'hostname': 'fin-09'} for i in range(3)]
    write_csv('exfiltration.csv', rows)


def application_access():
    paths = ('/.env', '/wp-admin/install.php', '/../../etc/passwd', '/phpmyadmin/index.php', '/.git/config')
    rows = [{'timestamp': at(i * 20), 'src_ip': '203.0.113.88', 'method': 'GET', 'path': path, 'status_code': 404, 'hostname': 'web-05', 'user_agent': 'scanner'} for i, path in enumerate(paths)]
    rows += [{'timestamp': at(200 + i * 30), 'src_ip': f'10.0.3.{i + 2}', 'method': 'GET', 'path': '/home', 'status_code': 200, 'hostname': 'web-05', 'user_agent': 'browser'} for i in range(6)]
    write_csv('application_access.csv', rows)


def malformed_records():
    """Some rows are good and some are not. The good ones must still be analyzed."""
    lines = ['timestamp,source,src_ip,dst_ip,user,event_type']
    lines += [f'{at(i * 30)},application,10.0.4.{i + 2},,user{i},authentication_success' for i in range(6)]
    lines += ['not-a-date,application,10.0.4.20,,userx,authentication_success',
              f'{at(300)},application,999.1.1.1,,usery,authentication_success',
              f'{at(310)},application,10.0.4.21',
              f'{at(320)},application,10.0.4.22,,userz,authentication_success,one,too,many',
              f'{at(330)},application,10.0.4.23,300.1.1.1,userw,authentication_success']
    write_lines('malformed_records.csv', lines)


def duplicate_records():
    rows = [{'timestamp': at(i * 60), 'source': 'application', 'src_ip': f'10.0.6.{i + 2}', 'user': f'user{i}', 'event_type': 'authentication_success'} for i in range(5)]
    write_csv('duplicate_records.csv', rows + rows[:3] + rows[:2])


def unsupported_fields():
    rows = [{'timestamp': at(i * 60), 'source': 'application', 'src_ip': f'10.0.2.{i + 2}', 'user': f'user{i}', 'event_type': 'authentication_success',
             'vendor_score': i * 3, 'tenant_ref': f'T-{i}', 'risk_note': 'none'} for i in range(5)]
    write_csv('unsupported_fields.csv', rows)


def missing_timestamps():
    rows = [{'timestamp': at(i * 60) if i % 3 else '', 'source': 'application', 'src_ip': f'10.0.1.{i + 2}', 'user': f'user{i}', 'event_type': 'authentication_success'} for i in range(9)]
    write_csv('missing_timestamps.csv', rows)


def custom_field_names():
    """Field names ALLSAFE cannot recognize by itself, to show the field mapping"""
    rows = [{'when': at(i * 5), 'kind': 'application', 'origin_addr': '203.0.113.95', 'who': 'admin', 'what': 'authentication_failure', 'machine': 'crm-03'} for i in range(6)]
    write_csv('custom_field_names.csv', rows)


def _flow_row(rng, label):
    row = {}
    for column, name in zip(FLOW_COLUMNS, FLOW_FEATURES):
        if name == 'Destination_Port':
            row[column] = rng.choice((443, 80, 53, 22, 8080))
        elif 'Flag' in name or 'Flags' in name:
            row[column] = rng.randint(0, 1)
        elif 'Bulk' in name:
            row[column] = 0
        else:
            row[column] = round(rng.uniform(0, 5000), 3)
    row['Flow Bytes/s'] = 'Infinity' if rng.random() < 0.02 else row['Flow Bytes/s']
    row['Label'] = label
    return row


def cicids_flows():
    """Random values in the CIC-IDS2017 layout: with no addresses or times, like the published ML files"""
    rng = random.Random(11)
    rows = [_flow_row(rng, 'BENIGN' if rng.random() < 0.8 else 'PortScan') for _ in range(200)]
    write_csv('network_flows_cicids.csv', [{f' {key}' if key != 'Label' else ' Label': value for key, value in row.items()} for row in rows])

    timed = []
    for index in range(100):
        base = _flow_row(rng, 'BENIGN' if rng.random() < 0.8 else 'DDoS')
        timed.append({'Flow ID': f'10.0.0.{index % 200 + 1}-192.0.2.10-{50000 + index}-443-6', 'Source IP': f'10.0.0.{index % 200 + 1}', 'Source Port': 50000 + index,
                      'Destination IP': '192.0.2.10', 'Protocol': 6, 'Timestamp': (START + timedelta(seconds=index * 7)).strftime('%d/%m/%Y %H:%M:%S'), **base})
    write_csv('network_flows_cicids_with_addresses.csv', timed)


def threat_feed():
    """A threat intelligence feed: indicators, not events. It holds a few entries that must be left out."""
    write_csv('threat_feed.csv', [
        {'type': 'ipv4', 'value': '198.51.100.77', 'confidence': 'high', 'first_seen': at(0), 'source_count': 2, 'sources': 'example-blog:2026-01-15|example-cert:2026-01-15', 'reason': 'Synthetic: command and control server'},
        {'type': 'domain', 'value': 'malware-c2.example', 'confidence': 'high', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-blog:2026-01-15', 'reason': 'Synthetic: payload delivery domain'},
        {'type': 'domain', 'value': 'phish-login[.]example', 'confidence': 'medium', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-cert:2026-01-15', 'reason': 'Synthetic: written defanged, as feeds often do'},
        {'type': 'url', 'value': 'hxxp://phish-login.example/account', 'confidence': 'low', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-cert:2026-01-15', 'reason': 'Synthetic: credential phishing page'},
        {'type': 'sha256', 'value': 'a' * 64, 'confidence': '0.9', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-lab:2026-01-15', 'reason': 'Synthetic: sample hash'},
        {'type': 'ipv4', 'value': '10.0.0.5', 'confidence': 'high', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-blog:2026-01-15', 'reason': 'Left out: an internal address would flag normal traffic'},
        {'type': 'cve', 'value': 'CVE-2026-0001', 'confidence': 'high', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-blog:2026-01-15', 'reason': 'Left out: not an indicator type that events can match'},
        {'type': 'domain', 'value': 'malware-c2.example', 'confidence': 'high', 'first_seen': at(0), 'source_count': 1, 'sources': 'example-blog:2026-01-15', 'reason': 'Left out: repeated in this file'},
    ])


def main():
    os.makedirs(OUT, exist_ok=True)
    for build in (clean_activity, brute_force_windows, linux_auth, firewall_ufw, suspicious_network, ioc_match, privilege_escalation,
                  exfiltration, application_access, malformed_records, duplicate_records, unsupported_fields, missing_timestamps,
                  custom_field_names, cicids_flows, threat_feed):
        build()
    print('Wrote', len(os.listdir(OUT)), 'files to', OUT)


if __name__ == '__main__':
    main()
