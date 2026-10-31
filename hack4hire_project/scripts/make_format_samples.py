"""Synthetic files in the shape of common log formats, for trying Log Analysis and for the tests.

    python scripts/make_format_samples.py

Every address and name is made up. Writes data/samples/formats.
"""
import csv
import json
import os
import sys

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'samples', 'formats')
os.makedirs(out, exist_ok=True)


def write(name, text):
    with open(os.path.join(out, name), 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(text)


attacker = '198.51.100.23'
# Zeek conn.log
zeek = ['#separator \\x09', '#set_separator\t,', '#empty_field\t(empty)', '#unset_field\t-', '#path\tconn', '#open\t2026-01-15-09-00-00',
        '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents',
        '#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]']
for i in range(30):
    zeek.append(f'{1768467600 + i}.0\tC{i:05d}\t10.1.1.5\t{50000 + i}\t10.1.1.{20 + i}\t445\ttcp\t-\t0.1\t100\t0\tS0\tT\tT\t0\tS\t1\t60\t0\t0\t-')
write('zeek_conn.log', '\n'.join(zeek) + '\n')
# Suricata eve.json
eve = []
for i in range(12):
    eve.append({'timestamp': f'2026-01-15T09:00:{i:02d}.000000+0000', 'flow_id': 1000 + i, 'event_type': 'alert', 'src_ip': attacker, 'src_port': 40000 + i, 'dest_ip': '10.1.1.9', 'dest_port': 22, 'proto': 'TCP',
                'alert': {'action': 'allowed', 'gid': 1, 'signature_id': 2001219, 'rev': 20, 'signature': 'ET SCAN Potential SSH Scan', 'category': 'Attempted Information Leak', 'severity': 2}})
write('suricata_eve.json', '\n'.join(json.dumps(item) for item in eve) + '\n')
# AWS CloudTrail
records = [{'eventVersion': '1.08', 'eventTime': f'2026-01-15T09:0{i}:00Z', 'eventSource': 'signin.amazonaws.com', 'eventName': 'ConsoleLogin', 'awsRegion': 'us-east-1', 'sourceIPAddress': attacker,
            'userIdentity': {'type': 'IAMUser', 'userName': 'alice', 'arn': 'arn:aws:iam::000000000000:user/alice'}, 'responseElements': {'ConsoleLogin': 'Failure'}, 'errorMessage': 'Failed authentication'} for i in range(6)]
records.append({'eventTime': '2026-01-15T09:07:00Z', 'eventSource': 'signin.amazonaws.com', 'eventName': 'ConsoleLogin', 'sourceIPAddress': attacker, 'userIdentity': {'type': 'IAMUser', 'userName': 'alice'}, 'responseElements': {'ConsoleLogin': 'Success'}})
write('aws_cloudtrail.json', json.dumps({'Records': records}, indent=1))
# Winlogbeat / ECS nested JSON
ecs = [{'@timestamp': f'2026-01-15T09:00:{i:02d}.000Z', 'event': {'code': '4625', 'action': 'logon-failed', 'outcome': 'failure'}, 'host': {'name': 'dc-01'}, 'source': {'ip': attacker, 'port': 50000 + i},
        'user': {'name': 'administrator'}, 'winlog': {'channel': 'Security', 'event_id': 4625, 'computer_name': 'dc-01', 'event_data': {'TargetUserName': 'administrator', 'IpAddress': attacker, 'LogonType': '3'}}} for i in range(8)]
write('winlogbeat_ecs.jsonl', '\n'.join(json.dumps(item) for item in ecs) + '\n')
# Elasticsearch export
write('elastic_export.json', json.dumps({'took': 5, 'hits': {'total': {'value': 8}, 'hits': [{'_index': 'logs', '_id': str(i), '_source': item} for i, item in enumerate(ecs)]}}))
# Event Viewer CSV
with open(os.path.join(out, 'windows_eventviewer.csv'), 'w', encoding='utf-8', newline='') as handle:
    writer = csv.writer(handle)
    writer.writerow(['Keywords', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Computer', 'Message'])
    for i in range(8):
        writer.writerow(['Audit Failure', f'1/15/2026 9:00:{i:02d} AM', 'Microsoft-Windows-Security-Auditing', '4625', 'Logon', 'dc-01', f'An account failed to log on. Account Name: bob Source Network Address: {attacker}'])
# Kaggle style cyber attack table
with open(os.path.join(out, 'kaggle_cybersecurity_attacks.csv'), 'w', encoding='utf-8', newline='') as handle:
    writer = csv.writer(handle)
    writer.writerow(['Timestamp', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port', 'Protocol', 'Packet Length', 'Packet Type', 'Traffic Type', 'Payload Data', 'Malware Indicators', 'Anomaly Scores', 'Alerts/Warnings', 'Attack Type', 'Attack Signature', 'Action Taken', 'Severity Level', 'User Information', 'Device Information', 'Network Segment', 'Geo-location Data', 'Proxy Information', 'Firewall Logs', 'IDS/IPS Alerts', 'Log Source'])
    for i in range(20):
        writer.writerow([f'2026-01-15 09:{i:02d}:00', f'203.0.113.{i + 1}', '10.1.1.9', 40000 + i, 443, 'TCP', 512, 'Data', 'HTTP', 'text', 'IoC Detected' if i % 2 else '', 11.5, 'Alert Data' if i % 3 == 0 else '', 'Malware' if i % 2 else 'DDoS', 'Known Pattern A', 'Logged' if i % 2 else 'Blocked', 'High' if i % 2 else 'Low', f'user{i}', 'Mozilla/5.0', 'Segment A', 'Pune, India', '', 'Log Data', '', 'Firewall'])
# Separate date and time columns, unusual names
with open(os.path.join(out, 'firewall_date_time_columns.csv'), 'w', encoding='utf-8', newline='') as handle:
    writer = csv.writer(handle)
    writer.writerow(['Date', 'Time', 'Src Addr', 'Dst Addr', 'Dst Port', 'Proto', 'Verdict', 'Sent Bytes'])
    for i in range(25):
        writer.writerow(['2026-01-15', f'09:00:{i:02d}', attacker, '10.1.1.9', 20 + i, 'TCP', 'DROP', 60])
# Unknown shape: a time and a message
with open(os.path.join(out, 'plain_time_message.csv'), 'w', encoding='utf-8', newline='') as handle:
    writer = csv.writer(handle)
    writer.writerow(['created_at', 'level', 'message'])
    for i in range(10):
        writer.writerow([f'2026-01-15T09:00:{i:02d}Z', 'WARN', f'Failed password for root from {attacker} port 22'])
# Line formats
write('syslog_rfc5424.log', ''.join(f'<34>1 2026-01-15T09:00:{i:02d}Z web-01 sshd 2201 - - Failed password for root from {attacker} port {50000 + i} ssh2\n' for i in range(8)))
write('syslog_rfc3164_pri.log', ''.join(f'<38>Jan 15 09:00:{i:02d} web-01 sshd[2201]: Failed password for root from {attacker} port {50000 + i} ssh2\n' for i in range(8)))
write('cef_events.log', ''.join(f'CEF:0|Acme|Firewall|1.0|100|Blocked connection|5|src={attacker} dst=10.1.1.{i + 2} spt={40000 + i} dpt=445 proto=TCP act=blocked suser=alice rt=Jan 15 2026 09:00:{i:02d}\n' for i in range(6)))
write('leef_events.log', ''.join(f'LEEF:1.0|Acme|IDS|2.0|4625|devTime=2026-01-15 09:00:{i:02d}\tsrc={attacker}\tdst=10.1.1.9\tusrName=bob\tproto=TCP\tdstPort=22\n' for i in range(6)))
write('nginx_error.log', ''.join(f'2026/01/15 09:00:{i:02d} [error] 1234#0: *{i} open() "/var/www/.env" failed (2: No such file or directory), client: {attacker}, server: example.test, request: "GET /.env HTTP/1.1", host: "example.test"\n' for i in range(6)))
write('apache_access.log', ''.join(f'{attacker} - - [15/Jan/2026:09:00:{i:02d} +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.0"\n' for i in range(8)))
write('app_iso_lines.log', ''.join(f'2026-01-15 09:00:{i:02d},120 ERROR [auth] Login failed for user bob from {attacker}\n' for i in range(7)))
write('key_value_fortigate.log', ''.join(f'date=2026-01-15 time=09:00:{i:02d} devname=fw-01 logid=0000000013 type=traffic action=deny srcip={attacker} dstip=10.1.1.9 dstport=445 proto=6 sentbyte=60\n' for i in range(6)))
write('iis_w3c.log', '#Software: Microsoft Internet Information Services 10.0\n#Version: 1.0\n#Date: 2026-01-15 09:00:00\n#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken\n'
      + ''.join(f'2026-01-15 09:00:{i:02d} 10.1.1.9 GET /.env - 443 - {attacker} curl/8.0 404 0 2 15\n' for i in range(6)))
write('snort_fast.log', ''.join(f'01/15-09:00:{i:02d}.000000  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {{TCP}} {attacker}:{40000 + i} -> 10.1.1.9:22\n' for i in range(6)))
okta = [{'published': f'2026-01-15T09:00:{i:02d}.000Z', 'eventType': 'user.session.start', 'displayMessage': 'User login to Okta', 'outcome': {'result': 'FAILURE', 'reason': 'INVALID_CREDENTIALS'},
         'actor': {'alternateId': 'alice@example.test', 'type': 'User'}, 'client': {'ipAddress': attacker}} for i in range(7)]
write('okta_system_log.json', json.dumps(okta, indent=1))
windows_xml = ''.join(f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-01-15T09:00:{i:02d}.000Z"/><Channel>Security</Channel><Computer>dc-01</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">{attacker}</Data></EventData></Event>' for i in range(7))
write('windows_events.xml', f'<Events>{windows_xml}</Events>')
print('wrote', len(os.listdir(out)))
