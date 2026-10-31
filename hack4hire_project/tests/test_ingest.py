import json
import os
import tempfile
import unittest

import models
from tests.helpers import TempDbTestCase
from utils.log_ingest import MAX_UPLOAD_BYTES, UploadRejected, ingest_upload, parse_upload

TS = '2026-01-02T03:04:05Z'


class UploadFormatTests(TempDbTestCase):

    def stored(self):
        return models.get_recent_logs(100)

    def test_json_array(self):
        data = json.dumps([{'timestamp': TS, 'source': 'network', 'src_ip': '10.0.0.1'}]).encode()
        report = ingest_upload('a.json', data)
        self.assertEqual(report['stored'], 1)
        self.assertEqual(self.stored()[0]['origin'], 'upload')

    def test_json_events_wrapper_and_default_source(self):
        data = json.dumps({'events': [{'timestamp': TS, 'event_type': 'x'}]}).encode()
        self.assertEqual(ingest_upload('a.json', data, default_source='endpoint')['by_source'], {'endpoint': 1})

    def test_jsonl_keeps_good_lines_and_reports_bad_ones(self):
        data = f'{{"timestamp":"{TS}","source":"network"}}\nnot json\n{{"source":"network"}}\n'.encode()
        report = ingest_upload('a.jsonl', data)
        self.assertEqual(report['stored'], 1)
        self.assertEqual(report['rejected'], 2)
        self.assertEqual(report['errors'][0], {'line': 2, 'error': 'invalid JSON'})

    def test_csv(self):
        data = f'timestamp,source,source_ip,status\n{TS},application,10.0.0.9,404\n'.encode()
        ingest_upload('a.csv', data)
        self.assertEqual(self.stored()[0]['src_ip'], '10.0.0.9')
        self.assertEqual(self.stored()[0]['status_code'], 404)

    def test_csv_with_bom_and_extra_columns(self):
        data = f'﻿timestamp,source\n{TS},network,surplus\n'.encode('utf-8')
        self.assertEqual(ingest_upload('a.csv', data)['stored'], 1)

    def test_apache_access_log(self):
        line = ('203.0.113.5 - bob [02/Jan/2026:03:04:05 +0000] "POST /login HTTP/1.1" 401 512 '
                '"-" "curl/8.0"\n')
        ingest_upload('access.log', line.encode())
        log = self.stored()[0]
        self.assertEqual(log['event_type'], 'authentication_failure')
        self.assertEqual((log['src_ip'], log['user'], log['user_agent']), ('203.0.113.5', 'bob', 'curl/8.0'))

    def test_sshd_sudo_and_useradd_syslog(self):
        text = ('Jan  2 03:04:05 srv1 sshd[77]: Failed password for invalid user oracle from 203.0.113.5 port 4242 ssh2\n'
                'Jan  2 03:04:09 srv1 sshd[78]: Accepted password for bob from 203.0.113.5 port 4243 ssh2\n'
                'Jan  2 03:05:00 srv1 sudo:      bob : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash\n'
                'Jan  2 03:06:00 srv1 useradd[99]: new user: name=backdoor, UID=1001\n'
                'this line is not a known format\n')
        report = ingest_upload('auth.log', text.encode())
        self.assertEqual(report['stored'], 4)
        self.assertEqual(report['rejected'], 1)
        types = {log['event_type'] for log in self.stored()}
        self.assertEqual(types, {'authentication_failure', 'authentication_success', 'process_start', 'account_created'})
        self.assertTrue(all(log['hostname'] == 'srv1' for log in self.stored()))

    def test_pcap_becomes_flow_events(self):
        from scapy.layers.inet import IP, TCP
        from scapy.utils import wrpcap
        packets = [IP(src='10.0.0.1', dst='203.0.113.9') / TCP(sport=5000, dport=443, flags='S'),
                   IP(src='203.0.113.9', dst='10.0.0.1') / TCP(sport=443, dport=5000, flags='SA'),
                   IP(src='10.0.0.1', dst='203.0.113.9') / TCP(sport=5000, dport=443, flags='F')]
        handle, path = tempfile.mkstemp(suffix='.pcap')
        os.close(handle)
        try:
            wrpcap(path, packets)
            with open(path, 'rb') as capture:
                report = ingest_upload('c.pcap', capture.read())
        finally:
            os.unlink(path)
        self.assertEqual(report['stored'], 1)
        flow = self.stored()[0]
        self.assertEqual(flow['packet_count'], 3)
        self.assertEqual(flow['connection_status'], 'closed')
        self.assertGreater(flow['bytes_out'], 0)
        self.assertGreater(flow['bytes_in'], 0)

    def test_reupload_does_not_duplicate(self):
        data = json.dumps([{'timestamp': TS, 'source': 'network'}]).encode()
        ingest_upload('a.json', data)
        report = ingest_upload('a.json', data)
        self.assertEqual((report['stored'], report['duplicates']), (0, 1))
        self.assertEqual(models.get_total_log_count(), 1)

    def test_identical_lines_in_one_file_stay_separate_events(self):
        line = f'{{"timestamp":"{TS}","source":"application","event_type":"authentication_failure"}}\n'
        self.assertEqual(ingest_upload('a.jsonl', (line * 3).encode())['stored'], 3)


class UploadRejectionTests(TempDbTestCase):

    def assertRejected(self, filename, data, fragment):
        with self.assertRaises(UploadRejected) as caught:
            ingest_upload(filename, data)
        self.assertIn(fragment, str(caught.exception))
        self.assertEqual(models.get_total_log_count(), 0)

    def test_disallowed_extension(self):
        self.assertRejected('shell.php', b'<?php', 'unsupported file type')
        self.assertRejected('noextension', b'x', 'unsupported file type')

    def test_oversized(self):
        self.assertRejected('a.log', b'x' * (MAX_UPLOAD_BYTES + 1), 'limit')

    def test_empty(self):
        self.assertRejected('a.json', b'', 'empty')

    def test_binary_masquerading_as_text(self):
        self.assertRejected('a.log', b'\xff\xfe\x00\x01binary', 'UTF-8')

    def test_malformed_json(self):
        self.assertRejected('a.json', b'{"oops":', 'not valid JSON')

    def test_json_scalar(self):
        self.assertRejected('a.json', b'42', 'JSON must be')

    def test_deeply_nested_json_does_not_crash(self):
        self.assertRejected('a.json', b'[' * 200000, 'not valid JSON')

    def test_invalid_pcap(self):
        self.assertRejected('a.pcap', b'this is not a capture', 'valid pcap')

    def test_nothing_usable(self):
        self.assertRejected('a.log', b'garbage line\n', 'no valid events')

    def test_non_object_records_are_rejected_individually(self):
        data = json.dumps([1, 'x', {'timestamp': TS, 'source': 'network'}]).encode()
        report = ingest_upload('a.json', data)
        self.assertEqual((report['stored'], report['rejected']), (1, 2))

    def test_parse_upload_never_touches_the_filesystem_path(self):
        records, _ = parse_upload('../../etc/passwd.json', json.dumps([{'a': 1}]).encode())
        self.assertEqual(len(records), 1)


if __name__ == '__main__':
    unittest.main()
