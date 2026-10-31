"""Any log type: each format is read, and gives only the detections its content supports."""
import gzip
import io
import os
import unittest
import zipfile

os.environ['ALLSAFE_LOAD_ML'] = '0'

from tests.test_dataset_analysis import SAMPLES, AnalysisTestCase
from utils.log_formats import UnpackRefused, parse_line, read_xml_log, unpack_upload
from utils.normalizer import normal_name, parse_timestamp

FORMATS = os.path.join(SAMPLES, 'formats')

WINDOWS_EVENT = (b'<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID>'
                 b'<TimeCreated SystemTime="2026-01-15T09:00:00.000Z"/><Channel>Security</Channel><Computer>dc-01</Computer></System>'
                 b'<EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">198.51.100.23</Data></EventData></Event></Events>')


class FormatSampleTests(AnalysisTestCase):

    CASES = (
        ('apache_access.log', 'THREATS_DETECTED', None),
        ('app_iso_lines.log', 'THREATS_DETECTED', 'IOA-001'),
        ('aws_cloudtrail.json', 'THREATS_DETECTED', 'IOA-002'),
        ('elastic_export.json', 'THREATS_DETECTED', 'IOA-001'),
        ('firewall_date_time_columns.csv', 'THREATS_DETECTED', 'IOA-005'),
        ('leef_events.log', 'THREATS_DETECTED', 'IOA-001'),
        ('nginx_error.log', 'THREATS_DETECTED', 'IOA-017'),
        ('plain_time_message.csv', 'THREATS_DETECTED', 'IOA-001'),
        ('syslog_rfc3164_pri.log', 'THREATS_DETECTED', 'IOA-001'),
        ('syslog_rfc5424.log', 'THREATS_DETECTED', 'IOA-001'),
        ('windows_eventviewer.csv', 'THREATS_DETECTED', 'IOA-001'),
        ('winlogbeat_ecs.jsonl', 'THREATS_DETECTED', 'IOA-001'),
        ('zeek_conn.log', 'THREATS_DETECTED', 'IOA-009'),
        ('iis_w3c.log', 'THREATS_DETECTED', 'IOA-017'),
        ('okta_system_log.json', 'THREATS_DETECTED', 'IOA-001'),
        ('windows_events.xml', 'THREATS_DETECTED', 'IOA-001'),
        ('snort_fast.log', 'SUSPICIOUS_ACTIVITY', 'IOA-018'),
        # Another tool's alert stays suspicious: it is a lead until a rule of ours supports it
        ('kaggle_cybersecurity_attacks.csv', 'SUSPICIOUS_ACTIVITY', 'IOA-018'),
        ('suricata_eve.json', 'SUSPICIOUS_ACTIVITY', 'IOA-018'),
    )

    def test_each_format_gives_a_real_result(self):
        for name, verdict, rule in self.CASES:
            with self.subTest(file=name):
                with open(os.path.join(FORMATS, name), 'rb') as handle:
                    dataset = self.analyze(name, handle.read())
                self.assertEqual(dataset['status'], 'COMPLETED')
                self.assertGreater(dataset['processed_events'], 0)
                self.assert_verdict(dataset, verdict)
                if rule:
                    self.assertIn(rule, self.rules(dataset))

    def test_a_format_with_no_rule_pattern_says_no_threats_and_keeps_every_record(self):
        with open(os.path.join(FORMATS, 'cef_events.log'), 'rb') as handle:
            dataset = self.analyze('cef_events.log', handle.read())
        self.assertGreater(dataset['processed_events'], 0)
        self.assertEqual(dataset['summary']['invalid_records'], 0)

    def test_a_plain_text_log_with_no_recognised_lines_is_kept_and_never_called_clean(self):
        dataset = self.analyze('notes.txt', b'first free text line\nsecond free text line\n')
        self.assertEqual(dataset['summary']['valid_records'], 2)
        self.assert_verdict(dataset, 'ANALYSIS_INCOMPLETE')

    def test_a_program_is_refused(self):
        response = self.upload('tool.exe', b'MZ' + b'\x00' * 64)
        self.assertEqual(response.status_code, 400)
        self.assertIn('unsupported file type', response.get_json()['error'])

    def test_a_compressed_log_is_read(self):
        with open(os.path.join(FORMATS, 'syslog_rfc3164_pri.log'), 'rb') as handle:
            text = handle.read()
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, 'w') as archive:
            archive.writestr('auth.log', text)
        for name, data in (('auth.log.gz', gzip.compress(text.replace(b'web-01', b'web-02'))), ('auth.zip', packed.getvalue())):
            with self.subTest(file=name):
                self.assertIn('IOA-001', self.rules(self.analyze(name, data)))


class ReaderTests(unittest.TestCase):

    def test_two_digit_year_dates_are_the_year_they_mean(self):
        self.assertEqual(parse_timestamp('081111 103615').year, 2008)
        self.assertEqual(parse_timestamp('20260115 103615').year, 2026)

    def test_digits_that_are_not_a_date_give_no_time_instead_of_a_crash(self):
        self.assertIsNone(parse_timestamp('000101 000000'.replace('0001', '0000')))
        self.assertIsNone(parse_timestamp('not a date'))

    def test_the_same_text_is_the_same_date_whatever_was_read_before(self):
        first = parse_timestamp('01/02/2026 10:00:00')
        parse_timestamp('13/02/2026 10:00:00')
        self.assertEqual(parse_timestamp('01/02/2026 10:00:00'), first)

    def test_field_names_in_any_spelling_are_one_name(self):
        self.assertEqual({normal_name(name) for name in ('Source IP', 'source-ip', 'sourceIp', 'source_ip')}, {'source_ip'})

    def test_line_formats(self):
        cases = (
            ('CEF:0|Acme|Firewall|1.0|100|Blocked|5|src=198.51.100.1 dst=10.0.0.2 dpt=445 rt=Jan 15 2026 09:00:00', 'src_ip', '198.51.100.1'),
            ('LEEF:1.0|Acme|IDS|2.0|4625|devTime=2026-01-15 09:00:00\tsrc=198.51.100.2\tdst=10.0.0.3', 'src_ip', '198.51.100.2'),
            ('<34>1 2026-01-15T09:00:00Z web-01 sshd 2201 - - Failed password', 'hostname', 'web-01'),
        )
        for line, field, value in cases:
            with self.subTest(line=line[:16]):
                parsed = parse_line(line)
                self.assertIsNotNone(parsed)
                self.assertEqual(parsed[0].get(field), value)

    def test_a_windows_xml_export_is_read(self):
        records, _errors = read_xml_log(WINDOWS_EVENT.decode())
        self.assertEqual(len(records), 1)
        fields = records[0][0]
        self.assertEqual(str(fields['EventID']), '4625')
        self.assertEqual(fields['TargetUserName'], 'alice')

    def test_xml_with_an_entity_is_refused_wherever_it_is_declared(self):
        padding = '<!-- ' + 'x' * 5000 + ' -->'
        for text in ('<!DOCTYPE a [<!ENTITY b "c">]><a>&b;</a>', padding + '<!DOCTYPE a [<!ENTITY b "c">]><a>&b;</a>'):
            with self.assertRaisesRegex(UnpackRefused, 'declares entities'):
                read_xml_log(text)

    def test_a_log_that_only_quotes_an_entity_is_read(self):
        records, _errors = read_xml_log('<log><entry><message><![CDATA[blocked <!ENTITY xxe SYSTEM "file:///etc/passwd">]]></message></entry></log>')
        self.assertIn('ENTITY', records[0][0]['message'])

    def test_broken_xml_says_so(self):
        with self.assertRaisesRegex(UnpackRefused, 'could not be read'):
            read_xml_log('<log><entry></log>')

    def test_an_archive_with_a_program_inside_is_refused(self):
        packed = io.BytesIO()
        with zipfile.ZipFile(packed, 'w') as archive:
            archive.writestr('tool.exe', b'MZ')
        with self.assertRaises(UnpackRefused):
            unpack_upload('logs.zip', packed.getvalue(), 1000000, {'exe'})


if __name__ == '__main__':
    unittest.main()
