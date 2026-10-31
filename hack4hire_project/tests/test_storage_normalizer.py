import json
import sqlite3
import unittest

import models
from tests.helpers import TempDbTestCase
from utils.normalizer import NormalizationError, is_internal_ip, normalize_log, parse_timestamp


class NormalizerTests(unittest.TestCase):

    def test_aliases_map_to_schema_and_raw_is_preserved(self):
        raw = {'source_ip': '10.0.0.5', 'destination_ip': '203.0.113.9', 'username': 'alice',
               'time': '2026-01-02T03:04:05Z', 'bytes_sent': 500, 'tenant': 'acme'}
        log = normalize_log(raw, 'network')
        self.assertEqual(log['src_ip'], '10.0.0.5')
        self.assertEqual(log['dst_ip'], '203.0.113.9')
        self.assertEqual(log['user'], 'alice')
        self.assertEqual(log['bytes_out'], 500)
        self.assertEqual(log['timestamp'], '2026-01-02T03:04:05+00:00')
        self.assertEqual(json.loads(log['raw_event']), raw)
        self.assertEqual(json.loads(log['normalized_fields'])['tenant'], 'acme')

    def test_existing_collector_call_signature_still_works(self):
        log = normalize_log({'action': 'process_start', 'process_name': 'x.exe'}, 'endpoint')
        self.assertEqual(log['event_type'], 'process_start')
        self.assertEqual(log['event_category'], 'process')
        self.assertTrue(log['event_id'])

    def test_invalid_optional_values_become_null_with_a_note(self):
        log = normalize_log({'src_ip': 'not-an-ip', 'dst_port': 70000, 'file_hash': 'xyz',
                             'timestamp': '2026-01-02T03:04:05Z'}, 'network')
        self.assertIsNone(log['src_ip'])
        self.assertIsNone(log['dst_port'])
        self.assertIsNone(log['file_hash'])
        self.assertEqual(sorted(json.loads(log['normalized_fields'])['validation_notes']),
                         ['dst_port_invalid', 'file_hash_invalid', 'src_ip_invalid'])

    def test_strict_mode_rejects_unusable_records(self):
        with self.assertRaises(NormalizationError):
            normalize_log({'timestamp': 'yesterday-ish'}, 'network', strict=True)
        with self.assertRaises(NormalizationError):
            normalize_log({'timestamp': '2026-01-02T03:04:05Z'}, None, strict=True)
        with self.assertRaises(NormalizationError):
            normalize_log(['not', 'a', 'dict'], 'network', strict=True)

    def test_timestamp_formats(self):
        expected = '2026-01-02T03:04:05+00:00'
        for value in ('2026-01-02T03:04:05Z', '02/Jan/2026:03:04:05 +0000', 1767323045, 1767323045000):
            self.assertEqual(parse_timestamp(value).isoformat(), expected, value)
        self.assertIsNone(parse_timestamp('nonsense'))
        self.assertIsNone(parse_timestamp(True))

    def test_web_login_status_becomes_authentication_event(self):
        failed = normalize_log({'method': 'POST', 'path': '/login', 'status': 401}, 'application')
        ok = normalize_log({'method': 'POST', 'path': '/login', 'status': 200}, 'application')
        page = normalize_log({'method': 'GET', 'path': '/login', 'status': 200}, 'application')
        self.assertEqual(failed['event_type'], 'authentication_failure')
        self.assertEqual(ok['auth_result'], 'success')
        self.assertEqual(page['event_type'], 'http_request')

    def test_legacy_login_names_are_canonicalized(self):
        self.assertEqual(normalize_log({'event_type': 'failed_login'}, 'application')['event_type'],
                         'authentication_failure')

    def test_network_events_get_a_real_type_and_resource_metrics_are_system(self):
        self.assertEqual(normalize_log({'event_type': 'info'}, 'network')['event_type'], 'network_connection')
        self.assertEqual(normalize_log({'event_type': 'high_memory'}, 'application')['event_category'], 'system')

    def test_outbound_bytes_only_for_internal_to_external(self):
        out = normalize_log({'src_ip': '10.0.0.1', 'dst_ip': '198.51.100.1', 'bytes': 9}, 'network')
        lan = normalize_log({'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'bytes': 9}, 'network')
        self.assertEqual(out['bytes_out'], 9)
        self.assertIsNone(lan['bytes_out'])

    def test_ip_scope(self):
        self.assertTrue(is_internal_ip('10.1.1.1'))
        self.assertFalse(is_internal_ip('203.0.113.5'))
        self.assertIsNone(is_internal_ip('nope'))


class StorageTests(TempDbTestCase):

    def test_batch_insert_returns_real_ids_and_ignores_duplicate_event_ids(self):
        logs = [normalize_log({'event_id': 'a', 'event_type': 'x'}, 'application'),
                normalize_log({'event_id': 'b', 'event_type': 'x'}, 'application')]
        ids = models.batch_insert_logs(logs)
        self.assertEqual(len(set(ids)), 2)
        self.assertEqual(models.batch_insert_logs(logs[:1]), [None])
        self.assertEqual(models.get_total_log_count(), 2)

    def test_init_is_idempotent(self):
        models.init_db()
        models.init_db()

    def test_migrates_a_legacy_database_without_losing_rows(self):
        models.DATABASE_NAME = models.DATABASE_NAME + '.legacy'
        conn = sqlite3.connect(models.DATABASE_NAME)
        conn.execute("""CREATE TABLE logs (id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
            event_type TEXT NOT NULL, timestamp TEXT NOT NULL, user TEXT, src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER, protocol TEXT, bytes INTEGER, duration REAL, flags TEXT,
            process_name TEXT, ppid INTEGER, parent_process_name TEXT, file_path TEXT, registry_key TEXT,
            method TEXT, endpoint TEXT, status_code INTEGER, payload_size INTEGER, user_agent TEXT,
            geo_location TEXT, details TEXT)""")
        conn.execute("""CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            description TEXT NOT NULL, severity TEXT NOT NULL, timestamp DATETIME, source_ip TEXT,
            status TEXT DEFAULT 'ACTIVE')""")
        conn.execute("INSERT INTO logs (source, event_type, timestamp) VALUES ('network','info','2026-10-30T18:47:25')")
        conn.execute("INSERT INTO incidents (title, description, severity) VALUES ('t','d','HIGH')")
        conn.commit()
        conn.close()

        models.init_db()

        self.assertEqual(models.get_total_log_count(), 1)
        self.assertEqual(models.get_recent_logs(5)[0]['event_id'], 'legacy-1')
        self.assertEqual(models.get_recent_incidents(5)[0]['title'], 't')
        # History is not replayed through the detection engine
        self.assertEqual(models.get_engine_state('last_log_id'), '1')


if __name__ == '__main__':
    unittest.main()
