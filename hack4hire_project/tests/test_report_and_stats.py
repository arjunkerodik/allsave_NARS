import unittest
from unittest import mock

from collectors.endpoint_collector import EndpointCollector, psutil
from tests.test_api import ApiTestCase


class IncidentReportTests(ApiTestCase):

    def run_scenario(self, name):
        return self.client.post(f'/api/simulate/{name}').get_json()['outcome']

    def test_report_is_a_download_built_from_stored_data(self):
        incident_id = self.run_scenario('multi_stage')['incident_ids'][0]
        detail = self.client.get(f'/api/incidents/{incident_id}').get_json()
        response = self.client.get(f'/api/incidents/{incident_id}/report')
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{detail['incident']['incident_uid']}-report.md", response.headers['Content-Disposition'])
        self.assertIn(detail['incident']['title'], body)
        for alert in detail['alerts']:
            self.assertIn(alert['rule_id'], body)
        for section in ('## Attack timeline', '## How this was scored', '## Response actions', '## Audit trail'):
            self.assertIn(section, body)

    def test_report_says_simulated_data_is_synthetic(self):
        incident_id = self.run_scenario('exfil')['incident_ids'][0]
        self.assertIn('Built from synthetic events', self.client.get(f'/api/incidents/{incident_id}/report').get_data(as_text=True))

    def test_report_for_a_missing_incident_is_a_json_error(self):
        response = self.client.get('/api/incidents/999/report')
        self.assertEqual(response.status_code, 404)
        self.assertIn('error', response.get_json())

    def test_log_text_cannot_add_lines_to_a_report(self):
        event = {'timestamp': '2026-01-02T03:04:05Z', 'source': 'endpoint', 'event_type': 'process_start', 'hostname': 'h1',
                 'user': 'alice\n## Forged section', 'process_name': 'mimikatz.exe', 'command_line': 'mimikatz.exe\n## Forged section'}
        self.client.post('/api/ingest/events', json=[event])
        incidents = self.client.get('/api/incidents?limit=1').get_json()
        body = self.client.get(f"/api/incidents/{incidents[0]['id']}/report").get_data(as_text=True)
        self.assertFalse([line for line in body.splitlines() if line.startswith('## Forged')])


class StatsTests(ApiTestCase):

    def test_stats_split_events_by_origin(self):
        self.client.post('/api/simulate/benign')
        stats = self.client.get('/api/stats').get_json()
        self.assertGreater(stats['by_origin']['simulation'], 0)
        self.assertEqual(sum(stats['by_origin'].values()), stats['total'])

    def test_validation_reports_how_many_runs_it_covers(self):
        for _ in range(3):
            self.client.post('/api/simulate/benign')
        validation = self.client.get('/api/simulate?limit=2').get_json()['validation']
        self.assertEqual((validation['runs'], validation['total_runs']), (2, 3))


class ProcessScanTests(unittest.TestCase):

    def collector(self, pids):
        collector = EndpointCollector()
        collector._previous_pids = set(pids)
        collector._process_names = {pid: f'p{pid}' for pid in pids}
        collector._last_resource_scan = float('inf')
        return collector

    def test_a_routine_pass_does_not_read_every_process(self):
        collector = self.collector([1, 2])
        with mock.patch.object(psutil, 'pids', return_value=[1, 2]), mock.patch.object(psutil, 'process_iter') as scan:
            self.assertEqual(collector._monitor_processes(), [])
        scan.assert_not_called()

    def test_new_and_ended_processes_are_reported(self):
        collector = self.collector([1, 2])
        process = mock.Mock()
        process.name.return_value = 'powershell.exe'
        process.username.return_value = 'alice'
        process.ppid.return_value = 1
        process.parent.return_value.name.return_value = 'explorer.exe'
        process.cmdline.return_value = ['powershell.exe', '-enc', 'abc']
        with mock.patch.object(psutil, 'pids', return_value=[1, 3]), mock.patch.object(psutil, 'Process', return_value=process):
            events = {event['action']: event for event in collector._monitor_processes()}
        self.assertEqual(events['process_start']['process_name'], 'powershell.exe')
        self.assertEqual(events['process_start']['user'], 'alice')
        self.assertEqual(events['process_start']['command_line'], 'powershell.exe -enc abc')
        self.assertEqual(events['process_stop']['process_name'], 'p2')

    def test_a_process_that_exits_at_once_is_still_recorded(self):
        collector = self.collector([1])
        with mock.patch.object(psutil, 'pids', return_value=[1, 3]), \
                mock.patch.object(psutil, 'Process', side_effect=psutil.NoSuchProcess(3)):
            events = collector._monitor_processes()
        self.assertEqual((events[0]['action'], events[0]['process_name'], events[0]['pid']), ('process_start', 'unknown', 3))

    def test_resource_usage_is_still_checked_periodically(self):
        collector = self.collector([1])
        collector._last_resource_scan = 0
        hog = mock.Mock(info={'pid': 1, 'name': 'hog.exe', 'username': 'alice', 'cpu_percent': 90.0, 'memory_percent': 1.0})
        with mock.patch.object(psutil, 'pids', return_value=[1]), mock.patch.object(psutil, 'process_iter', return_value=[hog]):
            events = collector._monitor_processes()
        self.assertEqual([event['action'] for event in events], ['high_cpu_process'])


if __name__ == '__main__':
    unittest.main()
