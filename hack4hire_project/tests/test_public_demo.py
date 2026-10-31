"""A tunnel connects from this machine, so being local must not be enough for anyone who comes through one."""
import os
import tempfile
import unittest
from unittest import mock

import app as allsafe
from tests.test_api import ApiTestCase
from utils import auth, real_response

FORWARDED = {'X-Forwarded-For': '198.51.100.7'}


class TunnelledVisitorTests(ApiTestCase):

    def setUp(self):
        super().setUp()
        auth.forget_enabled_state()
        self.addCleanup(auth.forget_enabled_state)

    def test_the_one_click_sign_in_is_refused_through_a_tunnel(self):
        response = self.client.post('/api/auth/demo', headers=FORWARDED)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post('/api/auth/demo').status_code, 200)

    def test_analyst_actions_are_refused_through_a_tunnel(self):
        incident_id = self.client.post('/api/simulate/multi_stage').get_json()['outcome']['incident_ids'][0]
        action = self.client.get(f'/api/incidents/{incident_id}/response-actions').get_json()[0]
        response = self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'approve', 'analyst': 'x'}, headers=FORWARDED)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get('/api/email/config', headers=FORWARDED).status_code, 403)


class PublicDemoTests(ApiTestCase):

    def setUp(self):
        super().setUp()
        auth.forget_enabled_state()
        self.addCleanup(auth.forget_enabled_state)
        patcher = mock.patch.dict(os.environ, {'ALLSAFE_PUBLIC_DEMO': '1'})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_one_click_sign_in_and_sign_up_are_closed(self):
        self.assertEqual(self.client.post('/api/auth/demo').status_code, 403)
        self.assertEqual(self.client.post('/api/auth/register', json={'username': 'visitor', 'password': 'Long-enough-pass-1'}).status_code, 403)

    def test_mail_settings_are_closed(self):
        auth.create_account('owner', 'Long-enough-pass-1', 'analyst')
        auth.forget_enabled_state()
        self.client.post('/api/auth/login', json={'username': 'owner', 'password': 'Long-enough-pass-1'})
        self.assertEqual(self.client.get('/api/email/config').status_code, 403)
        self.assertEqual(self.client.post('/api/email/config', json={}).status_code, 403)
        self.assertEqual(self.client.post('/api/email/test', json={'analyst': 'owner'}).status_code, 403)

    def test_real_mode_stays_off_even_if_asked_for(self):
        with mock.patch.dict(os.environ, {'ALLSAFE_REAL_RESPONSE': '1'}):
            self.assertFalse(real_response.enabled())

    def test_no_env_file_is_read(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, '.env')
            with open(path, 'w', encoding='utf-8') as env_file:
                env_file.write('ALLSAFE_TEST_PUBLIC=from file\n')
            allsafe.load_env_file(path)
        self.assertNotIn('ALLSAFE_TEST_PUBLIC', os.environ)

    def test_no_live_collector_starts(self):
        with mock.patch.object(allsafe.correlation_engine, 'start'), mock.patch('app.threading.Thread') as thread:
            allsafe.start_collectors()
        thread.assert_not_called()


if __name__ == '__main__':
    unittest.main()
