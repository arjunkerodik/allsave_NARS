"""Critical and high risk wait for the SOC. Small risks are handled automatically, and nothing real ever changes."""
import unittest

import models
from tests.test_api import ApiTestCase
from utils.response_engine import AUTOMATION_ACTOR, apply_policy_to_open_incidents, apply_response_policy


class ResponsePolicyTests(ApiTestCase):

    def run_scenario(self, name):
        outcome = self.client.post(f'/api/simulate/{name}').get_json()['outcome']
        return outcome['incident_ids'][0]

    def actions(self, incident_id):
        return self.client.get(f'/api/incidents/{incident_id}/response-actions').get_json()

    def audit(self, incident_id):
        return [entry['action'] for entry in self.client.get(f'/api/audit?incident_id={incident_id}&limit=500').get_json()]

    def test_critical_risk_waits_for_the_soc(self):
        incident_id = self.run_scenario('multi_stage')
        self.assertEqual(models.get_incident(incident_id)['risk_level'], 'CRITICAL')
        self.assertEqual({action['status'] for action in self.actions(incident_id)}, {'PENDING'})

    def test_high_risk_waits_for_the_soc(self):
        incident_id = self.run_scenario('exfil')
        self.assertEqual(models.get_incident(incident_id)['risk_level'], 'HIGH')
        self.assertEqual({action['status'] for action in self.actions(incident_id)}, {'PENDING'})

    def test_medium_risk_is_handled_automatically(self):
        incident_id = self.run_scenario('port_scan')
        self.assertEqual(models.get_incident(incident_id)['risk_level'], 'MEDIUM')
        actions = self.actions(incident_id)
        safe = [action for action in actions if not action['disruptive']]
        self.assertTrue(safe)
        for action in safe:
            self.assertEqual((action['status'], action['decided_by'], action['executed_by']), ('EXECUTED', AUTOMATION_ACTOR, AUTOMATION_ACTOR))
            self.assertIs(action['result']['real_system_changed'], False)
        self.assertIn('response_auto_approved', self.audit(incident_id))
        self.assertIn('response_executed', self.audit(incident_id))

    def test_a_disruptive_action_never_runs_on_its_own(self):
        incident_id = self.run_scenario('suspicious_process')
        self.assertEqual(models.get_incident(incident_id)['risk_level'], 'MEDIUM')
        held = [action for action in self.actions(incident_id) if action['disruptive']]
        self.assertTrue(held)
        for action in held:
            self.assertEqual(action['status'], 'HELD')
            self.assertIsNone(action['executed_by'])
            refused = self.client.post(f"/api/response-actions/{action['id']}/execute", json={'analyst': 'amy'})
            self.assertEqual(refused.status_code, 409)
        self.assertEqual(self.client.get('/api/blocklist').get_json(), [])
        self.assertIn('response_held', self.audit(incident_id))

    def test_an_analyst_can_still_decide_a_held_action(self):
        incident_id = self.run_scenario('suspicious_process')
        action = next(item for item in self.actions(incident_id) if item['status'] == 'HELD')
        decided = self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'approve', 'analyst': 'amy', 'reason': 'Confirmed'})
        self.assertEqual(decided.status_code, 200, decided.get_json())
        done = self.client.post(f"/api/response-actions/{action['id']}/execute", json={'analyst': 'amy'}).get_json()
        self.assertEqual(done['status'], 'EXECUTED')
        self.assertIs(done['result']['real_system_changed'], False)

    def test_held_actions_go_to_the_soc_when_the_risk_rises(self):
        incident_id = self.run_scenario('suspicious_process')
        held = [action['id'] for action in self.actions(incident_id) if action['status'] == 'HELD']
        already_run = [action['id'] for action in self.actions(incident_id) if action['status'] == 'EXECUTED']
        self.assertTrue(held and already_run)
        apply_response_policy(incident_id, 'CRITICAL')
        statuses = {action['id']: action['status'] for action in self.actions(incident_id)}
        self.assertEqual({statuses[action_id] for action_id in held}, {'PENDING'})
        # A safe step that ran while the risk was small stays on record as it was
        self.assertEqual({statuses[action_id] for action_id in already_run}, {'EXECUTED'})
        self.assertIn('response_escalated', self.audit(incident_id))

    def test_incidents_stored_before_the_policy_follow_it(self):
        small = self.run_scenario('suspicious_process')
        big = self.run_scenario('multi_stage')
        # As an older database has them: everything waiting for a person, whatever the risk
        for action in self.actions(small):
            models.update_response_action(action['id'], action['status'], {'status': 'PENDING', 'decided_by': None, 'decided_at': None, 'decision_reason': None})
        apply_policy_to_open_incidents()
        after = self.actions(small)
        self.assertEqual({action['status'] for action in after if action['disruptive']}, {'HELD'})
        self.assertEqual({action['status'] for action in after if not action['disruptive']}, {'EXECUTED'})
        self.assertEqual({action['status'] for action in self.actions(big)}, {'PENDING'})

    def test_applying_the_policy_again_changes_nothing(self):
        incident_id = self.run_scenario('suspicious_process')
        before = (self.actions(incident_id), self.audit(incident_id))
        apply_policy_to_open_incidents()
        self.assertEqual((self.actions(incident_id), self.audit(incident_id)), before)

    def test_a_resolved_incident_is_left_as_it_was(self):
        incident_id = self.run_scenario('multi_stage')
        models.update_incident(incident_id, {'status': 'RESOLVED', 'risk_level': 'LOW'})
        apply_policy_to_open_incidents()
        self.assertEqual({action['status'] for action in self.actions(incident_id)}, {'PENDING'})

    def test_automation_leaves_a_decision_a_person_made_alone(self):
        incident_id = self.run_scenario('multi_stage')
        action = next(item for item in self.actions(incident_id) if not item['disruptive'])
        self.client.post(f"/api/response-actions/{action['id']}/decision", json={'decision': 'reject', 'analyst': 'amy', 'reason': 'Not needed'})
        apply_response_policy(incident_id, 'LOW')
        after = next(item for item in self.actions(incident_id) if item['id'] == action['id'])
        self.assertEqual((after['status'], after['decided_by']), ('REJECTED', 'amy'))

    def test_the_queue_and_counts_tell_the_two_paths_apart(self):
        waiting = self.run_scenario('multi_stage')
        automatic = self.run_scenario('suspicious_process')
        stats = self.client.get('/api/stats').get_json()
        pending = self.client.get('/api/response-actions?status=PENDING&limit=1000').get_json()
        automated = self.client.get('/api/response-actions?status=AUTOMATED&limit=1000').get_json()
        self.assertEqual({action['incident_id'] for action in pending}, {waiting})
        self.assertEqual({action['incident_id'] for action in automated}, {automatic})
        self.assertEqual((stats['responses_pending'], stats['responses_automated']), (len(pending), len(automated)))
        self.assertGreater(stats['responses_held'], 0)


if __name__ == '__main__':
    unittest.main()
