"""The Solution Portal is read from the rules and the playbook in force, so it must cover all of them."""
import json

from tests.test_api import ApiTestCase
from utils.response_engine import PLAYBOOK
from utils.solutions import DISRUPTIVE_STEP, SAFE_STEP
from utils.simulator import SCENARIOS


class SolutionPortalTests(ApiTestCase):

    def setUp(self):
        super().setUp()
        self.body = self.client.get('/api/solutions').get_json()
        self.threats = {threat['id']: threat for threat in self.body['threats']}

    def test_every_threat_is_listed_once(self):
        ids = [threat['id'] for threat in self.body['threats']]
        self.assertEqual(len(ids), len(set(ids)))
        for rule_id in PLAYBOOK['rules']:
            self.assertIn(rule_id, ids)
        rules = self.client.get('/api/rules').get_json()
        for rule in rules['rules'] + rules['behavioral_rules']:
            self.assertIn(rule['id'], ids)

    def test_every_threat_has_a_fix_and_says_how_it_is_detected(self):
        for threat in self.threats.values():
            with self.subTest(threat=threat['id']):
                self.assertTrue(threat['fix_steps'])
                self.assertTrue(threat['detected_when'])
                self.assertTrue(threat['actions'])

    def test_a_rule_shows_its_real_limit(self):
        self.assertIn('50.0 MB', self.threats['IOA-007']['detected_when'])
        self.assertIn('300 seconds', self.threats['IOA-001']['detected_when'])

    def test_who_decides_follows_the_policy(self):
        actions = {action['label']: action for action in self.threats['IOA-002']['actions']}
        self.assertEqual(actions['Block test IP']['who_decides'], DISRUPTIVE_STEP)
        self.assertEqual(actions['Investigate source IP']['who_decides'], SAFE_STEP)

    def test_every_action_has_real_commands(self):
        for threat in self.threats.values():
            for action in threat['actions']:
                with self.subTest(threat=threat['id'], action=action['label']):
                    self.assertTrue(action['commands']['windows'])
                    self.assertTrue(action['commands']['linux'])

    def test_each_threat_names_the_scenarios_that_practise_it(self):
        for key, scenario in SCENARIOS.items():
            for rule_id in scenario['expected_rules']:
                self.assertIn(key, [item['id'] for item in self.threats[rule_id]['scenarios']])

    def test_an_alert_count_comes_from_stored_alerts(self):
        self.assertEqual(self.threats['IOA-001']['alerts'], 0)
        self.client.post('/api/simulate/brute_force')
        body = self.client.get('/api/solutions').get_json()
        self.assertGreater(next(item for item in body['threats'] if item['id'] == 'IOA-001')['alerts'], 0)

    def test_internals_are_not_exposed(self):
        self.assertNotIn('_pattern', json.dumps(self.body))
