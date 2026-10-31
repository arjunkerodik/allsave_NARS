"""The Solution Portal: every threat ALLSAFE can detect, how to fix it, and who decides."""
from utils.ioc_engine import _rule_for
from utils.real_response import manual_commands
from utils.threat_parameters import rule_parameters

# Commands in the portal are about no incident in particular, so they show a target to replace
EXAMPLE_TARGETS = {'ip': '203.0.113.50', 'account': 'ACCOUNT', 'process': 'PROCESS.exe', 'host': 'HOST'}
SAFE_STEP = 'Runs on its own at medium or low risk. Waits for the SOC at high or critical risk.'
DISRUPTIVE_STEP = 'Always needs a person. Held at medium or low risk, and waits for the SOC at high or critical risk.'
SEVERITY_ORDER = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')


def _actions(rule_id, playbook):
    actions = []
    for step in playbook['rules'].get(rule_id, []):
        definition = playbook['actions'][step['action']]
        actions.append({
            'label': definition['label'],
            'description': definition['description'],
            'disruptive': definition['disruptive'],
            'expected_impact': definition.get('expected_impact'),
            'who_decides': DISRUPTIVE_STEP if definition['disruptive'] else SAFE_STEP,
            'commands': manual_commands(step['action'], EXAMPLE_TARGETS[definition['target_type']]),
        })
    return actions


def build_solutions(rules, behavioral, ml_rules, scenarios, playbook):
    """One entry per threat, read from the rules and the playbook in force, so it cannot drift from what runs"""
    tested_by = {}
    for scenario in scenarios:
        for rule_id in scenario['expected_rules']:
            tested_by.setdefault(rule_id, []).append({'id': scenario['id'], 'name': scenario['name']})

    def entry(rule, kind, detected_when):
        mitre = rule.get('mitre') or []
        return {
            'id': rule['id'], 'name': rule['name'], 'kind': kind, 'severity': rule.get('severity'),
            'description': rule.get('description') or '', 'detected_when': detected_when,
            'tactics': sorted({item['tactic'] for item in mitre if item.get('tactic')}),
            'techniques': [{'id': item['id'], 'name': item.get('name') or item['id']} for item in mitre if item.get('id')],
            'fix_steps': rule.get('recommendations') or [],
            'actions': _actions(rule['id'], playbook),
            'scenarios': tested_by.get(rule['id'], []),
            'alerts': rule.get('alerts', 0),
        }

    threats = [entry(rule, 'Attack rule', rule_parameters(rule)['definition']) for rule in rules]
    threats += [entry(rule, 'Behaviour baseline', rule.get('logic') or rule.get('description') or '') for rule in behavioral]
    threats += [entry(_rule_for({'ioc_type': ioc_type, 'severity': None, 'confidence': None}), 'Threat intelligence',
                      'A log field equals an indicator on an imported feed. The feed sets the severity.')
                for ioc_type in ('ip', 'domain', 'url', 'file_hash')]
    threats += [entry(rule, 'ML model', 'The saved network model classifies a flow this way. It needs all 78 flow features, and it only ever counts as suspicious.')
                for rule in ml_rules]
    threats.sort(key=lambda threat: (SEVERITY_ORDER.index(threat['severity']) if threat['severity'] in SEVERITY_ORDER else len(SEVERITY_ORDER), threat['id']))
    return {
        'threats': threats,
        'tactics': sorted({tactic for threat in threats for tactic in threat['tactics']}),
        'scenarios': [{'id': scenario['id'], 'name': scenario['name'], 'expected_rules': scenario['expected_rules']} for scenario in scenarios],
    }
