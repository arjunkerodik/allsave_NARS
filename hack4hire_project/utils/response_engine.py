import json
import logging
import os
import re
from datetime import datetime, timezone

from models import (
    add_audit_entry, get_incident, get_response_action, get_response_actions, has_simulated_enforcement, insert_response_action,
    record_simulated_enforcement, search_incidents, update_response_action,
)
from utils import real_response
from utils.normalizer import clean_ip, is_internal_ip
from utils.real_response import RealResponseError

logger = logging.getLogger(__name__)

PLAYBOOK_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'response_playbook.json')

# Execution writes to the simulated_enforcement table, and reaches no firewall, directory or process.
# The one exception is a firewall block in real mode, which is off by default: see utils/real_response.py.
MODE = 'simulated'
REAL_MODE = 'real'
REAL_ACTION = 'block_test_ip'
_NAME = re.compile(r'^[\w.\\@ -]{1,128}$')
_IGNORED_TARGETS = {'SYSTEM', 'NT AUTHORITY\\SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'anonymous', 'unknown', '-', '127.0.0.1', '::1'}
MAX_ANALYST_NAME = 64
OPEN_DECISION_STATES = ('PENDING', 'NEEDS_INVESTIGATION', 'HELD')
AUTOMATION_ACTOR = 'automation'


class ResponseError(Exception):
    """A refused request. The message is safe to show to the client."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def load_playbook(path=PLAYBOOK_PATH):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


PLAYBOOK = load_playbook()


def clean_analyst(value):
    """The analyst's name, as typed. It is self-reported until user accounts exist."""
    name = str(value or '').strip()
    if not name:
        raise ResponseError('An analyst name is required')
    return name[:MAX_ANALYST_NAME]


def valid_target(target_type, value):
    """Clean a target for its type, or return None if it is not valid"""
    text = str(value or '').strip()
    if target_type == 'ip':
        return clean_ip(text)
    return text if _NAME.match(text) else None


def _targets_for(step, alert):
    values = (alert.get('entities') or {}).get(step['entity'], [])
    for value in values:
        if value in _IGNORED_TARGETS:
            continue
        if step.get('scope') == 'external' and is_internal_ip(value) is not False:
            continue
        yield value


def sync_recommendations(incident_id, alerts, playbook=PLAYBOOK):
    """Create any recommendation the incident's alerts call for. Safe to call repeatedly."""
    created = []
    existing = {(a['action_type'], a['original_target']) for a in get_response_actions(incident_id=incident_id, limit=1000)}
    for alert in alerts:
        for step in playbook['rules'].get(alert['rule_id'], []):
            definition = playbook['actions'][step['action']]
            for target in _targets_for(step, alert):
                if (step['action'], target) in existing:
                    continue
                existing.add((step['action'], target))
                action_id = insert_response_action({
                    'incident_id': incident_id,
                    'action_type': step['action'],
                    'label': definition['label'],
                    'description': definition['description'],
                    'target_type': definition['target_type'],
                    'target': target,
                    'disruptive': definition['disruptive'],
                    'recommended_by': alert['rule_id'],
                    'expected_impact': definition.get('expected_impact'),
                    'rationale': f"{alert['rule_id']} {alert['rule_name']}: {alert.get('explanation') or ''}"[:500],
                })
                if action_id:
                    add_audit_entry('system', 'response_recommended', 'response_action', action_id, incident_id,
                                    {'action_type': step['action'], 'target': target, 'recommended_by': alert['rule_id']})
                    created.append(action_id)
    return created


def _load(action_id):
    action = get_response_action(action_id)
    if not action:
        raise ResponseError('Response action not found', 404)
    return action


def _refuse(action, actor, message, status):
    """Refused attempts are part of the record too"""
    add_audit_entry(actor or 'unknown', 'response_refused', 'response_action', action['id'], action['incident_id'],
                    {'reason': message, 'status': action['status']})
    raise ResponseError(message, status)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def decide_action(action_id, data):
    """Record an analyst's approve, reject, modify or investigate-further decision"""
    action = _load(action_id)
    actor = str(data.get('analyst') or '').strip()[:MAX_ANALYST_NAME]
    if not actor:
        _refuse(action, None, 'An analyst name is required', 400)
    decision = data.get('decision')
    if decision not in ('approve', 'reject', 'modify', 'investigate'):
        _refuse(action, actor, 'decision must be approve, reject, modify or investigate', 400)
    if action['status'] not in OPEN_DECISION_STATES:
        _refuse(action, actor, f"This action is already {action['status']}", 409)
    reason = str(data.get('reason') or '')[:500]

    fields = {'decided_by': actor, 'decision_reason': reason, 'decided_at': _utc_now()}
    audit_details = {'action_type': action['action_type'], 'target': action['target'], 'reason': reason}
    if decision == 'reject':
        fields['status'] = 'REJECTED'
        audit_name = 'response_rejected'
    elif decision == 'investigate':
        # Still undecided: it stays open, and marked so that nobody runs it without looking first
        fields['status'] = 'NEEDS_INVESTIGATION'
        audit_name = 'response_marked_for_investigation'
    else:
        fields['status'] = 'APPROVED'
        audit_name = 'response_approved'
    if decision == 'modify':
        target = valid_target(action['target_type'], data.get('target'))
        if not target:
            _refuse(action, actor, f"Not a valid {action['target_type']} target", 400)
        fields['target'] = target
        audit_name = 'response_modified'
        audit_details.update(target=target, original_target=action['original_target'])

    if not update_response_action(action_id, action['status'], fields):
        _refuse(action, actor, 'Another analyst has already decided this action', 409)
    add_audit_entry(actor, audit_name, 'response_action', action_id, action['incident_id'], audit_details)
    return _load(action_id)


def _simulate(action, playbook):
    """Apply the action to the simulated environment, and return its result"""
    # A review only reads, so only an action that could disrupt something is refused on these
    if action['disruptive'] and action['target'] in playbook['protected_targets']:
        raise ResponseError(f"{action['target']} is a protected target and cannot be acted on")
    record_simulated_enforcement(action['id'], action['action_type'], action['target'])
    return {
        'simulated': True,
        'real_system_changed': False,
        'summary': f"Simulated: {action['label']} on {action['target']}. No real system was changed.",
    }


def _verify(action):
    """Read the simulated environment back. Confirms the record exists, not a real-world effect."""
    if has_simulated_enforcement(action['id'], action['action_type'], action['target']):
        return {'verified': True, 'method': 'Read the simulated enforcement record back.'}
    return {'verified': False, 'method': 'Read the simulated enforcement record back.', 'reason': 'No record was found.'}


def _from_uploaded_log(incident_id):
    """An uploaded log is history, and its analysis stays read-only"""
    runs = ((get_incident(incident_id) or {}).get('entities') or {}).get('simulation_run') or []
    runs = runs if isinstance(runs, list) else [runs]
    return any(str(run).startswith('ds-') for run in runs)


def _runs_for_real(action):
    return real_response.enabled() and action['action_type'] == REAL_ACTION and not _from_uploaded_log(action['incident_id'])


def _block_for_real(action, playbook):
    """Add the real firewall rule and read it back. Returns the result and its verification."""
    reason = real_response.refusal_reason(action['target'], playbook['protected_targets'])
    if reason:
        raise ResponseError(reason)
    ip = clean_ip(action['target'])
    real_response.block(ip)
    method = 'Read the rule back from Windows Firewall.'
    if not real_response.rule_exists(ip):
        return ({'simulated': False, 'real_system_changed': True, 'error': 'The firewall rule could not be read back. Check Windows Firewall.'},
                {'verified': False, 'method': method, 'reason': 'The rule was not found.'})
    return ({'simulated': False, 'real_system_changed': True, 'firewall_rule': real_response.rule_name(ip),
             'summary': f'Real: Windows Firewall on this machine now blocks {ip}, in and out.'},
            {'verified': True, 'method': method})


def describe_actions(actions, playbook=PLAYBOOK):
    """What the page needs beyond the stored row: the real commands, and whether running this one is a real change"""
    described = []
    for action in actions:
        protected = action['disruptive'] and action['target'] in playbook['protected_targets']
        described.append({**action, 'runs_for_real': _runs_for_real(action),
                          'manual_commands': None if protected else real_response.manual_commands(action['action_type'], action['target'])})
    return described


def apply_response_policy(incident_id, risk_level, playbook=PLAYBOOK):
    """Small risks are handled automatically, and high and critical ones wait for the SOC.

    At low and medium risk, safe actions are approved and run in simulation by automation, and each
    step is audited. A disruptive action never runs without a person: at small risk it is held, because
    it would not be proportionate. If the incident's risk rises, held actions join the SOC's queue.
    """
    automatic = playbook['risk_policy'][risk_level].get('response') == 'automatic'
    for action in get_response_actions(incident_id=incident_id, limit=1000):
        if not automatic:
            if action['status'] == 'HELD' and update_response_action(action['id'], 'HELD', {'status': 'PENDING'}):
                add_audit_entry(AUTOMATION_ACTOR, 'response_escalated', 'response_action', action['id'], incident_id,
                                {'action_type': action['action_type'], 'target': action['target'], 'risk_level': risk_level})
        elif action['status'] == 'PENDING':
            if action['disruptive']:
                if update_response_action(action['id'], 'PENDING', {'status': 'HELD'}):
                    add_audit_entry(AUTOMATION_ACTOR, 'response_held', 'response_action', action['id'], incident_id,
                                    {'action_type': action['action_type'], 'target': action['target'], 'risk_level': risk_level})
            elif update_response_action(action['id'], 'PENDING', {'status': 'APPROVED', 'decided_by': AUTOMATION_ACTOR, 'decided_at': _utc_now(),
                                                                  'decision_reason': f'{risk_level} risk: safe steps are handled automatically'}):
                add_audit_entry(AUTOMATION_ACTOR, 'response_auto_approved', 'response_action', action['id'], incident_id,
                                {'action_type': action['action_type'], 'target': action['target'], 'risk_level': risk_level})
                execute_action(action['id'], {'analyst': AUTOMATION_ACTOR}, playbook)


def apply_policy_to_open_incidents(playbook=PLAYBOOK):
    """Open incidents stored before this policy follow it too, so the SOC's queue holds only what the policy sends there"""
    for incident in search_incidents(limit=100000, status='OPEN'):
        if incident.get('risk_level') in playbook['risk_policy']:
            apply_response_policy(incident['id'], incident['risk_level'], playbook)


def execute_action(action_id, data, playbook=PLAYBOOK):
    """Run an approved action, then record the result and verify it. It runs in simulation,
    unless real mode covers it and a person asked: automation never makes a real change."""
    action = _load(action_id)
    actor = str(data.get('analyst') or '').strip()[:MAX_ANALYST_NAME]
    if not actor:
        _refuse(action, None, 'An analyst name is required', 400)
    if action['status'] != 'APPROVED':
        _refuse(action, actor, f"Only an approved action can run. This one is {action['status']}", 409)

    real = actor != AUTOMATION_ACTOR and _runs_for_real(action)
    if real and real_response.not_ready_reason():
        # Nothing was tried, so the action stays approved and can run after a restart as administrator
        _refuse(action, actor, real_response.not_ready_reason(), 409)
    try:
        if real:
            result, verification = _block_for_real(action, playbook)
        else:
            result = _simulate(action, playbook)
            verification = _verify(action)
        status = 'EXECUTED' if verification['verified'] else 'FAILED'
    except (ResponseError, RealResponseError) as error:
        result = {'simulated': not real, 'real_system_changed': False, 'error': error.message}
        verification = {'verified': False, 'method': 'Not attempted.', 'reason': error.message}
        status = 'FAILED'
    except Exception:
        logger.exception('Response %s failed', action_id)
        result = {'simulated': not real, 'real_system_changed': False, 'error': 'The action failed unexpectedly.'}
        verification = {'verified': False, 'method': 'Not attempted.', 'reason': 'Execution failed.'}
        status = 'FAILED'

    claimed = update_response_action(action_id, 'APPROVED', {
        'status': status, 'executed_by': actor, 'executed_at': _utc_now(),
        'result': result, 'verification': verification,
        'mode': REAL_MODE if result['real_system_changed'] else action['mode'],
    })
    if not claimed:
        _refuse(action, actor, 'This action has already been run', 409)
    add_audit_entry(actor, 'response_executed' if status == 'EXECUTED' else 'response_failed', 'response_action',
                    action_id, action['incident_id'], {'action_type': action['action_type'], 'target': action['target'], 'result': result})
    add_audit_entry('system', 'response_verified' if verification['verified'] else 'response_verification_failed',
                    'response_action', action_id, action['incident_id'], verification)
    return _load(action_id)


def undo_action(action_id, data):
    """Remove a real firewall rule that ALLSAFE added"""
    action = _load(action_id)
    actor = str(data.get('analyst') or '').strip()[:MAX_ANALYST_NAME]
    if not actor:
        _refuse(action, None, 'An analyst name is required', 400)
    if action['mode'] != REAL_MODE or action['status'] != 'EXECUTED':
        _refuse(action, actor, 'Only a real block that is in place can be undone', 409)
    ip = clean_ip(action['target'])
    try:
        real_response.unblock(ip)
    except RealResponseError as error:
        _refuse(action, actor, error.message, 409)
    result = {**action['result'], 'undone_by': actor, 'undone_at': _utc_now(),
              'summary': f'Removed: Windows Firewall on this machine no longer blocks {ip}.'}
    if not update_response_action(action_id, 'EXECUTED', {'status': 'UNDONE', 'result': result}):
        _refuse(action, actor, 'This block has already been undone', 409)
    add_audit_entry(actor, 'response_undone', 'response_action', action_id, action['incident_id'],
                    {'action_type': action['action_type'], 'target': ip})
    return _load(action_id)
