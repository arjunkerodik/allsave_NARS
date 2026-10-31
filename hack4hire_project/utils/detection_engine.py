import copy
import hashlib
import json
import logging
import os
import re
import statistics
import uuid
from collections import Counter

from models import find_open_alert, insert_alert, update_alert
from utils.normalizer import is_internal_ip

logger = logging.getLogger(__name__)

RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'detection_rules.json')

SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
ENTITY_FIELDS = ('src_ip', 'dst_ip', 'user', 'hostname', 'session_id', 'process_name')
MAX_ENTITY_VALUES = 20
SAMPLE_EVENTS = 5
RULE_TYPES = ('threshold', 'sum', 'sequence', 'periodic')
_REQUIRED_RULE_KEYS = ('id', 'name', 'description', 'type', 'group_by', 'window_seconds', 'severity', 'confidence')


class RuleConfigError(ValueError):
    """A rule in the configuration file is not usable"""


def _compile_condition(condition):
    """Validate a condition tree and compile its regular expressions in place"""
    if not isinstance(condition, dict):
        raise RuleConfigError(f'condition must be an object: {condition!r}')
    if 'all' in condition or 'any' in condition:
        for child in condition.get('all', []) + condition.get('any', []):
            _compile_condition(child)
        return
    if 'not' in condition:
        _compile_condition(condition['not'])
        return
    if 'field' not in condition:
        raise RuleConfigError(f'condition has no field: {condition!r}')
    if 'regex' in condition:
        try:
            condition['_pattern'] = re.compile(condition['regex'], re.IGNORECASE)
        except re.error as error:
            raise RuleConfigError(f"bad regex in {condition['field']}: {error}")
    elif 'ip_scope' in condition:
        if condition['ip_scope'] not in ('internal', 'external'):
            raise RuleConfigError(f"bad ip_scope: {condition['ip_scope']}")
    elif not any(op in condition for op in ('equals', 'in', 'exists')):
        raise RuleConfigError(f'condition has no operator: {condition!r}')


def _lower(value):
    return value.lower() if isinstance(value, str) else value


def matches(condition, event):
    """Evaluate a compiled condition tree against one event"""
    if 'all' in condition:
        return all(matches(child, event) for child in condition['all'])
    if 'any' in condition:
        return any(matches(child, event) for child in condition['any'])
    if 'not' in condition:
        return not matches(condition['not'], event)
    value = event.get(condition['field'])
    if 'exists' in condition:
        return (value not in (None, '')) == condition['exists']
    if value in (None, ''):
        return False
    if '_pattern' in condition:
        return condition['_pattern'].search(str(value)) is not None
    if 'ip_scope' in condition:
        internal = is_internal_ip(value)
        if internal is None:
            return False
        return internal if condition['ip_scope'] == 'internal' else not internal
    if 'equals' in condition:
        return _lower(value) == _lower(condition['equals'])
    return _lower(value) in [_lower(item) for item in condition['in']]


def validate_rule(rule):
    """Validate one rule definition. Returns a compiled copy, or raises RuleConfigError."""
    compiled = copy.deepcopy(rule)
    missing = [key for key in _REQUIRED_RULE_KEYS if key not in compiled]
    if missing:
        raise RuleConfigError(f"missing keys: {', '.join(missing)}")
    if compiled['type'] not in RULE_TYPES:
        raise RuleConfigError(f"unknown rule type: {compiled['type']}")
    if compiled['severity'] not in SEVERITIES:
        raise RuleConfigError(f"unknown severity: {compiled['severity']}")
    if compiled['window_seconds'] <= 0 or not 0 <= compiled['confidence'] <= 100:
        raise RuleConfigError('window_seconds must be positive and confidence 0-100')
    if compiled['type'] == 'sequence':
        for key in ('first', 'then'):
            if key not in compiled:
                raise RuleConfigError(f'sequence rule needs {key}')
            _compile_condition(compiled[key])
        compiled['match'] = {'any': [compiled['first'], compiled['then']]}
    elif 'match' not in compiled:
        raise RuleConfigError('rule needs match')
    else:
        _compile_condition(compiled['match'])
    if compiled['type'] == 'periodic':
        if compiled.get('min_events', 0) < 3:
            raise RuleConfigError('periodic rule needs min_events of at least 3')
    elif compiled.get('threshold', 0) <= 0:
        raise RuleConfigError('rule needs a positive threshold')
    if compiled['type'] == 'sum' and 'field' not in compiled:
        raise RuleConfigError('sum rule needs field')
    return compiled


def simulation_run_of(event):
    """The simulation run an event belongs to, or None for real telemetry.

    Each run is isolated: repeating a scenario must not add up across runs into a detection
    its ground truth does not expect, and synthetic events must never touch real incidents.
    A dataset is analyzed the same way, as a world of its own.
    """
    return event.get('ingest_batch') if event.get('origin') in ('simulation', 'dataset') else None


def event_summary(event):
    """One readable line describing an event, built only from its stored fields"""
    who = event.get('user')
    host = event.get('hostname')
    event_type = event.get('event_type')
    if event_type == 'ids_alert' and event.get('details'):
        return event['details']
    if event.get('event_category') == 'authentication':
        outcome = 'Failed login' if event.get('auth_result') == 'failure' else 'Successful login'
        target = f" to {host}" if host else ''
        return f"{outcome} for {who or 'unknown user'} from {event.get('src_ip') or 'unknown source'}{target}"
    if event.get('source') == 'network':
        size = event.get('bytes_out') or event.get('bytes')
        size_text = f', {size:,} bytes' if size else ''
        return (f"{event.get('src_ip')} -> {event.get('dst_ip')}:{event.get('dst_port') or '?'} "
                f"{event.get('protocol') or ''}{size_text}".replace('  ', ' '))
    if event.get('command_line'):
        return f"{event.get('process_name') or 'process'}: {event['command_line']}"
    if event.get('method') or event.get('endpoint'):
        return f"{event.get('method') or ''} {event.get('endpoint') or ''} -> {event.get('status_code') or '?'}".strip()
    return event.get('details') or event.get('file_path') or event.get('process_name') or event_type or 'event'


class DetectionEngine:
    """Evaluates the configured IOA rules over new events, using event time."""

    def __init__(self, rules_path=RULES_PATH):
        self.rules = []
        self.load_errors = []
        self.failed_rules = []
        self.rules_path = rules_path
        self.reload()

    def reload(self):
        """Load rules from configuration. A bad rule is reported and skipped, not fatal."""
        self.rules, self.load_errors = [], []
        try:
            with open(self.rules_path, encoding='utf-8') as handle:
                definitions = json.load(handle)['rules']
        except (OSError, ValueError, KeyError) as error:
            self.load_errors.append({'rule': None, 'error': f'cannot read rule file: {error}'})
            logger.error('Cannot read rule file %s: %s', self.rules_path, error)
            return
        seen = set()
        for definition in definitions:
            rule_id = definition.get('id') if isinstance(definition, dict) else None
            try:
                if not isinstance(definition, dict):
                    raise RuleConfigError('rule must be an object')
                if rule_id in seen:
                    raise RuleConfigError('duplicate rule id')
                seen.add(rule_id)
                if definition.get('enabled', True):
                    self.rules.append(validate_rule(definition))
            except RuleConfigError as error:
                self.load_errors.append({'rule': rule_id, 'error': str(error)})
                logger.error('Skipping rule %s: %s', rule_id, error)

    @property
    def max_window(self):
        return max((rule['window_seconds'] for rule in self.rules), default=0)

    def describe_rules(self):
        """Rule definitions for the API, without compiled internals"""
        def clean(value):
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if not k.startswith('_')}
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        return [clean(rule) for rule in self.rules]

    def evaluate(self, new_events, context_events):
        """Return findings for rules triggered by new_events. context_events must include them."""
        new_ids = {event['id'] for event in new_events}
        findings = []
        self.failed_rules = []
        for rule in self.rules:
            try:
                findings.extend(self._evaluate_rule(rule, new_ids, context_events))
            except Exception:
                # One broken rule must not stop the others from running, but it is recorded,
                # because an analysis missing a rule must not look like a clean one
                logger.exception('Rule %s failed', rule['id'])
                self.failed_rules.append(rule['id'])
        return findings

    def _evaluate_rule(self, rule, new_ids, context_events):
        groups = {}
        for event in context_events:
            if event.get('ts_epoch') is None or not matches(rule['match'], event):
                continue
            key = tuple(event.get(field) for field in rule['group_by'])
            usable = any(part not in (None, '') for part in key) if rule.get('group_optional') \
                else all(part not in (None, '') for part in key)
            if usable:
                groups.setdefault(key + (simulation_run_of(event),), []).append(event)

        evaluate = {'threshold': self._sliding, 'sum': self._sliding,
                    'sequence': self._sequence, 'periodic': self._periodic}[rule['type']]
        findings = []
        for key, events in groups.items():
            if not any(event['id'] in new_ids for event in events):
                continue
            events.sort(key=lambda e: (e['ts_epoch'], e['id']))
            group = dict(zip(rule['group_by'], key))
            if key[-1]:
                group['simulation_run'] = key[-1]
            for finding in evaluate(rule, events, new_ids):
                finding.update(rule=rule, group=group)
                findings.append(finding)
        return findings

    def _sliding(self, rule, events, new_ids):
        """Count, distinct-count or sum over a sliding window. Overlapping hits become one finding."""
        window = rule['window_seconds']
        threshold = rule['threshold']
        distinct_field = rule.get('distinct')
        sum_field = rule['field'] if rule['type'] == 'sum' else None
        values = Counter()
        total = 0
        left = 0
        spans = []

        def add(event, sign):
            nonlocal total
            if sum_field:
                total += sign * (event.get(sum_field) or 0)
            elif distinct_field:
                value = event.get(distinct_field)
                if value not in (None, ''):
                    values[value] += sign
                    if values[value] <= 0:
                        del values[value]
            else:
                total += sign

        for right, event in enumerate(events):
            add(event, 1)
            while event['ts_epoch'] - events[left]['ts_epoch'] > window:
                add(events[left], -1)
                left += 1
            metric = len(values) if distinct_field else total
            if metric >= threshold and event['id'] in new_ids:
                if spans and events[spans[-1]['right']]['ts_epoch'] >= events[left]['ts_epoch']:
                    spans[-1]['right'] = right
                    spans[-1]['observed'] = max(spans[-1]['observed'], metric)
                else:
                    spans.append({'left': left, 'right': right, 'observed': metric})
        return [self._finding(events[s['left']:s['right'] + 1], s['observed']) for s in spans]

    def _sequence(self, rule, events, new_ids):
        """At least `threshold` events of `first`, then an event of `then`, inside the window"""
        findings = []
        for index, event in enumerate(events):
            if event['id'] not in new_ids or not matches(rule['then'], event):
                continue
            earlier = [e for e in events[:index]
                       if event['ts_epoch'] - e['ts_epoch'] <= rule['window_seconds'] and matches(rule['first'], e)]
            if len(earlier) >= rule['threshold']:
                findings.append(self._finding(earlier + [event], len(earlier)))
        return findings

    def _periodic(self, rule, events, new_ids):
        """Regular spacing between connections, measured from the event timestamps"""
        last_new = max(i for i, event in enumerate(events) if event['id'] in new_ids)
        end_ts = events[last_new]['ts_epoch']
        recent = [e for e in events[:last_new + 1] if end_ts - e['ts_epoch'] <= rule['window_seconds']][-200:]
        if len(recent) < rule['min_events']:
            return []
        gaps = [b['ts_epoch'] - a['ts_epoch'] for a, b in zip(recent, recent[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap < rule['min_interval_seconds']:
            return []
        jitter = statistics.pstdev(gaps) / mean_gap
        if jitter > rule['max_jitter_ratio']:
            return []
        return [self._finding(recent, len(recent), interval_seconds=mean_gap, jitter_percent=jitter * 100)]

    @staticmethod
    def _finding(events, observed, **extra):
        return {
            'events': events,
            'observed': observed,
            'first_ts': events[0]['ts_epoch'],
            'last_ts': events[-1]['ts_epoch'],
            'metrics': extra,
        }


def _iso_of(events, ts_value):
    for event in events:
        if event['ts_epoch'] == ts_value:
            return event['timestamp']
    return None


def _entities_from(events):
    entities = {}
    for field in ENTITY_FIELDS:
        values = []
        for event in events:
            value = event.get(field)
            if value not in (None, '') and value not in values:
                values.append(value)
            if len(values) >= MAX_ENTITY_VALUES:
                break
        if values:
            entities[field] = values
    run = simulation_run_of(events[0]) if events else None
    if run:
        entities['simulation_run'] = [run]
    return entities


def _merge_entities(first, second):
    merged = {field: list(values) for field, values in first.items()}
    for field, values in second.items():
        target = merged.setdefault(field, [])
        target.extend(v for v in values if v not in target and len(target) < MAX_ENTITY_VALUES)
    return merged


class _BlankDefault(dict):
    def __missing__(self, key):
        return 'unknown'


def _explain(finding, sample_text):
    """Fill a rule's explanation template from what was actually observed"""
    rule = finding['rule']
    template = rule.get('explanation')
    if not template:
        return rule['description']
    threshold = rule.get('threshold') or rule.get('min_events') or 0
    values = _BlankDefault(
        observed=finding['observed'],
        threshold=threshold,
        window_seconds=rule['window_seconds'],
        observed_mb=finding['observed'] / (1024 * 1024),
        threshold_mb=threshold / (1024 * 1024),
        sample=sample_text,
        **finding.get('metrics', {}),
    )
    for field, value in finding['group'].items():
        values[field] = value if value not in (None, '') else 'unknown'
    first_event = finding['events'][-1]
    for field in ('user', 'hostname', 'process_name'):
        if values.get(field) in (None, 'unknown') and first_event.get(field):
            values[field] = first_event[field]
    try:
        return template.format_map(values)
    except (ValueError, KeyError, TypeError):
        logger.warning('Bad explanation template in rule %s', rule['id'])
        return rule['description']


def _confidence(rule, observed):
    """Base confidence from the rule, plus 5 points for each multiple above the threshold"""
    confidence = rule['confidence']
    threshold = rule.get('threshold', 0)
    if threshold > 1:
        confidence += int(5 * max(0.0, observed / threshold - 1))
    return min(confidence, rule.get('max_confidence', rule['confidence']))


def _evidence(finding):
    rule = finding['rule']
    events = finding['events']
    samples = events[:SAMPLE_EVENTS] if len(events) <= SAMPLE_EVENTS else events[:SAMPLE_EVENTS - 1] + events[-1:]
    logic = {key: rule[key] for key in ('type', 'group_by', 'threshold', 'distinct', 'field', 'min_events',
                                        'min_interval_seconds', 'max_jitter_ratio') if key in rule}
    logic['window_seconds'] = rule['window_seconds']
    for key in ('match', 'first', 'then'):
        if key in rule and not (key == 'match' and rule['type'] == 'sequence'):
            logic[key] = _public_condition(rule[key])
    evidence = {
        'rule_logic': logic,
        'matched_group': finding['group'],
        'observed': finding['observed'],
        'metrics': finding.get('metrics', {}),
        'sample_events': [{'event_id': e.get('event_id'), 'timestamp': e.get('timestamp'),
                           'summary': event_summary(e)} for e in samples],
    }
    evidence.update(finding.get('extra_evidence', {}))
    return evidence


def _public_condition(value):
    if isinstance(value, dict):
        return {k: _public_condition(v) for k, v in value.items() if not k.startswith('_')}
    if isinstance(value, list):
        return [_public_condition(v) for v in value]
    return value


def persist_finding(finding):
    """Store a finding as a new alert, or merge it into the overlapping alert for the same
    rule and entity. Returns (alert_id, created)."""
    rule = finding['rule']
    events = finding['events']
    group_text = json.dumps(sorted((k, str(v)) for k, v in finding['group'].items()))
    dedupe_key = hashlib.sha256(f"{rule['id']}|{group_text}".encode()).hexdigest()
    log_ids = [event['id'] for event in events]
    evidence = _evidence(finding)
    explanation = _explain(finding, evidence['sample_events'][-1]['summary'])
    confidence = _confidence(rule, finding['observed'])
    entities = _entities_from(events)
    first_iso = _iso_of(events, finding['first_ts'])
    last_iso = _iso_of(events, finding['last_ts'])

    existing = find_open_alert(dedupe_key, finding['first_ts'] - rule['window_seconds'])
    if existing:
        fields = {
            'explanation': explanation if finding['observed'] >= (existing['observed'] or 0) else existing['explanation'],
            'evidence': evidence if finding['observed'] >= (existing['observed'] or 0) else existing['evidence'],
            'observed': max(finding['observed'], existing['observed'] or 0),
            'confidence': max(confidence, existing['confidence']),
            'entities': _merge_entities(existing['entities'] or {}, entities),
        }
        if finding['first_ts'] < existing['first_seen_ts']:
            fields.update(first_seen=first_iso, first_seen_ts=finding['first_ts'])
        if finding['last_ts'] > existing['last_seen_ts']:
            fields.update(last_seen=last_iso, last_seen_ts=finding['last_ts'])
        update_alert(existing['id'], fields, log_ids)
        return existing['id'], False

    alert_id = insert_alert({
        'alert_uid': f'ALT-{uuid.uuid4().hex[:10].upper()}',
        'dedupe_key': dedupe_key,
        'rule_id': rule['id'],
        'rule_name': rule['name'],
        'detection_type': rule.get('detection_type', 'IOA'),
        'severity': rule['severity'],
        'confidence': confidence,
        'explanation': explanation,
        'evidence': evidence,
        'mitre': rule.get('mitre', []),
        'recommendations': rule.get('recommendations', []),
        'entities': entities,
        'observed': finding['observed'],
        'event_count': len(set(log_ids)),
        'first_seen': first_iso,
        'last_seen': last_iso,
        'first_seen_ts': finding['first_ts'],
        'last_seen_ts': finding['last_ts'],
    }, log_ids)
    return alert_id, True
