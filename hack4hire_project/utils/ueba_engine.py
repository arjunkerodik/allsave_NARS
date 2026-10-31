import json
import logging
import os
import statistics

from models import get_outbound_sizes, get_user_login_history
from utils.detection_engine import simulation_run_of

logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'ueba_rules.json')
MB = 1024 * 1024


def load_ueba_rules(path=CONFIG_PATH):
    with open(path, encoding='utf-8') as handle:
        return {rule['id']: rule for rule in json.load(handle)['rules']}


def _scope(event):
    """A simulation run or dataset is compared only with itself, and real telemetry with real telemetry"""
    return simulation_run_of(event)


def _hour_of(ts_epoch):
    return (ts_epoch % 86400) / 3600


def _clock(hour):
    return f'{int(hour):02d}:{int(hour * 60) % 60:02d}'


def _finding(rule, event, observed, group, metrics):
    run = _scope(event)
    if run:
        group = {**group, 'simulation_run': run}
    return {'rule': rule, 'group': group, 'events': [event], 'observed': observed,
            'first_ts': event['ts_epoch'], 'last_ts': event['ts_epoch'], 'metrics': metrics}


class UebaEngine:
    """Compares each entity with its own recorded history. Every finding states its baseline.

    These are transparent statistics, not a trained model. An entity without enough history is
    not judged at all, so a new deployment starts quiet rather than flagging everything as new.
    """

    def __init__(self, rules=None):
        self.rules = rules if rules is not None else load_ueba_rules()
        self.failed = []

    @staticmethod
    def applicable(event):
        if event.get('ts_epoch') is None:
            return False
        return (event.get('event_type') == 'authentication_success' and bool(event.get('user'))) or bool(event.get('bytes_out'))

    def evaluate(self, new_events):
        findings = []
        self.failed = []
        history = {}
        for event in new_events:
            try:
                if event.get('event_type') == 'authentication_success' and event.get('user'):
                    earlier = self._earlier_logins(event, history)
                    findings.extend(self._new_source_login(event, earlier))
                    findings.extend(self._unusual_login_time(event, earlier))
                findings.extend(self._unusual_outbound_volume(event))
            except Exception as error:
                # A behavioral check must never stop the rule and IOC detections, but it is recorded
                logger.exception('Behavioral check failed for event %s', event.get('id'))
                self.failed.append(type(error).__name__)
        return findings

    @staticmethod
    def _earlier_logins(event, history):
        """This user's logins before this event. Read once per user for each batch."""
        key = (event['user'], _scope(event))
        if key not in history:
            history[key] = get_user_login_history(event['user'], _scope(event))
        return [row for row in history[key] if (row['ts_epoch'], row['id']) < (event['ts_epoch'], event['id'])]

    def _new_source_login(self, event, earlier):
        rule = self.rules.get('UEBA-001')
        if not rule or not event.get('src_ip'):
            return []
        sources = {row['src_ip'] for row in earlier if row['src_ip']}
        logins = sum(1 for row in earlier if row['src_ip'])
        if logins < rule['min_baseline_events'] or event['src_ip'] in sources:
            return []
        return [_finding(rule, event, logins, {'user': event['user'], 'src_ip': event['src_ip']},
                         {'baseline_logins': logins, 'known_sources': len(sources)})]

    def _unusual_login_time(self, event, earlier):
        """Only a user with a clear pattern can be outside it. Times spread over the day show none."""
        rule = self.rules.get('UEBA-003')
        if not rule or len(earlier) < rule['min_baseline_events']:
            return []
        hours = sorted(_hour_of(row['ts_epoch']) for row in earlier)
        gaps = [(hours[(i + 1) % len(hours)] - hours[i]) % 24 for i in range(len(hours))]
        widest = max(range(len(gaps)), key=gaps.__getitem__)
        usual_start = hours[(widest + 1) % len(hours)]
        usual_span = 24 - gaps[widest]
        if usual_span > rule['max_usual_hours']:
            return []
        hour = _hour_of(event['ts_epoch'])
        past_start = (hour - usual_start) % 24
        if past_start <= usual_span:
            return []
        outside = min(past_start - usual_span, 24 - past_start)
        if outside < rule['min_hours_outside']:
            return []
        return [_finding(rule, event, len(earlier), {'user': event['user']}, {
            'baseline_logins': len(earlier), 'login_hour': _clock(hour),
            'usual_start': _clock(usual_start), 'usual_end': _clock((usual_start + usual_span) % 24)})]

    def _unusual_outbound_volume(self, event):
        rule = self.rules.get('UEBA-002')
        size = event.get('bytes_out')
        if not rule or not size or not event.get('src_ip') or size < rule['min_bytes']:
            return []
        history = get_outbound_sizes(event['src_ip'], event['ts_epoch'], event['id'], _scope(event))
        if len(history) < rule['min_baseline_events']:
            return []
        mean = statistics.mean(history)
        deviation = statistics.pstdev(history)
        # A perfectly flat history has no deviation. A floor stops one small change looking infinite.
        score = (size - mean) / max(deviation, mean * 0.1, 1)
        if score < rule['min_deviations']:
            return []
        return [_finding(rule, event, size, {'src_ip': event['src_ip']},
                         {'baseline_events': len(history), 'baseline_mean_mb': mean / MB,
                          'observed_size_mb': size / MB, 'deviations': score})]
