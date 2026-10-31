import logging
import math
import random
import threading

from models import upsert_anomaly
from utils.dataset_generator import normal_events
from utils.detection_engine import simulation_run_of
from utils.simulator import SCENARIOS, event_label

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 300
MIN_EVENTS = 4
THRESHOLD_QUANTILE = 0.998
MODEL_SEED = 42
ADMIN_PORTS = {22, 23, 135, 445, 3389, 5985, 5986}
TRAINING_SETS = ((1, 4000, 7200), (2, 2000, 3600), (3, 500, 3600), (4, 8000, 7200), (5, 200, 600))
HOLDOUT_SETS = ((11, 3000, 7200), (12, 1000, 3600), (13, 300, 3600))
MAX_STORED_EVENT_IDS = 100

FEATURE_LABELS = (
    'events', 'failed logins', 'successful logins', 'distinct users', 'distinct destinations',
    'distinct destination ports', 'connections to admin ports', 'bytes transferred', 'process starts',
)


def entity_of(event):
    return event.get('src_ip') or event.get('hostname')


def bucket_of(ts_epoch):
    return int(ts_epoch // WINDOW_SECONDS)


def window_counts(events):
    """What one source or host did in one time window. No detection result or label is an input."""
    return [
        len(events),
        sum(1 for e in events if e.get('event_type') == 'authentication_failure'),
        sum(1 for e in events if e.get('event_type') == 'authentication_success'),
        len({e['user'] for e in events if e.get('user')}),
        len({e['dst_ip'] for e in events if e.get('dst_ip')}),
        len({e['dst_port'] for e in events if e.get('dst_port')}),
        sum(1 for e in events if e.get('dst_port') in ADMIN_PORTS),
        sum((e.get('bytes') or e.get('bytes_out') or 0) for e in events),
        sum(1 for e in events if e.get('event_type') == 'process_start'),
    ]


def _vector(counts):
    return [math.log1p(value) for value in counts]


def _windows(rows):
    """rows: (timestamp, fields, is_attack)"""
    groups = {}
    for when, fields, is_attack in rows:
        entity = entity_of(fields)
        if entity:
            groups.setdefault((entity, bucket_of(when)), []).append((fields, is_attack))
    return [(window_counts([item[0] for item in members]), any(item[1] for item in members)) for members in groups.values()]


def _normal_rows(seed, count, span):
    return [(when, fields, False) for when, _, fields in normal_events(random.Random(seed), count, 0, span)]


class AnomalyEngine:
    """An Isolation Forest over per-source activity windows, trained on synthetic normal activity.

    It says "this window is statistically unusual", never "this is an attack". A finding opens no
    incident by itself: it adds to the behavioral risk of an incident about the same entity, and
    shows as suspicious activity. It does not run on live telemetry from this machine, because
    the synthetic baseline says nothing about what is normal here.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._model = None
        self._failure = None
        self.threshold = None
        self.score_span = None
        self.means = None
        self.deviations = None
        self.trained_windows = 0
        self._evaluation = None

    def prepare(self):
        """Train once. Takes under a second, and is seeded, so the result is reproducible."""
        with self._lock:
            if self._model is not None or self._failure:
                return self._model is not None
            try:
                import numpy as np
                from sklearn.ensemble import IsolationForest
                windows = []
                for seed, count, span in TRAINING_SETS:
                    windows += _windows(_normal_rows(seed, count, span))
                data = np.array([_vector(counts) for counts, _ in windows])
                model = IsolationForest(n_estimators=150, random_state=MODEL_SEED).fit(data)
                scores = -model.score_samples(data)
                self.threshold = float(np.quantile(scores, THRESHOLD_QUANTILE))
                self.score_span = max(0.05, float(scores.max()) - self.threshold)
                self.means = data.mean(axis=0)
                self.deviations = data.std(axis=0)
                self.trained_windows = len(data)
                self._model = model
                return True
            except Exception as error:
                logger.exception('Could not train the anomaly model')
                self._failure = f'The anomaly model could not be prepared ({type(error).__name__}).'
                return False

    def unavailable_reason(self):
        return self._failure

    @staticmethod
    def applicable(event):
        return event.get('ts_epoch') is not None and event.get('origin') != 'live' and bool(entity_of(event))

    def _is_flagged(self, score, event_count):
        return score > self.threshold and event_count >= MIN_EVENTS

    def _strength(self, score):
        """A 50 to 99 display value for how far past the threshold a window is. Not a probability."""
        return min(99, round(50 + 49 * min(1.0, (score - self.threshold) / self.score_span)))

    def _explain(self, counts):
        vector = _vector(counts)
        ranked = sorted(range(len(counts)), key=lambda i: (vector[i] - self.means[i]) / max(self.deviations[i], 0.1), reverse=True)
        parts = [f'{counts[i]:,} {FEATURE_LABELS[i]} (typically about {max(0.0, math.expm1(self.means[i])):,.1f})'
                 for i in ranked[:3] if counts[i] and vector[i] > self.means[i]]
        return f"Unusual compared with the model's synthetic baseline of normal activity: {', '.join(parts) or 'an unusual combination of activity'}. A statistical anomaly, not a confirmed attack."

    def evaluate(self, new_events, context):
        """Score every window these events touched, and store the unusual ones. Returns them."""
        relevant = [event for event in new_events if self.applicable(event)]
        if not relevant or not self.prepare():
            return []
        import numpy as np
        touched = {(event.get('ingest_batch'), entity_of(event), bucket_of(event['ts_epoch'])) for event in relevant}
        members = {}
        for event in context:
            if self.applicable(event):
                key = (event.get('ingest_batch'), entity_of(event), bucket_of(event['ts_epoch']))
                if key in touched:
                    members.setdefault(key, []).append(event)
        keys = list(members)
        if not keys:
            return []
        counts = [window_counts(members[key]) for key in keys]
        scores = -self._model.score_samples(np.array([_vector(row) for row in counts]))

        findings = []
        for key, row, score in zip(keys, counts, scores):
            if not self._is_flagged(float(score), row[0]):
                continue
            batch, entity, bucket = key
            events = members[key]
            finding = {
                'batch_id': batch,
                'scope': simulation_run_of(events[0]),
                'entity': entity,
                'window_start_ts': bucket * WINDOW_SECONDS,
                'window_end_ts': (bucket + 1) * WINDOW_SECONDS,
                'strength': self._strength(float(score)),
                'score': round(float(score), 4),
                'event_count': row[0],
                'explanation': self._explain(row),
                'features': dict(zip(FEATURE_LABELS, row)),
                'event_log_ids': [event['id'] for event in events[:MAX_STORED_EVENT_IDS]],
            }
            upsert_anomaly(finding)
            findings.append(finding)
        return findings

    def evaluation(self):
        """Measured on seeded data the model did not train on. Synthetic, so it says how the model
        separates these scenarios from this normal activity, and nothing about real attacks."""
        if not self.prepare():
            return None
        with self._lock:
            if self._evaluation:
                return self._evaluation
        import numpy as np
        normal = []
        for seed, count, span in HOLDOUT_SETS:
            normal += _windows(_normal_rows(seed, count, span))
        normal_scores = -self._model.score_samples(np.array([_vector(counts) for counts, _ in normal]))
        false_alarms = sum(1 for (counts, _), score in zip(normal, normal_scores) if self._is_flagged(float(score), counts[0]))

        by_scenario = {}
        for name, definition in SCENARIOS.items():
            rows = [(1000000 + offset, fields, event_label(definition, offset) != 'normal') for offset, _, fields in definition['build']()]
            windows = _windows(rows)
            scores = -self._model.score_samples(np.array([_vector(counts) for counts, _ in windows]))
            attack = [(counts, score) for (counts, is_attack), score in zip(windows, scores) if is_attack]
            flagged_normal = sum(1 for (counts, is_attack), score in zip(windows, scores) if not is_attack and self._is_flagged(float(score), counts[0]))
            by_scenario[name] = {'attack_windows': len(attack), 'flagged': sum(1 for counts, score in attack if self._is_flagged(float(score), counts[0])), 'normal_windows_flagged': flagged_normal}

        attack_windows = sum(row['attack_windows'] for row in by_scenario.values())
        flagged = sum(row['flagged'] for row in by_scenario.values())
        result = {
            'held_out_normal_windows': len(normal),
            'held_out_false_alarms': false_alarms,
            'false_alarm_rate': round(false_alarms / len(normal), 4) if normal else None,
            'attack_windows': attack_windows,
            'attack_windows_flagged': flagged,
            'recall': round(flagged / attack_windows, 4) if attack_windows else None,
            'by_scenario': by_scenario,
            'note': 'Measured on seeded synthetic data the model did not train on. It does not predict performance on real traffic. Low recall is expected: single commands are not statistically unusual, and the rules cover those.',
        }
        with self._lock:
            self._evaluation = result
        return result

    def status(self):
        return {
            'name': 'Anomaly model (Isolation Forest over 5-minute activity windows)',
            'available': self._failure is None,
            'reason': self._failure,
            'loaded': self._model is not None,
            'trained_windows': self.trained_windows,
            'threshold_quantile': THRESHOLD_QUANTILE,
            'minimum_events': MIN_EVENTS,
            'features': list(FEATURE_LABELS),
            'note': 'Trained on synthetic normal activity. Not applied to live telemetry from this machine. A finding is never treated as a confirmed attack.',
        }
