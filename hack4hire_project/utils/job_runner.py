import hashlib
import logging
import random
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from models import (
    find_completed_dataset, get_dataset, get_simulation_outcome, insert_dataset, insert_ground_truth,
    insert_simulation_run, update_dataset, update_simulation_run,
)
from utils.dataset_analysis import analyze_batch
from utils.dataset_engine import prepare_dataset, summarize_generated
from utils.dataset_generator import PROFILES, expected_rules_for, generate_dataset, generate_feed_test, normal_events
from utils.evaluation import evaluate_batch
from utils.log_ingest import UploadRejected, ingest_records
from utils.report_engine import build_report
from utils.simulator import SCENARIOS, build_scenario_events

logger = logging.getLogger(__name__)

INTENSITIES = {'low': 0, 'medium': 50, 'high': 200}
SPEEDS = {'instant': 0, 'fast': 0.15, 'normal': 0.75}
CHUNKS_PER_RUN = 20
MAX_BACKGROUND_EVENTS = 5000
DATASET_CHUNK = 500


class JobError(ValueError):
    """A refused request. The message is safe to show to the client."""

    def __init__(self, message, status=400, validation=None, validation_failed=False):
        super().__init__(message)
        self.message = message
        self.status = status
        self.validation = validation
        self.validation_failed = validation_failed


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


class JobRunner:
    """Runs simulations and datasets on background threads, through the same ingestion and
    detection path as any other log. One of each kind runs at a time."""

    def __init__(self, engine_getter, socketio=None):
        self._engine = engine_getter
        self.socketio = socketio
        self._lock = threading.Lock()
        self._simulation = None
        self._dataset = None

    def _emit(self, name, payload):
        if self.socketio:
            try:
                self.socketio.emit(name, payload)
            except Exception:
                # Losing a progress update must never affect the job itself
                logger.exception('Could not publish %s', name)

    def active_simulation(self):
        job = self._simulation
        return job['run_id'] if job else None

    def active_dataset(self):
        job = self._dataset
        return job['dataset_id'] if job else None

    # ---------- Simulation ----------

    def start_simulation(self, params):
        scenario = params.get('scenario')
        if scenario not in SCENARIOS:
            raise JobError('Unknown scenario')
        intensity = params.get('intensity') or 'low'
        if intensity not in INTENSITIES:
            raise JobError(f"Intensity must be one of: {', '.join(INTENSITIES)}")
        speed = params.get('speed') or 'fast'
        if speed not in SPEEDS:
            raise JobError(f"Speed must be one of: {', '.join(SPEEDS)}")
        background = params.get('background_events')
        try:
            background = INTENSITIES[intensity] if background in (None, '') else int(background)
            seed = random.randrange(1, 1000000) if params.get('seed') in (None, '') else int(params['seed'])
        except (TypeError, ValueError):
            raise JobError('Background events and seed must be whole numbers')
        if not 0 <= background <= MAX_BACKGROUND_EVENTS:
            raise JobError(f'Background events must be between 0 and {MAX_BACKGROUND_EVENTS}')

        with self._lock:
            if self._simulation:
                raise JobError(f"Simulation {self._simulation['run_id']} is still running. Stop it or wait for it to finish.", 409)
            run_id = f'sim-{uuid.uuid4().hex[:12]}'
            job = {'run_id': run_id, 'stop': threading.Event(), 'resume': threading.Event(), 'status': 'RUNNING'}
            job['resume'].set()
            self._simulation = job

        try:
            events = self._build_simulation(scenario, run_id, background, seed)
            definition = SCENARIOS[scenario]
            insert_ground_truth([(raw['event_id'], run_id, label, attack) for raw, _, label, attack in events])
            insert_simulation_run({'run_id': run_id, 'scenario': scenario, 'is_malicious': definition['malicious'],
                                   'expected_rules': definition['expected_rules'], 'event_count': len(events),
                                   'started_at': _utc_now(), 'status': 'RUNNING', 'intensity': intensity, 'speed': speed,
                                   'seed': seed, 'background_events': background})
        except Exception:
            self._simulation = None
            raise
        threading.Thread(target=self._run_simulation, args=(job, events, SPEEDS[speed]), daemon=True).start()
        self._emit('simulation_progress', {'run_id': run_id, 'status': 'RUNNING', 'processed': 0, 'total': len(events)})
        return get_simulation_outcome(run_id)

    def _build_simulation(self, scenario, run_id, background, seed):
        built = build_scenario_events(scenario, run_id)
        rows = [(raw, source, label, scenario if label != 'normal' else None) for raw, source, label in built]
        if background:
            stamps = [datetime.fromisoformat(raw['timestamp']).timestamp() for raw, *_ in rows]
            # Noise shares the attack's time span, from hosts that have nothing to do with it
            start, end = min(stamps), max(max(stamps), min(stamps) + 60)
            for index, (when, source, fields) in enumerate(normal_events(random.Random(seed), background, start, end)):
                raw = {k: v for k, v in fields.items() if v is not None}
                raw.update(timestamp=datetime.fromtimestamp(when, timezone.utc).isoformat(), event_id=f'{run_id}-bg{index:05d}', synthetic=True)
                rows.append((raw, source, 'normal', None))
        rows.sort(key=lambda row: row[0]['timestamp'])
        return rows

    def _control(self, run_id, action):
        job = self._simulation
        if not job or job['run_id'] != run_id:
            raise JobError('That simulation is not running', 409)
        if action == 'stop':
            job['stop'].set()
            job['resume'].set()
        elif action == 'pause':
            job['resume'].clear()
            job['status'] = 'PAUSED'
            update_simulation_run(run_id, {'status': 'PAUSED'})
        else:
            job['status'] = 'RUNNING'
            update_simulation_run(run_id, {'status': 'RUNNING'})
            job['resume'].set()
        self._emit('simulation_progress', {'run_id': run_id, 'status': 'STOPPING' if action == 'stop' else job['status']})
        return get_simulation_outcome(run_id)

    def stop_simulation(self, run_id):
        return self._control(run_id, 'stop')

    def pause_simulation(self, run_id):
        return self._control(run_id, 'pause')

    def resume_simulation(self, run_id):
        return self._control(run_id, 'resume')

    def _run_simulation(self, job, events, delay):
        run_id = job['run_id']
        total = len(events)
        size = max(1, total // CHUNKS_PER_RUN) if delay else total
        processed = failed = 0
        status, error = 'COMPLETED', None
        try:
            for start in range(0, total, size):
                job['resume'].wait()
                if job['stop'].is_set():
                    status = 'STOPPED'
                    break
                chunk = events[start:start + size]
                report = ingest_records([(raw, source) for raw, source, *_ in chunk], origin='simulation', batch_id=run_id)
                processed += report['stored']
                failed += report['rejected'] + report['duplicates']
                update_simulation_run(run_id, {'processed_count': processed, 'failed_count': failed})
                self._emit('simulation_progress', {'run_id': run_id, 'status': job['status'], 'processed': processed, 'failed': failed, 'total': total})
                if delay and start + size < total:
                    time.sleep(delay)
            self._engine().process_new_events()
        except Exception as e:
            logger.exception('Simulation %s failed', run_id)
            status, error = 'FAILED', f'The run stopped because of an internal error ({type(e).__name__}). Events stored so far were kept.'
        self._finish_simulation(run_id, status, error, processed, total)

    def _finish_simulation(self, run_id, status, error, processed, total):
        report_id = None
        try:
            update_simulation_run(run_id, {'status': status, 'error': error, 'completed_at': _utc_now()})
            if processed:
                report_id = build_report('simulation', run_id)['report_id']
        except Exception:
            logger.exception('Could not finish simulation %s', run_id)
        finally:
            self._simulation = None
        self._emit('simulation_progress', {'run_id': run_id, 'status': status, 'processed': processed, 'total': total,
                                           'error': error, 'report_id': report_id, 'finished': True})

    # ---------- Datasets ----------

    def _claim_dataset(self, dataset_id):
        with self._lock:
            if self._dataset:
                raise JobError('Another log file is still being analyzed. Wait for it to finish, then add the next one.', 409)
            self._dataset = {'dataset_id': dataset_id}

    def start_upload(self, filename, data, mapping, default_source, reanalyze=False):
        """Validate now, so a bad file is refused at once, then process in the background"""
        try:
            prepared = prepare_dataset(filename, data, mapping, default_source)
        except UploadRejected as error:
            self._record_validation_failure(filename, data, str(error))
            raise JobError(str(error), 400, validation_failed=True)
        if not prepared['rows']:
            first = prepared['invalid'][0] if prepared['invalid'] else None
            detail = f" First problem, row {first['row']}: {'; '.join(first['errors'])}." if first else ''
            message = f'No valid events found in this file.{detail}'
            self._record_validation_failure(filename, data, message, prepared)
            raise JobError(message, 400, validation=prepared['summary'], validation_failed=True)
        existing = find_completed_dataset(prepared['sha256'])
        if existing and not reanalyze:
            return {'duplicate_of': existing, 'dataset': get_dataset(existing)}

        dataset_id = f'ds-{uuid.uuid4().hex[:12]}'
        self._claim_dataset(dataset_id)
        try:
            rows = []
            truth = []
            for index, row in enumerate(prepared['rows']):
                event_id = f"{dataset_id}-{hashlib.sha256(row['fingerprint'].encode()).hexdigest()[:16]}"
                raw = {**row['raw'], 'event_id': event_id}
                rows.append((raw, row['hint'] or default_source))
                if row['label']:
                    truth.append((event_id, dataset_id, row['label'], row['attack_type']))
            insert_ground_truth(truth)
            insert_dataset({'dataset_id': dataset_id, 'name': filename, 'kind': 'upload', 'status': 'PROCESSING', 'sha256': prepared['sha256'],
                            'params': {'mapping': mapping, 'default_source': default_source}, 'summary': prepared['summary'],
                            'invalid_records': prepared['invalid'], 'total_events': len(rows)})
        except Exception:
            self._dataset = None
            raise
        threading.Thread(target=self._run_dataset, args=(dataset_id, rows, 'dataset', None), daemon=True).start()
        return {'dataset': get_dataset(dataset_id)}

    @staticmethod
    def _record_validation_failure(filename, data, message, prepared=None):
        """A refused file still leaves a record, so the analyst can see that it was refused and why"""
        insert_dataset({'dataset_id': f'ds-{uuid.uuid4().hex[:12]}', 'name': filename or 'unnamed file', 'kind': 'upload', 'status': 'VALIDATION_FAILED',
                        'sha256': hashlib.sha256(data).hexdigest(), 'summary': (prepared or {}).get('summary'),
                        'invalid_records': (prepared or {}).get('invalid'), 'verdict': 'VALIDATION_FAILED', 'error': message, 'total_events': 0})

    def start_generated(self, params):
        profile = params.get('profile')
        if profile not in PROFILES:
            raise JobError(f"Profile must be one of: {', '.join(PROFILES)}")
        try:
            count = int(params.get('count') or 500)
            duration = int(params.get('duration_seconds') or 3600)
            seed = random.randrange(1, 1000000) if params.get('seed') in (None, '') else int(params['seed'])
        except (TypeError, ValueError):
            raise JobError('Count, duration and seed must be whole numbers')

        dataset_id = f'ds-{uuid.uuid4().hex[:12]}'
        try:
            built = generate_dataset(profile, count, duration, seed, dataset_id)
        except ValueError as e:
            raise JobError(str(e))
        self._claim_dataset(dataset_id)
        try:
            insert_ground_truth([(raw['event_id'], dataset_id, label, attack) for raw, _, label, attack in built])
            insert_dataset({'dataset_id': dataset_id, 'name': f"{PROFILES[profile]['name']} (seed {seed})", 'kind': 'generated', 'status': 'PROCESSING',
                            'params': {'profile': profile, 'count': count, 'duration_seconds': duration, 'seed': seed},
                            'summary': summarize_generated(built),
                            'invalid_records': [], 'expected_rules': expected_rules_for(profile), 'total_events': len(built)})
        except Exception:
            self._dataset = None
            raise
        rows = [(raw, source) for raw, source, _, _ in built]
        threading.Thread(target=self._run_dataset, args=(dataset_id, rows, 'simulation', expected_rules_for(profile)), daemon=True).start()
        return {'dataset': get_dataset(dataset_id)}

    def start_feed_test(self, source, indicators, params):
        """Plant a sample of a feed's indicators in synthetic logs, and run them through the whole pipeline"""
        try:
            count = int(params.get('count') or 500)
            contacts = int(params.get('contacts') or 25)
            duration = int(params.get('duration_seconds') or 3600)
            seed = random.randrange(1, 1000000) if params.get('seed') in (None, '') else int(params['seed'])
        except (TypeError, ValueError):
            raise JobError('Count, planted indicators, duration and seed must be whole numbers')
        dataset_id = f'ds-{uuid.uuid4().hex[:12]}'
        try:
            built, expected = generate_feed_test(indicators, count, duration, seed, dataset_id, contacts)
        except ValueError as e:
            raise JobError(str(e))
        self._claim_dataset(dataset_id)
        try:
            insert_ground_truth([(raw['event_id'], dataset_id, label, attack) for raw, _, label, attack in built])
            insert_dataset({'dataset_id': dataset_id, 'name': f'Feed test: {source} (seed {seed})', 'kind': 'generated', 'status': 'PROCESSING',
                            'params': {'feed': source, 'count': count, 'contacts': contacts, 'duration_seconds': duration, 'seed': seed},
                            'summary': summarize_generated(built), 'invalid_records': [], 'expected_rules': expected, 'total_events': len(built)})
        except Exception:
            self._dataset = None
            raise
        rows = [(raw, log_source) for raw, log_source, _, _ in built]
        threading.Thread(target=self._run_dataset, args=(dataset_id, rows, 'simulation', expected), daemon=True).start()
        return {'dataset': get_dataset(dataset_id)}

    def _run_dataset(self, dataset_id, rows, origin, expected_rules):
        started = time.monotonic()
        processed = rejected = 0
        total = len(rows)
        try:
            for start in range(0, total, DATASET_CHUNK):
                report = ingest_records(rows[start:start + DATASET_CHUNK], origin=origin, batch_id=dataset_id)
                processed += report['stored']
                rejected += report['rejected'] + report['duplicates']
                update_dataset(dataset_id, {'processed_events': processed})
                self._emit('dataset_progress', {'dataset_id': dataset_id, 'status': 'PROCESSING', 'processed': processed, 'total': total})
            self._engine().process_new_events()
            metrics = evaluate_batch(dataset_id, expected_rules)
            metrics['processing_seconds'] = round(time.monotonic() - started, 2)
            metrics['rejected_during_normalization'] = rejected
            summary = (get_dataset(dataset_id) or {}).get('summary') or {}
            analysis = analyze_batch(dataset_id, summary)
            update_dataset(dataset_id, {'status': 'COMPLETED', 'metrics': metrics, 'analysis': analysis,
                                        'verdict': analysis['verdict']['status'], 'completed_at': _utc_now()})
            report_id = build_report('dataset', dataset_id)['report_id']
            self._emit('dataset_progress', {'dataset_id': dataset_id, 'status': 'COMPLETED', 'verdict': analysis['verdict']['status'],
                                            'processed': processed, 'total': total, 'report_id': report_id, 'finished': True})
        except Exception as e:
            logger.exception('Dataset %s failed', dataset_id)
            error = f'Processing stopped because of an internal error ({type(e).__name__}). Events stored so far were kept.'
            try:
                summary = (get_dataset(dataset_id) or {}).get('summary') or {}
                update_dataset(dataset_id, {'status': 'FAILED', 'error': error, 'verdict': 'ANALYSIS_INCOMPLETE',
                                            'analysis': analyze_batch(dataset_id, summary, failure=error), 'completed_at': _utc_now()})
                build_report('dataset', dataset_id)
            except Exception:
                logger.exception('Could not record the failure of dataset %s', dataset_id)
            self._emit('dataset_progress', {'dataset_id': dataset_id, 'status': 'FAILED', 'verdict': 'ANALYSIS_INCOMPLETE', 'error': error, 'finished': True})
        finally:
            self._dataset = None
