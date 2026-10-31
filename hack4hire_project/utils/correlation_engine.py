import json
import time
import logging
import threading
from datetime import datetime, timezone

from models import (
    add_audit_entry, create_incident, get_alert, get_alert_event_ids, get_alerts_for_incident, get_anomalies_for_incident,
    get_detections_for_logs, record_engine_run,
    get_engine_state, get_incident, get_logs_after, get_logs_in_window, get_open_incidents_in_window,
    get_response_actions, get_unassigned_alerts, set_engine_state, update_alert, update_incident,
)
from utils.anomaly_engine import AnomalyEngine
from utils.automation import apply_alert_policy, apply_incident_policy
from utils.detection_engine import SEVERITIES, DetectionEngine, event_summary, persist_finding
from utils.ioc_engine import IocEngine
from utils.nids_engine import NidsEngine, is_flow_event
from utils.normalizer import is_internal_ip
from utils.response_engine import apply_response_policy, sync_recommendations
from utils.risk_engine import apply_overrides, load_scoring_config, score_incident, tactics_in_order
from utils.ueba_engine import UebaEngine

logger = logging.getLogger(__name__)

BATCH_SIZE = 5000
# A file with thousands of unrelated hits should not bury everything else. The result says what was left out.
MAX_ALERTS_PER_RULE = 200
MAX_STREAMED_EVENTS = 100
INDICATOR_FIELDS = ('src_ip', 'dst_ip', 'domain', 'url', 'file_hash')
ENGINE_OF_DETECTION = {'IOA': 'IOA', 'IOC': 'IOC', 'UEBA': 'UEBA', 'ML': 'NIDS'}


def _has_indicator(event):
    return event.get('ts_epoch') is not None and any(event.get(field) for field in INDICATOR_FIELDS)


def _has_event_time(event):
    return event.get('ts_epoch') is not None


def link_score(alert_entities, incident_entities, settings):
    """How strongly an alert relates to an incident, from the entities they share.

    Shared entities combine as 1 - product(1 - weight). Time alone never links anything.
    Returns (score, reasons).
    """
    # Each simulation run is its own world, and synthetic events never join real incidents
    if alert_entities.get('simulation_run') != incident_entities.get('simulation_run'):
        return 0.0, []
    weights = settings['entity_weights']
    ignored = set(settings['ignored_entities'])
    doubt = 1.0
    reasons = []
    for field, weight in weights.items():
        if field in ('pivot', 'asset_mapping'):
            continue
        shared = (set(alert_entities.get(field, [])) & set(incident_entities.get(field, []))) - ignored
        if shared:
            doubt *= 1 - weight
            reasons.append({'type': 'shared_entity', 'field': field, 'values': sorted(shared), 'weight': weight})
    # A host that was a destination earlier and is now acting as a source
    pivots = {ip for ip in set(alert_entities.get('src_ip', [])) & set(incident_entities.get('dst_ip', []))
              if is_internal_ip(ip) and ip not in ignored}
    if pivots:
        doubt *= 1 - weights['pivot']
        reasons.append({'type': 'pivot', 'field': 'src_ip', 'values': sorted(pivots), 'weight': weights['pivot']})
    # Flow data names addresses and host logs name hosts. The asset list says which are the same machine.
    mapped = _mapped_hosts(alert_entities, incident_entities, settings) | _mapped_hosts(incident_entities, alert_entities, settings)
    if mapped:
        doubt *= 1 - weights['asset_mapping']
        reasons.append({'type': 'asset_mapping', 'field': 'hostname', 'values': sorted(mapped), 'weight': weights['asset_mapping']})
    return round(1 - doubt, 3), reasons


def _mapped_hosts(host_side, address_side, settings):
    """Hosts named on one side whose listed address appears as a source on the other side"""
    addresses = set(address_side.get('src_ip', []))
    return {f"{host}={ip}" for host in host_side.get('hostname', [])
            for ip in settings.get('host_addresses', {}).get(host, []) if ip in addresses}


def _merge_entities(alerts):
    merged = {}
    for alert in alerts:
        for field, values in (alert.get('entities') or {}).items():
            target = merged.setdefault(field, [])
            target.extend(value for value in values if value not in target)
    return merged


class CorrelationEngine:
    """The 'Brain' of the SIEM: detects threats in new events and correlates them into incidents.

    Runs on a background thread, and can also be called directly so that an upload or a
    simulation returns its detections. A stored cursor means every event is evaluated once.
    """

    def __init__(self, socketio=None, stats_cb=None):
        self.socketio = socketio
        self.stats_cb = stats_cb
        self.on_notification = None
        self.is_running = False
        self.check_interval = 1
        self.detection = DetectionEngine()
        self.ioc_engine = IocEngine()
        self.ueba = UebaEngine()
        self.anomaly = AnomalyEngine()
        self.nids = NidsEngine()
        self.config = load_scoring_config()
        self.settings = self.config['correlation']
        self._lock = threading.Lock()
        self._alerts_per_rule = {}
        self.health = {'events_processed': 0, 'last_run': None, 'errors': 0, 'last_error': None}

    def use_risk_settings(self, overrides):
        """Apply saved weights and thresholds. Open incidents are scored again so they agree."""
        with self._lock:
            self.config = apply_overrides(load_scoring_config(), overrides)
            self.settings = self.config['correlation']
            rescored = get_open_incidents_in_window(0, float('inf'))
            for incident in rescored:
                self._refresh_incident(incident['id'])
                self._apply_automation(incident['id'])
        return len(rescored)

    def start(self):
        self.is_running = True
        threading.Thread(target=self._run, daemon=True).start()
        logger.info("Correlation Engine started")

    def _run(self):
        while self.is_running:
            try:
                self.process_new_events()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.exception("Correlation Engine Error")
                self._record_error(e)
                time.sleep(10)

    def _record_error(self, error):
        self.health['errors'] += 1
        self.health['last_error'] = type(error).__name__

    def process_new_events(self):
        """Evaluate every stored event not yet processed. Returns what changed."""
        summary = {'events': 0, 'alerts_created': 0, 'alerts_updated': 0, 'incidents_created': [], 'incidents_updated': []}
        with self._lock:
            while True:
                cursor = int(get_engine_state('last_log_id', '0'))
                events = get_logs_after(cursor, BATCH_SIZE)
                if not events:
                    break
                self._process_batch(events, summary)
                # Always advance: a poison event must not stall the pipeline forever
                set_engine_state('last_log_id', events[-1]['id'])
                self.health['events_processed'] += len(events)
                summary['events'] += len(events)
            self.health['last_run'] = datetime.now(timezone.utc).isoformat()
        summary['incidents_updated'] = sorted(set(summary['incidents_updated']) - set(summary['incidents_created']))
        return summary

    def _run_engine(self, name, events, applicable, evaluate, failures=None, detail=None):
        """Run one detection engine, and record for each ingest batch that it really ran, on
        how many events, and whether it failed. A report states this, rather than assuming it."""
        failed = []
        findings = []
        try:
            findings = evaluate()
            failed = list(failures()) if failures else []
        except Exception as e:
            logger.exception('Detection engine %s failed', name)
            self._record_error(e)
            failed = [type(e).__name__]
        batches = {}
        for event in events:
            if event.get('ingest_batch'):
                row = batches.setdefault(event['ingest_batch'], {'seen': 0, 'applicable': 0, 'findings': 0})
                row['seen'] += 1
                row['applicable'] += 1 if applicable(event) else 0
        for finding in findings:
            # Anomaly findings name their batch, and events outside any batch leave it empty
            batch = finding['batch_id'] if 'batch_id' in finding else finding['events'][0].get('ingest_batch')
            if batch in batches:
                batches[batch]['findings'] += 1
        extra = detail() if detail else None
        for batch, row in batches.items():
            record_engine_run(batch, name, row['seen'], row['applicable'], row['findings'], len(failed),
                              {**(extra or {}), **({'failures': failed[:5]} if failed else {})})
        return findings

    def _note_lost_finding(self, batch, detection_type, error):
        """A finding that could not be stored or linked must not leave a clean-looking result"""
        self._record_error(error)
        if batch:
            record_engine_run(batch, ENGINE_OF_DETECTION.get(detection_type, 'IOA'), 0, 0, 0, 1, {'failures': [type(error).__name__]})

    def _process_batch(self, events, summary):
        timed = [e for e in events if e.get('ts_epoch') is not None]
        touched_incidents = set()
        created_incidents = set()
        changed_alerts = []

        context = []
        if timed:
            start = min(e['ts_epoch'] for e in timed) - self.detection.max_window
            end = max(e['ts_epoch'] for e in timed)
            context = get_logs_in_window(start, end)

        findings = self._run_engine('IOA', events, _has_event_time, lambda: self.detection.evaluate(timed, context) if timed else [],
                                    failures=lambda: self.detection.failed_rules if timed else [])
        findings += self._run_engine('IOC', events, _has_indicator, lambda: self.ioc_engine.evaluate(timed) if timed else [])
        findings += self._run_engine('UEBA', events, self.ueba.applicable, lambda: self.ueba.evaluate(timed) if timed else [],
                                     failures=lambda: self.ueba.failed if timed else [])
        findings += self._run_engine('NIDS', events, is_flow_event, lambda: self.nids.evaluate(events),
                                     detail=lambda: self.nids.last_detail)
        # Anomaly findings are signals for scoring and for the analyst. They never become alerts.
        self._run_engine('ANOMALY', events, self.anomaly.applicable, lambda: self.anomaly.evaluate(timed, context) if timed else [],
                         detail=lambda: {'reason': self.anomaly.unavailable_reason()} if self.anomaly.unavailable_reason() else None)

        # Oldest first, so an incident's first alert really is where the activity began
        findings.sort(key=lambda f: (f['first_ts'], -SEVERITIES.index(f['rule']['severity'])))
        findings = self._within_alert_limit(findings)
        alert_origin = {}
        for finding in findings:
            try:
                alert_id, created = persist_finding(finding)
                summary['alerts_created' if created else 'alerts_updated'] += 1
                changed_alerts.append(alert_id)
                alert_origin[alert_id] = (finding['events'][0].get('ingest_batch'), finding['rule'].get('detection_type', 'IOA'))
            except Exception as e:
                logger.exception('Could not store finding for rule %s', finding['rule'].get('id'))
                self._note_lost_finding(finding['events'][0].get('ingest_batch'), finding['rule'].get('detection_type', 'IOA'), e)

        for alert_id in dict.fromkeys(changed_alerts):
            try:
                incident_id, created = self._correlate_alert(alert_id)
            except Exception as e:
                logger.exception('Could not correlate alert %s', alert_id)
                self._note_lost_finding(*alert_origin[alert_id], e)
                continue
            if incident_id:
                touched_incidents.add(incident_id)
                if created:
                    created_incidents.add(incident_id)

        notifications = []
        for incident_id in touched_incidents:
            self._adopt_unassigned_alerts(incident_id)
            self._refresh_incident(incident_id)
            sync_recommendations(incident_id, get_alerts_for_incident(incident_id))
            notification = self._apply_automation(incident_id)
            if notification:
                notifications.append(notification)

        for alert_id in dict.fromkeys(changed_alerts):
            self._score_alert(alert_id)

        self._publish(events, touched_incidents, created_incidents, notifications, bool(changed_alerts))
        summary['incidents_created'].extend(sorted(created_incidents))
        summary['incidents_updated'].extend(sorted(touched_incidents))

    def _within_alert_limit(self, findings):
        """Keep the first alerts of each rule in an uploaded file or run, and record how many more it had"""
        kept, left_out = [], {}
        for finding in findings:
            batch = finding['events'][0].get('ingest_batch')
            rule_id = finding['rule'].get('id')
            count = self._alerts_per_rule.get((batch, rule_id), 0)
            if batch and count >= MAX_ALERTS_PER_RULE:
                left_out.setdefault(batch, {}).setdefault(rule_id, 0)
                left_out[batch][rule_id] += 1
                continue
            if batch:
                self._alerts_per_rule[(batch, rule_id)] = count + 1
            kept.append(finding)
        for batch, rules in left_out.items():
            stored = json.loads(get_engine_state(f'alerts_left_out:{batch}', '{}'))
            for rule_id, count in rules.items():
                stored[rule_id] = stored.get(rule_id, 0) + count
            set_engine_state(f'alerts_left_out:{batch}', json.dumps(stored))
        return kept

    def _apply_automation(self, incident_id):
        """The safe steps for this risk tier. A failure here must not affect detection."""
        try:
            apply_response_policy(incident_id, get_incident(incident_id)['risk_level'])
            return apply_incident_policy(get_incident(incident_id), get_alerts_for_incident(incident_id),
                                         get_response_actions(incident_id=incident_id, limit=1000), self.config)
        except Exception as e:
            logger.exception('Could not apply automation to incident %s', incident_id)
            self._record_error(e)
            return None

    def _score_alert(self, alert_id):
        """Every alert has its own risk. One with no incident still gets its tier's safe handling."""
        try:
            alert = get_alert(alert_id)
            scores = score_incident([alert], self.config)
            update_alert(alert_id, {'risk_score': scores['risk_score'], 'risk_level': scores['risk_level']})
            if not alert['incident_id']:
                apply_alert_policy(alert, scores['risk_level'], self.config)
        except Exception as e:
            logger.exception('Could not score alert %s', alert_id)
            self._record_error(e)

    def _correlate_alert(self, alert_id):
        """Attach an alert to the best related open incident, or open a new one if it warrants it"""
        alert = get_alert(alert_id)
        if alert['incident_id']:
            return alert['incident_id'], False

        window = self.settings['window_seconds']
        candidates = get_open_incidents_in_window(alert['first_seen_ts'] - window, alert['last_seen_ts'] + window)
        best_incident, best_score, best_reasons = None, 0.0, []
        for incident in candidates:
            score, reasons = link_score(alert['entities'] or {}, incident.get('entities') or {}, self.settings)
            if score > best_score:
                best_incident, best_score, best_reasons = incident, score, reasons

        if best_incident and best_score >= self.settings['min_link_score']:
            update_alert(alert_id, {'incident_id': best_incident['id'], 'correlation_score': best_score,
                                    'correlation_reasons': best_reasons})
            # Refresh now so the next alert in this batch can link to this one's entities too
            self._refresh_incident(best_incident['id'])
            return best_incident['id'], False

        minimum = SEVERITIES.index(self.settings['min_severity_to_open_incident'])
        if SEVERITIES.index(alert['severity']) < minimum:
            return None, False

        incident_id = create_incident({
            'title': alert['rule_name'],
            'description': alert['explanation'] or '',
            'severity': alert['severity'],
        })
        update_alert(alert_id, {'incident_id': incident_id, 'correlation_score': 1.0,
                                'correlation_reasons': [{'type': 'first_alert'}]})
        add_audit_entry('system', 'incident_created', 'incident', incident_id, incident_id,
                        {'first_alert': alert['rule_id'], 'severity': alert['severity']})
        self._refresh_incident(incident_id)
        return incident_id, True

    def _adopt_unassigned_alerts(self, incident_id):
        """Weak alerts wait unassigned. Pull them in when a related incident appears."""
        incident = get_incident(incident_id)
        window = self.settings['window_seconds']
        for alert in get_unassigned_alerts(incident['first_seen_ts'] - window, incident['last_seen_ts'] + window):
            score, reasons = link_score(alert['entities'] or {}, incident.get('entities') or {}, self.settings)
            if score >= self.settings['min_link_score']:
                update_alert(alert['id'], {'incident_id': incident_id, 'correlation_score': score,
                                           'correlation_reasons': reasons})

    def _refresh_incident(self, incident_id):
        """Recompute everything derived from an incident's alerts"""
        alerts = get_alerts_for_incident(incident_id)
        if not alerts:
            return
        entities = _merge_entities(alerts)
        first, last = min(alerts, key=lambda a: a['first_seen_ts']), max(alerts, key=lambda a: a['last_seen_ts'])
        anomalies = get_anomalies_for_incident(entities, first['first_seen_ts'], last['last_seen_ts'])
        scores = score_incident(alerts, self.config, anomalies)
        tactics = tactics_in_order(alerts)

        linked = [a['correlation_score'] for a in alerts
                  if a.get('correlation_score') is not None and (a.get('correlation_reasons') or [{}])[0].get('type') != 'first_alert']
        event_ids = set()
        for alert in alerts:
            event_ids.update(get_alert_event_ids(alert['id']))

        mitre, remediation = [], []
        for alert in alerts:
            mitre.extend(t for t in (alert.get('mitre') or []) if t not in mitre)
            remediation.extend(r for r in (alert.get('recommendations') or []) if r not in remediation)

        stages = [{
            'rule_id': a['rule_id'],
            'rule_name': a['rule_name'],
            'tactic': (a.get('mitre') or [{}])[0].get('tactic'),
            'first_seen': a['first_seen'],
            'severity': a['severity'],
        } for a in alerts]

        update_incident(incident_id, {
            'incident_uid': f'INC-{incident_id:06d}',
            'title': self._title(alerts, tactics, entities),
            'description': self._description(alerts, entities),
            'source_ip': self._primary_source(alerts),
            'severity': scores['severity'],
            'confidence': scores['confidence'],
            'risk_score': scores['risk_score'],
            'risk_level': scores['risk_level'],
            'score_breakdown': scores['score_breakdown'],
            'correlation_confidence': round(sum(linked) / len(linked), 3) if linked else None,
            'first_seen': first['first_seen'],
            'first_seen_ts': first['first_seen_ts'],
            'last_seen': last['last_seen'],
            'last_seen_ts': last['last_seen_ts'],
            'alert_count': len(alerts),
            'event_count': len(event_ids),
            'entities': entities,
            'mitre': mitre,
            'stages': stages,
            'remediation': remediation,
        })

    def _title(self, alerts, tactics, entities):
        target = (entities.get('hostname') or entities.get('src_ip') or ['unknown'])[0]
        if len(tactics) >= self.settings['multi_stage_min_tactics']:
            return f'Multi-Stage Attack on {target}: {len(tactics)} tactics, {len(alerts)} detections'
        top = max(alerts, key=lambda a: (SEVERITIES.index(a['severity']), a['confidence']))
        return f"{top['rule_name']} ({target})"

    @staticmethod
    def _description(alerts, entities):
        parts = [a['explanation'] for a in alerts if a.get('explanation')]
        return ' '.join(parts[:6])

    def _primary_source(self, alerts):
        """Source address of the earliest alert: where the activity appears to begin"""
        ignored = set(self.settings['ignored_entities'])
        for alert in alerts:
            for ip in (alert.get('entities') or {}).get('src_ip', []):
                if ip not in ignored:
                    return ip
        return None

    def _publish(self, events, touched, created, notifications=(), alerts_changed=False):
        """Push processed events and incident changes to connected dashboards"""
        if self.on_notification:
            for notification in notifications:
                self.on_notification(notification)
        if not self.socketio:
            return
        try:
            streamed = events[-MAX_STREAMED_EVENTS:]
            detections = get_detections_for_logs(e['id'] for e in streamed)
            for event in streamed:
                log = {k: v for k, v in event.items() if k != 'raw_event'}
                log['detections'] = detections.get(event['id'], [])
                log['summary'] = event_summary(event)
                self.socketio.emit('new_log', log)
            for incident_id in touched:
                name = 'new_incident' if incident_id in created else 'incident_update'
                self.socketio.emit(name, get_incident(incident_id))
            for notification in notifications:
                self.socketio.emit('notification', notification)
            if (touched or alerts_changed) and self.stats_cb:
                self.socketio.emit('stats_update', self.stats_cb())
            # An alert too weak for an incident still changes what open pages should show
            if alerts_changed and not touched:
                self.socketio.emit('alerts_changed', {})
        except Exception as e:
            # Losing a live update must never affect detection or stored data
            logger.exception('Could not publish updates')
            self._record_error(e)
