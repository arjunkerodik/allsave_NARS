"""Email alerts over SMTP when an incident reaches a high risk level.

Off until ALLSAFE_SMTP_HOST and ALLSAFE_ALERT_EMAIL_TO are set. Sending happens on its own thread, so a
slow or broken mail server never delays detection, and every attempt is recorded in email_log.
"""
import datetime
import logging
import os
import queue
import smtplib
import ssl
import threading
from email.message import EmailMessage

from models import count_emails_sent_since, get_alerts_for_incident, get_email_log, get_incident, get_response_actions, save_email_log

logger = logging.getLogger(__name__)

SEND_TIMEOUT_SECONDS = 20
RISK_ORDER = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
DEFAULT_MAX_PER_HOUR = 20
_MAX_DETECTIONS = 5


def _setting(name, default=''):
    return os.environ.get(name, default).strip()


def _one_line(value, limit=200):
    """Logs can hold anything, and a line break in a header would let them add headers"""
    return ' '.join(str(value if value is not None else '').split())[:limit]


class EmailAlerter:
    def __init__(self):
        self._queue = queue.Queue()
        self._thread = None
        self._lock = threading.Lock()

    @staticmethod
    def recipients():
        return [address.strip() for address in _setting('ALLSAFE_ALERT_EMAIL_TO').split(',') if address.strip()]

    def configured(self):
        return bool(_setting('ALLSAFE_SMTP_HOST') and self.recipients())

    @staticmethod
    def minimum_level():
        level = _setting('ALLSAFE_ALERT_EMAIL_MIN_RISK', 'HIGH').upper()
        return level if level in RISK_ORDER else 'HIGH'

    @staticmethod
    def max_per_hour():
        try:
            return max(1, int(_setting('ALLSAFE_ALERT_EMAIL_MAX_PER_HOUR', str(DEFAULT_MAX_PER_HOUR))))
        except ValueError:
            return DEFAULT_MAX_PER_HOUR

    def status(self):
        """No password or address book here: the page only needs to know what will happen"""
        configured = self.configured()
        return {
            'configured': configured,
            'server': f"{_setting('ALLSAFE_SMTP_HOST')}:{self._port()}" if configured else None,
            'recipients': len(self.recipients()),
            'minimum_risk': self.minimum_level(),
            'max_per_hour': self.max_per_hour(),
            'needs': None if configured else 'Set ALLSAFE_SMTP_HOST and ALLSAFE_ALERT_EMAIL_TO in .env, and restart.',
            'recent': get_email_log(10),
        }

    @staticmethod
    def _port():
        return int(_setting('ALLSAFE_SMTP_PORT', '587'))

    # ---------- Deciding and queueing ----------

    def on_notification(self, notification):
        """Called for each new incident notification. Never raises into detection."""
        try:
            level = str(notification.get('level') or '').upper()
            if not self.configured() or level not in RISK_ORDER or RISK_ORDER.index(level) < RISK_ORDER.index(self.minimum_level()):
                return
            self._enqueue(('incident', notification.get('incident_id')))
        except Exception:
            logger.exception('Could not queue an alert email')

    def _enqueue(self, item):
        with self._lock:
            if not self._thread or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._work, daemon=True)
                self._thread.start()
        self._queue.put(item)

    def _work(self):
        while True:
            kind, value = self._queue.get()
            try:
                if kind == 'incident':
                    self.send_incident(value)
            except Exception:
                logger.exception('Alert email worker failed')
            finally:
                self._queue.task_done()

    def drain(self):
        """For tests: wait until everything queued has been handled"""
        self._queue.join()

    # ---------- Building and sending ----------

    def send_incident(self, incident_id):
        incident = get_incident(incident_id)
        if not incident:
            return None
        subject, body = self.compose(incident)
        since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).isoformat()
        if count_emails_sent_since(since) >= self.max_per_hour():
            save_email_log(incident_id, ', '.join(self.recipients()), subject, 'SKIPPED', f'More than {self.max_per_hour()} emails in an hour')
            return False
        return self._send(incident_id, subject, body)

    def send_test(self):
        """Returns (sent, error)"""
        if not self.configured():
            return False, 'Email is not set up yet.'
        sent = self._send(None, 'ALLSAFE test email', 'This is a test from ALLSAFE. Alert emails are working.\n')
        return (True, None) if sent else (False, get_email_log(1)[0]['error'])

    @staticmethod
    def compose(incident):
        alerts = get_alerts_for_incident(incident['id'])
        actions = [action for action in get_response_actions(incident_id=incident['id']) if action['status'] == 'PENDING']
        runs = (incident.get('entities') or {}).get('simulation_run') or []
        runs = runs if isinstance(runs, list) else [runs]
        # Uploaded logs also carry their batch id here, and a log file is not a simulation
        origin = 'log file' if any(str(run).startswith('ds-') for run in runs) else 'simulated' if runs else 'observed'
        tag = {'simulated': '[SIMULATED] ', 'log file': '[LOG ANALYSIS] '}.get(origin, '')
        subject = _one_line(f"{tag}ALLSAFE {incident.get('risk_level')} risk: {incident.get('incident_uid')} {incident.get('title')}")
        base = _setting('ALLSAFE_PUBLIC_URL', f"http://127.0.0.1:{_setting('ALLSAFE_PORT', '5000')}").rstrip('/')
        lines = [
            f"{incident.get('incident_uid')}: {_one_line(incident.get('title'))}", '',
            f"Risk: {incident.get('risk_score')}/100 ({incident.get('risk_level')})", f"Severity: {incident.get('severity')}", f"Confidence: {incident.get('confidence')}%",
            f"Status: {incident.get('status')}", f"Activity: {incident.get('first_seen')} to {incident.get('last_seen')}", '', 'Why it was flagged:',
        ]
        lines += [f"- {alert['rule_id']} {_one_line(alert['rule_name'])}: {_one_line(alert['explanation'], 300)}" for alert in alerts[:_MAX_DETECTIONS]]
        if len(alerts) > _MAX_DETECTIONS:
            lines.append(f'- And {len(alerts) - _MAX_DETECTIONS} more.')
        entities = [(name, values) for name, values in (incident.get('entities') or {}).items() if name != 'simulation_run' and values]
        if entities:
            lines += ['', 'Involved:'] + [f"- {name.replace('_', ' ')}: {_one_line(', '.join(str(v) for v in values[:5]))}" for name, values in entities]
        if actions:
            lines += ['', 'Waiting for an analyst decision:'] + [f"- {_one_line(action['label'])} on {_one_line(action['target'])}" for action in actions[:_MAX_DETECTIONS]]
        lines += ['', f"Investigate: {base}/dashboard#investigations/{incident['id']}", '']
        if origin == 'simulated':
            lines.append('This incident comes from synthetic simulation data, not a real compromise.')
        elif origin == 'log file':
            lines.append('This incident comes from an analyzed log file, not from live monitoring. Nothing was changed on any system.')
        lines.append('A detection is evidence to investigate, not proof of compromise. ALLSAFE has not changed any system.')
        return subject, '\n'.join(lines) + '\n'

    def _send(self, incident_id, subject, body):
        recipients = self.recipients()
        message = EmailMessage()
        sender = _setting('ALLSAFE_ALERT_EMAIL_FROM') or _setting('ALLSAFE_SMTP_USER') or 'allsafe@localhost'
        message['From'] = sender
        message['To'] = ', '.join(recipients)
        message['Subject'] = _one_line(subject, 250)
        message.set_content(body)
        host, port = _setting('ALLSAFE_SMTP_HOST'), self._port()
        security = _setting('ALLSAFE_SMTP_SECURITY', 'ssl' if port == 465 else 'starttls').lower()
        try:
            context = ssl.create_default_context()
            if security == 'ssl':
                server = smtplib.SMTP_SSL(host, port, timeout=SEND_TIMEOUT_SECONDS, context=context)
            else:
                server = smtplib.SMTP(host, port, timeout=SEND_TIMEOUT_SECONDS)
            with server:
                if security == 'starttls':
                    server.starttls(context=context)
                if _setting('ALLSAFE_SMTP_USER') and security != 'none':
                    server.login(_setting('ALLSAFE_SMTP_USER'), os.environ.get('ALLSAFE_SMTP_PASSWORD', ''))
                server.send_message(message)
        except (OSError, smtplib.SMTPException) as error:
            # The server's reply can quote the login, so only the kind of failure is kept
            logger.warning('Alert email failed: %s', type(error).__name__)
            save_email_log(incident_id, ', '.join(recipients), message['Subject'], 'FAILED', f'{type(error).__name__}: the mail server refused or could not be reached')
            return False
        save_email_log(incident_id, ', '.join(recipients), message['Subject'], 'SENT')
        return True
