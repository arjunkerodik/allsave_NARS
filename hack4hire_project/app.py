import os


def load_env_file(path=os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')):
    """Settings and keys kept out of the code. Real environment variables win over this file."""
    if os.environ.get('ALLSAFE_NO_ENV_FILE') == '1' or os.environ.get('ALLSAFE_PUBLIC_DEMO') == '1' or not os.path.exists(path):
        return
    with open(path, encoding='utf-8') as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                name, value = line.split('=', 1)
                os.environ.setdefault(name.strip(), value.strip().strip('"').strip("'"))


# Flask would otherwise load any .env in the current folder itself, even when ALLSAFE_NO_ENV_FILE says not to
os.environ['FLASK_SKIP_DOTENV'] = '1'

# Before the imports below, because several read their settings as they load
if __name__ == '__main__':
    load_env_file()

from flask import Flask, Response, redirect, render_template, request, jsonify, session, url_for
from functools import wraps
from flask_socketio import SocketIO, emit
from urllib.parse import urlsplit
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename
import json
import secrets
import threading
import time
import logging
from datetime import datetime, timedelta
import os
import uuid

from models import (
    init_db, batch_insert_logs, get_recent_logs, get_log_counts, get_total_log_count,
    get_recent_incidents, block_ip, get_blocklist, get_dashboard_counts, get_recent_alerts,
    get_alert, get_all_iocs, get_simulation_outcome, get_recent_simulation_runs,
    get_batch_detection, get_detection_watermark, get_audit_entries, get_response_actions,
    get_incident, set_incident_status, add_audit_entry, INCIDENT_STATES, search_logs, search_alerts,
    search_incidents, get_log, get_log_facets, get_overview, get_rule_activity, get_ioc_match_counts,
    get_detections_for_logs, keep_wal_open, get_log_origin_counts, count_simulation_runs,
    get_engine_state, set_engine_state, get_automation_log, get_notifications, mark_notifications_read,
    get_risk_distribution, mark_interrupted_jobs, update_simulation_run, get_batch_events, get_batch_alerts,
    get_dataset, get_datasets, get_reports, get_latest_report_id, get_alert_event_ids, get_flow, username_taken, get_user, insert_dataset, update_dataset,
)
from utils.normalizer import clean_ip, normalize_log
from utils.log_ingest import MAX_UPLOAD_BYTES, UploadRejected, ingest_records, ingest_upload
from utils.ioc_engine import import_iocs, load_synthetic_feed
from utils.investigation import build_incident_report, get_incident_detail
from utils.detection_engine import event_summary
from utils import real_response
from utils.response_engine import apply_policy_to_open_incidents, ResponseError, decide_action, describe_actions, execute_action, clean_analyst, undo_action
from collectors.app_logger import ApplicationLogger
from collectors.network_collector import NetworkCollector
from collectors.endpoint_collector import EndpointCollector
from utils.simulator import AttackSimulator, SCENARIOS
from utils.automation import STEPS as AUTOMATION_STEPS
from utils.dataset_analysis import analyze_batch, is_confirmed, _confirmed_threshold
from utils.dataset_engine import BLOCKED_EXTENSIONS, parse_mapping, prepare_dataset
from utils.log_formats import UnpackRefused, unpack_upload
from utils.dataset_generator import PROFILES as DATASET_PROFILES
from utils.evaluation import evaluate_batch
from utils.job_runner import INTENSITIES, SPEEDS, JobError, JobRunner
from utils.report_engine import ReportError, build_report, load_report, render_csv, render_markdown, render_pdf
from utils.response_engine import PLAYBOOK
from utils.risk_engine import validate_settings
from utils.correlation_engine import CorrelationEngine
from utils.attack_views import build_attack_graph, build_attack_matrix, build_flow
from utils.email_alerts import EmailAlerter
from utils.impact import build_impact
from utils.nids_engine import load_ml_rules
from utils.solutions import build_solutions
from utils.threat_parameters import explain_log, threat_parameters
from utils.auth import auth_enabled, create_account, current_user, log_in
from utils.ioc_feed import get_feed_analysis, import_feed, indicators_of, list_feeds, parse_feed, preview as preview_feed, remove_feed
from utils.nars import Nars

app = Flask(__name__)
# Without a configured key, sessions simply do not survive a restart. Nothing secret ships in source.
app.config['SECRET_KEY'] = os.environ.get('ALLSAFE_SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES + 1024 * 1024
# Scripts are always read from disk. A remembered page next to a newer script breaks the console.
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('ALLSAFE_HTTPS') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
socketio = SocketIO(app, async_mode='threading')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize collectors
app_logger = ApplicationLogger()
network_collector = NetworkCollector()
endpoint_collector = EndpointCollector()
simulator = AttackSimulator()

def fetch_stats():
    """Logic to get statistics dictionary"""
    counts = get_dashboard_counts()
    return {
        'total': get_total_log_count(),
        'by_source': get_log_counts(),
        'by_origin': get_log_origin_counts(),
        'incidents': counts['incidents_open'],
        'network_metrics': network_collector.throughput,
        'network_capture': network_collector.capture_status,
        **counts,
    }

correlation_engine = CorrelationEngine(socketio, fetch_stats)
job_runner = JobRunner(lambda: correlation_engine, socketio)
nars = Nars(lambda: correlation_engine)
DEMO_ACCOUNT = 'analyst'
email_alerter = EmailAlerter()
correlation_engine.on_notification = email_alerter.on_notification

def api_error(message, status=400, **extra):
    extra = {key: value for key, value in extra.items() if value is not None}
    return jsonify({'error': message, **extra}), status

def bounded_limit(default, maximum=1000):
    """Read ?limit= and keep it in range. SQLite treats a negative LIMIT as no limit at all."""
    limit = request.args.get('limit', default, type=int)
    return max(1, min(limit, maximum))

def detection_report(batch_id, watermark):
    """Finish detection, then report what this batch led to from the stored results"""
    correlation_engine.process_new_events()
    return get_batch_detection(batch_id, watermark)

def public_demo():
    """Reachable from the internet: synthetic data only, with no keys, no mail and nothing from this machine"""
    return os.environ.get('ALLSAFE_PUBLIC_DEMO') == '1'

def on_this_machine():
    """A tunnel or proxy also connects from this machine, and names who it is forwarding for in these headers"""
    forwarded = any(request.headers.get(name) for name in ('X-Forwarded-For', 'Forwarded', 'X-Real-IP'))
    return request.remote_addr in ('127.0.0.1', '::1') and not forwarded and not public_demo()

def is_local_request():
    """Without accounts, analyst decisions are limited to this machine. With them, the login and
    role check has already run for this request."""
    return auth_enabled() or on_this_machine()

def analyst_body():
    """The JSON body. With accounts, the analyst is the logged-in user, whatever the body says."""
    data = request.get_json(silent=True) or {}
    user = current_user() if auth_enabled() else None
    if user and isinstance(data, dict):
        data['analyst'] = user['username']
    return data

def job_errors(view):
    """Refusals from the job and report layers become plain JSON errors"""
    @wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except JobError as e:
            return api_error(e.message, e.status, validation=e.validation,
                             analysis_status='VALIDATION_FAILED' if e.validation_failed else None)
        except (UploadRejected, ReportError) as e:
            return api_error(str(e))
    return wrapper

@app.before_request
def reject_cross_origin_writes():
    """A web page on another site must not be able to trigger writes on this dashboard"""
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        origin = request.headers.get('Origin')
        if origin and urlsplit(origin).netloc != request.host:
            return api_error('Cross-origin request refused', 403)

# Open to anyone with an account, including read-only viewers, because they change no security data
VIEWER_WRITES = ('/api/auth/logout', '/api/nars/ask')

@app.before_request
def require_login():
    """Applies only once an account exists. Viewers can read everything and change nothing."""
    if request.endpoint in ('login_page', 'login', 'register', 'demo_login', 'static') or not auth_enabled():
        return None
    user = current_user()
    if not user:
        return api_error('Log in first', 401) if request.path.startswith('/api/') else redirect(url_for('login_page'))
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') and user['role'] != 'analyst' and request.path not in VIEWER_WRITES:
        return api_error('Your account can read but not change anything', 403)
    return None

@app.after_request
def add_security_headers(response):
    """Scripts and styles are all served from here, so a page can be locked down to that"""
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Content-Security-Policy', (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"))
    return response

@app.errorhandler(HTTPException)
def handle_http_error(error):
    """API clients get JSON errors, and nothing about the internals"""
    if request.path.startswith('/api/'):
        return api_error(error.description, error.code)
    return error

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.exception('Unhandled error on %s', request.path)
    return api_error('Internal server error', 500)

@app.route('/')
def landing():
    """The front page. Its numbers and flow come from the same APIs as the dashboard."""
    return render_template('landing.html')

@app.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/login')
def login_page():
    if current_user():
        return redirect(url_for('dashboard'))
    if app.config.get('TESTING') and not auth_enabled():
        return redirect(url_for('landing'))
    return render_template('login.html')

@app.route('/api/auth/register', methods=['POST'])
def register():
    if os.environ.get('ALLSAFE_PUBLIC_DEMO') == '1':
        return api_error('Sign-up is closed on the public demo', 403)
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '').strip()
    password = str(data.get('password') or '')
    role = str(data.get('role') or 'analyst').strip().lower()
    if role not in ('analyst', 'viewer'):
        role = 'analyst'
    # Registering must never replace an account: that would hand it to whoever asked
    if username_taken(username):
        return api_error('That username is already taken.', 409)
    # The first account sets the system up. After that only an analyst can create another analyst,
    # so that signing up cannot grant the right to approve responses.
    if auth_enabled() and (current_user() or {}).get('role') != 'analyst':
        role = 'viewer'
    try:
        created = create_account(username, password, role)
        session.clear()
        session['user'] = created
        session.permanent = True
        add_audit_entry(created, 'user_registered', 'user', None, None,
                        {'role': role, 'client': request.remote_addr})
        return jsonify({'user': {'username': created, 'role': role}})
    except ValueError as e:
        return api_error(str(e), 400)
    except Exception:
        return api_error('Could not create account: username may already exist or is invalid.', 400)

@app.route('/api/auth/demo', methods=['POST'])
def demo_login():
    """One-click sign-in for a demonstration on this machine. The account has a random password, so
    there is no shared credential in the code or on the page."""
    if not on_this_machine():
        return api_error('The demo sign-in only works on this machine', 403)
    if not get_user(DEMO_ACCOUNT):
        create_account(DEMO_ACCOUNT, secrets.token_urlsafe(24), 'analyst')
        add_audit_entry(DEMO_ACCOUNT, 'user_registered', 'user', None, None, {'role': 'analyst', 'client': request.remote_addr, 'demo': True})
    account = get_user(DEMO_ACCOUNT)
    if account['disabled']:
        return api_error('The demo account is disabled', 403)
    session.clear()
    session['user'] = account['username']
    session.permanent = True
    add_audit_entry(account['username'], 'login_succeeded', 'user', None, None, {'client': request.remote_addr, 'demo': True})
    return jsonify({'user': {'username': account['username'], 'role': account['role']}})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    user, error, status = log_in(data.get('username'), data.get('password'), request.remote_addr)
    add_audit_entry(str(data.get('username') or 'unknown')[:64], 'login_succeeded' if user else 'login_failed', 'user', None, None,
                    {'client': request.remote_addr})
    return jsonify({'user': user}) if user else api_error(error, status)

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': 'Logged out'})

@app.route('/api/auth/me')
def who_am_i():
    return jsonify({'auth_enabled': auth_enabled(), 'user': current_user() if auth_enabled() else None})

@app.after_request
def log_app_request(response):
    """Global hook to capture high-fidelity app logs"""
    # A question to the assistant reads data. It is recorded in the audit log instead.
    if request.path.startswith(('/static', '/socket.io', '/api/nars')):
        return response
    # The dashboard polling itself is not security telemetry, and would bury real events
    if request.method == 'GET' and request.path.startswith('/api/') and response.status_code < 400:
        return response
    app_logger.log_request(request, response)
    return response

@app.route('/api/stats')
def get_stats():
    """API endpoint to get statistics"""
    return jsonify(fetch_stats())

@app.route('/api/health')
def get_health():
    """What is actually running. Components that are off say so."""
    return jsonify({
        'status': 'ok',
        'engine': correlation_engine.health,
        'rules_loaded': len(correlation_engine.detection.rules),
        'rule_errors': correlation_engine.detection.load_errors,
        'network_capture': network_collector.capture_status,
        'endpoint_monitoring': endpoint_collector.is_running,
        'ml_model_loaded': correlation_engine.nids.status()['loaded'],
        'ml_model_available': correlation_engine.nids.status()['available'],
        'ml_model_validated': False,
        'anomaly_model_available': correlation_engine.anomaly.status()['available'],
    })

@app.route('/api/ml')
def get_ml_status():
    """The two models in the pipeline, what they accept, and how they were measured"""
    return jsonify({
        'anomaly_model': {**correlation_engine.anomaly.status(), 'evaluation': correlation_engine.anomaly.evaluation()},
        'network_model': correlation_engine.nids.status(),
    })

@app.route('/api/logs')
def get_logs():
    """API endpoint to fetch recent logs"""
    source_filter = request.args.get('source', None)

    logs = search_logs(
        bounded_limit(100), source_filter, request.args.get('event_type'), request.args.get('origin'),
        (request.args.get('q') or '').strip()[:200], request.args.get('detected') == '1',
        request.args.get('exclude_system') == '1', request.args.get('before_id', type=int))
    detections = get_detections_for_logs(log['id'] for log in logs)
    for log in logs:
        log['summary'] = event_summary(log)
        log['detections'] = detections.get(log['id'], [])
        log.pop('raw_event', None)
    return jsonify(logs)

@app.route('/api/logs/facets')
def get_logs_facets():
    """Filter options, taken from the stored data"""
    return jsonify(get_log_facets())

@app.route('/api/logs/<int:log_id>/verdict')
def get_log_verdict(log_id):
    """Why this log is or is not a threat, with each rule's parameters measured for it"""
    log = get_log(log_id)
    if not log:
        return api_error('Event not found', 404)
    return jsonify(explain_log(log, correlation_engine.detection.rules))

@app.route('/api/solutions')
def get_solutions():
    """The Solution Portal: every threat, how to fix it, and who decides"""
    activity = get_rule_activity()
    rules = [{**rule, **activity.get(rule['id'], {})} for rule in correlation_engine.detection.rules]
    _, behavioral = rules_with_activity()
    return jsonify(build_solutions(rules, behavioral, load_ml_rules(), simulator.list_scenarios(), PLAYBOOK))

@app.route('/api/threat-parameters')
def get_threat_parameters():
    """Everything that decides whether logs count as a threat"""
    activity = get_rule_activity()
    rules = [{**rule, **activity.get(rule['id'], {})} for rule in correlation_engine.detection.rules]
    _, behavioral = rules_with_activity()
    return jsonify(threat_parameters(rules, behavioral, load_ml_rules(), correlation_engine.anomaly.status(), correlation_engine.nids.status(), correlation_engine.config['risk']))

@app.route('/api/flow')
def get_flow_route():
    """How stored logs moved through detection: ?minutes=15, 60, 360, 1440 or 0, and optional origin"""
    minutes = request.args.get('minutes', 60, type=int)
    if minutes not in (0, 15, 60, 360, 1440):
        return api_error('minutes must be 0, 15, 60, 360 or 1440')
    minimum = _confirmed_threshold()
    return jsonify({**build_flow(get_flow(minutes, request.args.get('origin') or None, minimum), minimum), 'minutes': minutes})

@app.route('/api/email/status')
def get_email_status():
    return jsonify(email_alerter.status())

def _update_env_file(key_values):
    """Safely updates or appends environment variables in .env"""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    existing_lines = []
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                existing_lines = f.readlines()
        except OSError:
            existing_lines = []
    updated_keys = set()
    new_lines = []
    for line in existing_lines:
        trimmed = line.strip()
        if trimmed and not trimmed.startswith('#') and '=' in trimmed:
            k = trimmed.split('=', 1)[0].strip()
            if k in key_values:
                new_lines.append(f"{k}={key_values[k]}\n")
                updated_keys.add(k)
                continue
        new_lines.append(line)
    for k, v in key_values.items():
        if k not in updated_keys and v:
            new_lines.append(f"{k}={v}\n")
    try:
        with open(env_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)
    except OSError:
        pass

@app.route('/api/email/config', methods=['GET', 'POST'])
def email_config():
    if public_demo():
        return api_error('Mail settings are not available on the public demo', 403)
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    if request.method == 'GET':
        return jsonify({
            'configured': email_alerter.configured(),
            'host': os.environ.get('ALLSAFE_SMTP_HOST', ''),
            'port': int(os.environ.get('ALLSAFE_SMTP_PORT', '587')),
            'security': os.environ.get('ALLSAFE_SMTP_SECURITY', 'starttls'),
            'user': os.environ.get('ALLSAFE_SMTP_USER', ''),
            'has_password': bool(os.environ.get('ALLSAFE_SMTP_PASSWORD')),
            'from_email': os.environ.get('ALLSAFE_ALERT_EMAIL_FROM', ''),
            'to_email': os.environ.get('ALLSAFE_ALERT_EMAIL_TO', ''),
            'min_risk': email_alerter.minimum_level(),
            'max_per_hour': email_alerter.max_per_hour(),
            'server': email_alerter.status().get('server'),
            'needs': email_alerter.status().get('needs'),
        })
    try:
        analyst = clean_analyst(analyst_body().get('analyst'))
    except ResponseError:
        user = current_user() if auth_enabled() else None
        analyst = user['username'] if user else 'analyst'

    data = request.get_json(silent=True) or {}
    host = str(data.get('host') or '').strip()
    port = str(data.get('port') or '587').strip()
    security = str(data.get('security') or 'starttls').strip().lower()
    user_str = str(data.get('user') or '').strip()
    password = str(data.get('password') or '').strip()
    from_email = str(data.get('from_email') or '').strip()
    to_email = str(data.get('to_email') or '').strip()
    min_risk = str(data.get('min_risk') or 'HIGH').strip().upper()
    max_per_hour = str(data.get('max_per_hour') or '20').strip()

    os.environ['ALLSAFE_SMTP_HOST'] = host
    os.environ['ALLSAFE_SMTP_PORT'] = port
    os.environ['ALLSAFE_SMTP_SECURITY'] = security
    os.environ['ALLSAFE_SMTP_USER'] = user_str
    if password:
        os.environ['ALLSAFE_SMTP_PASSWORD'] = password
    os.environ['ALLSAFE_ALERT_EMAIL_FROM'] = from_email
    os.environ['ALLSAFE_ALERT_EMAIL_TO'] = to_email
    os.environ['ALLSAFE_ALERT_EMAIL_MIN_RISK'] = min_risk
    os.environ['ALLSAFE_ALERT_EMAIL_MAX_PER_HOUR'] = max_per_hour

    env_dict = {
        'ALLSAFE_SMTP_HOST': host,
        'ALLSAFE_SMTP_PORT': port,
        'ALLSAFE_SMTP_SECURITY': security,
        'ALLSAFE_SMTP_USER': user_str,
        'ALLSAFE_ALERT_EMAIL_FROM': from_email,
        'ALLSAFE_ALERT_EMAIL_TO': to_email,
        'ALLSAFE_ALERT_EMAIL_MIN_RISK': min_risk,
        'ALLSAFE_ALERT_EMAIL_MAX_PER_HOUR': max_per_hour,
    }
    if password:
        env_dict['ALLSAFE_SMTP_PASSWORD'] = password
    _update_env_file(env_dict)

    add_audit_entry(analyst, 'smtp_config_updated', 'email', None, None,
                    {'host': host, 'port': port, 'security': security, 'to': to_email})
    return jsonify({'success': True, 'status': email_alerter.status()})

@app.route('/api/email/test', methods=['POST'])
def send_test_email():
    if public_demo():
        return api_error('Mail settings are not available on the public demo', 403)
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    try:
        analyst = clean_analyst(analyst_body().get('analyst'))
    except ResponseError as e:
        return api_error(e.message, e.status)
    sent, error = email_alerter.send_test()
    add_audit_entry(analyst, 'email_test', 'email', None, None, {'sent': sent})
    return jsonify({'sent': True}) if sent else api_error(error, 502 if email_alerter.configured() else 400)

@app.route('/api/logs/<int:log_id>')
def get_log_route(log_id):
    """One event in full, including the original raw record"""
    log = get_log(log_id)
    if not log:
        return api_error('Event not found', 404)
    log['summary'] = event_summary(log)
    log['detections'] = get_detections_for_logs([log_id]).get(log_id, [])
    for field in ('raw_event', 'normalized_fields'):
        try:
            log[field] = json.loads(log[field]) if log.get(field) else None
        except ValueError:
            pass
    return jsonify(log)

@app.route('/api/overview')
def get_overview_route():
    """Chart data for a time range: ?minutes=15, 60, 360, 1440, or 0 for everything"""
    minutes = request.args.get('minutes', 60, type=int)
    if minutes not in (0, 15, 60, 360, 1440):
        return api_error('minutes must be 0, 15, 60, 360 or 1440')
    return jsonify({**get_overview(minutes), 'latest_log': latest_log_analysis()})

def latest_log_analysis():
    """The newest log analysis, so that its result is on the first page anyone opens"""
    latest = next(iter(get_datasets(1)), None)
    if not latest:
        return None
    metrics, analysis = latest.get('metrics') or {}, latest.get('analysis') or {}
    return {'dataset_id': latest['dataset_id'], 'name': latest['name'], 'kind': latest['kind'], 'status': latest['status'], 'verdict': latest['verdict'] or latest['status'],
            'created_at': latest['created_at'], 'events': latest['total_events'], 'alerts': metrics.get('alerts'), 'incidents': metrics.get('incidents'), 'error': latest.get('error'),
            'indicators': analysis.get('usable') if latest['kind'] == 'feed' else None, 'statement': (analysis.get('verdict') or {}).get('statement')}

def with_data_origin(incidents):
    """Say where each incident's data came from: a log file, a simulation or live monitoring"""
    names = {dataset['dataset_id']: dataset['name'] for dataset in get_datasets(500)}
    for incident in incidents:
        run = ((incident.get('entities') or {}).get('simulation_run') or [None])[0]
        incident['data_origin'] = 'live' if not run else 'logs' if str(run).startswith('ds-') else 'simulation'
        incident['data_name'] = names.get(run)
    return incidents

@app.route('/api/incidents')
def get_incidents():
    """Fetch recent security incidents"""
    return jsonify(with_data_origin(search_incidents(bounded_limit(20), request.args.get('status'), request.args.get('severity'),
                                                     (request.args.get('q') or '').strip()[:200], request.args.get('sort'),
                                                     request.args.get('risk'), request.args.get('data'))))

@app.route('/api/incidents/<int:incident_id>')
def get_incident_route(incident_id):
    """Full investigation view: scores with reasons, alerts, evidence and timeline"""
    detail = get_incident_detail(incident_id)
    if not detail:
        return api_error('Incident not found', 404)
    detail['attack_graph'] = build_attack_graph(detail)
    return jsonify(detail)

@app.route('/api/incidents/<int:incident_id>/report')
def get_incident_report(incident_id):
    """The investigation as a Markdown file an analyst can keep or hand over"""
    detail = get_incident_detail(incident_id)
    if not detail:
        return api_error('Incident not found', 404)
    name = detail['incident'].get('incident_uid') or f'incident-{incident_id}'
    text = build_incident_report(detail)
    if request.args.get('format') == 'pdf':
        return Response(render_pdf(text), mimetype='application/pdf',
                        headers={'Content-Disposition': f'attachment; filename="{name}-report.pdf"'})
    return Response(text, mimetype='text/markdown',
                    headers={'Content-Disposition': f'attachment; filename="{name}-report.md"'})

@app.route('/api/alerts')
def get_alerts():
    """Fetch detections, optionally filtered by severity or rule"""
    return jsonify(search_alerts(bounded_limit(100), request.args.get('severity'), request.args.get('rule_id'),
                                 request.args.get('detection_type'), (request.args.get('q') or '').strip()[:200]))

@app.route('/api/alerts/<int:alert_id>')
def get_alert_route(alert_id):
    alert = get_alert(alert_id)
    if not alert:
        return api_error('Alert not found', 404)
    log_ids = get_alert_event_ids(alert_id)
    alert['supporting_event_count'] = len(log_ids)
    alert['supporting_log_ids'] = log_ids[:200]
    return jsonify(alert)

def rules_with_activity():
    activity = get_rule_activity()
    rules = correlation_engine.detection.describe_rules()
    for rule in rules:
        rule.update(activity.get(rule['id'], {'alerts': 0, 'last_fired': None}))
    behavioral = []
    for rule in correlation_engine.ueba.rules.values():
        behavioral.append({**rule, **activity.get(rule['id'], {'alerts': 0, 'last_fired': None})})
    return rules, behavioral

@app.route('/api/rules')
def get_rules():
    """The detection rules in force"""
    rules, behavioral = rules_with_activity()
    return jsonify({'rules': rules, 'behavioral_rules': behavioral, 'errors': correlation_engine.detection.load_errors})

@app.route('/api/attack-matrix')
def get_attack_matrix():
    """The rules in force on the ATT&CK tactics, with what has fired and which scenario tests each"""
    rules, behavioral = rules_with_activity()
    return jsonify(build_attack_matrix(rules + behavioral, simulator.list_scenarios()))

# ---------- NARS, the analyst assistant ----------

@app.route('/api/nars/status')
def get_nars_status():
    return jsonify(nars.status())

@app.route('/api/nars/ask', methods=['POST'])
def ask_nars():
    """Answer one question from stored data. This reads only, and the question goes in the audit log."""
    if not is_local_request():
        return api_error('The assistant only answers requests from this machine', 403)
    data = analyst_body()
    if not isinstance(data, dict):
        return api_error('Expected a JSON object with a question')
    try:
        return jsonify(nars.ask(data.get('question'), data.get('context'), data.get('history'), str(data.get('analyst') or '').strip()[:64] or None))
    except ValueError as e:
        return api_error(str(e))

@app.route('/api/iocs/feeds')
def get_ioc_feeds():
    return jsonify(list_feeds())

@app.route('/api/iocs/feeds/<path:source>/analysis')
def get_ioc_feed_analysis(source):
    analysis = get_feed_analysis(source)
    return jsonify(analysis) if analysis else api_error('No analysis is stored for this feed. Upload it again to create one.', 404)

@app.route('/api/iocs/feeds/<path:source>/test', methods=['POST'])
@job_errors
def test_ioc_feed(source):
    """Plant a sample of this feed's indicators in synthetic logs, and analyze them like any dataset"""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    indicators = indicators_of(source)
    if not indicators:
        return api_error('This feed has no indicators loaded', 404)
    return jsonify(job_runner.start_feed_test(source, indicators, request.get_json(silent=True) or {})), 202

@app.route('/api/iocs/feeds/<path:source>', methods=['DELETE'])
def delete_ioc_feed(source):
    """Remove one imported feed's indicators. Alerts they already produced stay on record."""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    try:
        analyst = clean_analyst(analyst_body().get('analyst'))
        removed = remove_feed(source)
    except ResponseError as e:
        return api_error(e.message, e.status)
    except ValueError as e:
        return api_error(str(e))
    add_audit_entry(analyst, 'ioc_feed_removed', 'feed', None, None, {'source': source, 'indicators': removed})
    return jsonify({'source': source, 'removed': removed})

@app.route('/api/iocs', methods=['GET'])
def get_iocs():
    matches = get_ioc_match_counts()
    indicators = get_all_iocs(bounded_limit(500, 10000))
    for indicator in indicators:
        indicator['alerts'] = matches.get(indicator['value'], 0)
    return jsonify(indicators)

@app.route('/api/iocs', methods=['POST'])
def add_iocs():
    """Import indicators as a JSON list or {"indicators": [...]}"""
    data = request.get_json(silent=True)
    items = data.get('indicators') if isinstance(data, dict) else data
    if not isinstance(items, list):
        return api_error('Expected a JSON list of indicators, or {"indicators": [...]}')
    try:
        return jsonify(import_iocs(items))
    except ValueError as e:
        return api_error(str(e))

@app.route('/api/ingest/upload', methods=['POST'])
def upload_logs():
    """Validate and ingest an uploaded log file, then report what was stored and detected"""
    upload = request.files.get('file')
    if not upload or not upload.filename:
        return api_error('No file provided')
    filename = secure_filename(upload.filename)
    source = request.form.get('source') or None
    batch_id = f'upload-{uuid.uuid4().hex[:12]}'
    watermark = get_detection_watermark()
    try:
        report = ingest_upload(filename, upload.read(), default_source=source, batch_id=batch_id)
    except UploadRejected as e:
        return api_error(str(e))
    report['detection'] = detection_report(batch_id, watermark)
    return jsonify(report)

@app.route('/api/ingest/events', methods=['POST'])
def ingest_events():
    """Ingest structured events as a JSON list or {"events": [...]}"""
    data = request.get_json(silent=True)
    events = data.get('events') if isinstance(data, dict) else data
    if not isinstance(events, list):
        return api_error('Expected a JSON list of events, or {"events": [...]}')
    batch_id = f'api-{uuid.uuid4().hex[:12]}'
    watermark = get_detection_watermark()
    try:
        report = ingest_records([(event, None) for event in events], origin='api', batch_id=batch_id)
    except UploadRejected as e:
        return api_error(str(e))
    report['detection'] = detection_report(batch_id, watermark)
    return jsonify(report)

@app.route('/api/simulate', methods=['GET'])
def list_simulations():
    """Available scenarios with their expected detections, and recent results"""
    runs = get_recent_simulation_runs(bounded_limit(50, 200))
    return jsonify({
        'scenarios': simulator.list_scenarios(),
        'recent_runs': runs,
        # Results against each scenario's recorded ground truth, not real-world detection rates
        'validation': {
            'runs': len(runs),
            'total_runs': count_simulation_runs(),
            'expected_detections': sum(len(run['expected_rules']) for run in runs),
            'missed_detections': sum(len(run['missed_rules']) for run in runs),
            'unexpected_detections': sum(len(run['unexpected_rules']) for run in runs),
            'benign_runs': sum(1 for run in runs if not run['is_malicious']),
            'benign_runs_with_alerts': sum(1 for run in runs if not run['is_malicious'] and run['fired_rules']),
        },
    })

@app.route('/api/simulate/<attack_type>', methods=['POST'])
def simulate_attack(attack_type):
    """Run a synthetic scenario through the real pipeline and compare it with its ground truth"""
    if attack_type not in SCENARIOS:
        return api_error('Invalid attack type')
    watermark = get_detection_watermark()
    run = simulator.run_scenario(attack_type)
    detection = detection_report(run['run_id'], watermark)
    return jsonify({
        'status': 'Synthetic events processed by the detection pipeline',
        'name': run['name'],
        'outcome': get_simulation_outcome(run['run_id']),
        'detection': detection,
    })

# ---------- Controlled simulation runs ----------

def simulation_view(run_id):
    outcome = get_simulation_outcome(run_id)
    if not outcome:
        return None
    alerts = get_batch_alerts(run_id)
    risk = {}
    for alert in alerts:
        if alert.get('risk_level'):
            risk[alert['risk_level']] = risk.get(alert['risk_level'], 0) + 1
    incidents = [get_incident(incident_id) for incident_id in outcome['incident_ids']]
    outcome.update(
        name=SCENARIOS.get(outcome['scenario'], {}).get('name', outcome['scenario']),
        active=job_runner.active_simulation() == run_id,
        metrics=evaluate_batch(run_id, outcome['expected_rules']),
        alert_count=len(alerts),
        alert_risk_distribution=risk,
        report_id=get_latest_report_id(run_id),
        incidents=[{key: incident.get(key) for key in ('id', 'incident_uid', 'title', 'severity', 'confidence', 'risk_score', 'risk_level', 'priority', 'status')}
                   for incident in incidents if incident],
    )
    return outcome

@app.route('/api/simulations', methods=['GET'])
def list_simulation_runs():
    return jsonify({
        'active_run': job_runner.active_simulation(),
        'intensities': INTENSITIES,
        'speeds': list(SPEEDS),
        'runs': get_recent_simulation_runs(bounded_limit(20, 200)),
    })

@app.route('/api/simulations', methods=['POST'])
@job_errors
def start_simulation_run():
    """Start a scenario in the background. Refused while another run is in progress."""
    run = job_runner.start_simulation(request.get_json(silent=True) or {})
    return jsonify(simulation_view(run['run_id'])), 202

@app.route('/api/simulations/<run_id>')
def get_simulation_run(run_id):
    view = simulation_view(run_id)
    return jsonify(view) if view else api_error('Simulation run not found', 404)

@app.route('/api/simulations/<run_id>/<action>', methods=['POST'])
@job_errors
def control_simulation_run(run_id, action):
    controls = {'stop': job_runner.stop_simulation, 'pause': job_runner.pause_simulation, 'resume': job_runner.resume_simulation}
    if action not in controls:
        return api_error('Unknown control', 404)
    return jsonify(controls[action](run_id))

@app.route('/api/simulations/<run_id>/events')
def get_simulation_events(run_id):
    if not get_simulation_outcome(run_id):
        return api_error('Simulation run not found', 404)
    return jsonify(get_batch_events(run_id, bounded_limit(100, 1000), max(0, request.args.get('offset', 0, type=int))))

@app.route('/api/simulations/<run_id>/impact')
def get_simulation_impact(run_id):
    """What the threat did to the simulated environment"""
    if not get_simulation_outcome(run_id):
        return api_error('Simulation run not found', 404)
    return jsonify(build_impact(run_id, correlation_engine.detection.rules))

@app.route('/api/simulations/<run_id>/alerts')
def get_simulation_alerts(run_id):
    if not get_simulation_outcome(run_id):
        return api_error('Simulation run not found', 404)
    return jsonify(get_batch_alerts(run_id))

# ---------- Datasets ----------

DATASET_DETAIL_INCIDENTS = 25
DATASET_DETAIL_TIMELINE = 60

def read_upload(upload):
    """The uploaded file's name and content. A .gz or .zip with one log in it counts as that log."""
    try:
        return unpack_upload(secure_filename(upload.filename) or 'upload.log', upload.read(), MAX_UPLOAD_BYTES, BLOCKED_EXTENSIONS)
    except UnpackRefused as error:
        raise UploadRejected(str(error))

@app.route('/api/datasets', methods=['GET'])
def list_datasets():
    return jsonify({
        'active_dataset': job_runner.active_dataset(),
        'max_upload_mb': MAX_UPLOAD_BYTES // (1024 * 1024),
        'profiles': [{'id': key, 'name': value['name']} for key, value in DATASET_PROFILES.items()],
        'datasets': get_datasets(bounded_limit(50, 200)),
    })

@app.route('/api/datasets/validate', methods=['POST'])
@job_errors
def validate_dataset():
    """Check a file and report what is wrong with it. Nothing is stored."""
    upload = request.files.get('file')
    if not upload or not upload.filename:
        return api_error('No file provided')
    filename, data = read_upload(upload)
    mapping = parse_mapping(request.form.get('mapping'))
    feed = parse_feed(filename, data) if not mapping else None
    if feed:
        return jsonify({'ioc_feed': preview_feed(feed)})
    prepared = prepare_dataset(filename, data, mapping, request.form.get('source') or None)
    return jsonify({'summary': prepared['summary'], 'invalid': prepared['invalid']})

@app.route('/api/datasets/upload', methods=['POST'])
@job_errors
def upload_dataset():
    """Validate a file and process it in the background. The same file is analyzed once unless
    reanalyze=1 is sent."""
    upload = request.files.get('file')
    if not upload or not upload.filename:
        return api_error('No file provided')
    filename, data = read_upload(upload)
    mapping = parse_mapping(request.form.get('mapping'))
    # A threat intelligence feed lists indicators, not events, so it goes to the indicator table
    feed = parse_feed(filename, data) if not mapping else None
    if feed:
        if not is_local_request():
            return api_error('Analyst actions are only accepted from this machine', 403)
        result = import_feed(feed)
        user = current_user() if auth_enabled() else None
        add_audit_entry((user or {}).get('username') or request.form.get('analyst') or 'unknown', 'ioc_feed_imported', 'feed', None, None,
                        {'source': feed['name'], 'added': result['added'], 'updated': result['updated'], 'skipped': feed['skipped'],
                         'matching_events': result['retro_hunt']['matching_events']})
        # On the list with every other file analyzed, so that it can be opened again
        dataset_id = f'ds-{uuid.uuid4().hex[:12]}'
        insert_dataset({'dataset_id': dataset_id, 'name': filename, 'kind': 'feed', 'status': 'COMPLETED', 'verdict': 'FEED_IMPORTED', 'total_events': 0})
        update_dataset(dataset_id, {'analysis': result, 'completed_at': datetime.now().astimezone().isoformat()})
        return jsonify({'ioc_feed': result, 'dataset_id': dataset_id}), 201
    result = job_runner.start_upload(filename, data, mapping, request.form.get('source') or None, request.form.get('reanalyze') == '1')
    return jsonify(result), 200 if result.get('duplicate_of') else 202

@app.route('/api/datasets/generate', methods=['POST'])
@job_errors
def generate_dataset_route():
    return jsonify(job_runner.start_generated(request.get_json(silent=True) or {})), 202

@app.route('/api/datasets/<dataset_id>')
def get_dataset_route(dataset_id):
    dataset = get_dataset(dataset_id)
    if not dataset:
        return api_error('Dataset not found', 404)
    alerts = get_batch_alerts(dataset_id)
    severities, risks = {}, {}
    for alert in alerts:
        severities[alert['severity']] = severities.get(alert['severity'], 0) + 1
        if alert.get('risk_level'):
            risks[alert['risk_level']] = risks.get(alert['risk_level'], 0) + 1
    detections = {}
    for alert in alerts:
        detections[alert['rule_id']] = detections.get(alert['rule_id'], 0) + 1
    incident_ids = sorted({a['incident_id'] for a in alerts if a['incident_id']})
    details = [get_incident_detail(i) for i in incident_ids[:DATASET_DETAIL_INCIDENTS]]
    minimum = _confirmed_threshold()
    dataset.update(
        active=job_runner.active_dataset() == dataset_id,
        severity_distribution=severities,
        alert_risk_distribution=risks,
        detection_distribution=detections,
        report_id=get_latest_report_id(dataset_id),
        alerts=[{**{key: alert.get(key) for key in ('id', 'rule_id', 'rule_name', 'detection_type', 'severity', 'confidence', 'risk_score', 'risk_level',
                                                    'explanation', 'event_count', 'incident_id', 'mitre', 'first_seen', 'last_seen')},
                 'confirmed': is_confirmed(alert, minimum)} for alert in alerts],
        incidents=[{**{key: detail['incident'].get(key) for key in ('id', 'incident_uid', 'title', 'severity', 'confidence', 'risk_score', 'risk_level', 'priority', 'status')},
                    'hosts': (detail['incident'].get('entities') or {}).get('hostname', []),
                    'users': (detail['incident'].get('entities') or {}).get('user', []),
                    'risk_reasons': [c for c in ((detail['incident'].get('score_breakdown') or {}).get('risk') or {}).get('components', []) if c['points']],
                    'timeline': detail['timeline'][:DATASET_DETAIL_TIMELINE],
                    'actions': detail['response_actions']} for detail in details if detail],
    )
    return jsonify(dataset)

@app.route('/api/datasets/<dataset_id>/impact')
def get_dataset_impact(dataset_id):
    if not get_dataset(dataset_id):
        return api_error('Dataset not found', 404)
    return jsonify(build_impact(dataset_id, correlation_engine.detection.rules))

@app.route('/api/datasets/<dataset_id>/events')
def get_dataset_events(dataset_id):
    if not get_dataset(dataset_id):
        return api_error('Dataset not found', 404)
    return jsonify(get_batch_events(dataset_id, bounded_limit(100, 1000), max(0, request.args.get('offset', 0, type=int))))

# ---------- Reports ----------

@app.route('/api/reports', methods=['GET'])
def list_reports():
    return jsonify(get_reports(bounded_limit(100, 500)))

@app.route('/api/reports', methods=['POST'])
@job_errors
def create_report():
    """Generate a new report from what is stored now, including any analyst decisions since the last one"""
    data = request.get_json(silent=True) or {}
    report = build_report(data.get('subject_type'), str(data.get('subject_id')))
    return jsonify({key: report[key] for key in ('report_id', 'subject_type', 'subject_id', 'title', 'generated_at')}), 201

@app.route('/api/reports/<report_id>')
@job_errors
def get_report_route(report_id):
    report = load_report(report_id)
    file_format = request.args.get('format', 'json')
    if file_format == 'json':
        response = jsonify(report)
        if request.args.get('download'):
            response.headers['Content-Disposition'] = f'attachment; filename="{report_id}.json"'
        return response
    renderers = {
        'md': (lambda: render_markdown(report), 'text/markdown'),
        'csv': (lambda: render_csv(report), 'text/csv'),
        'pdf': (lambda: render_pdf(render_markdown(report)), 'application/pdf'),
    }
    if file_format not in renderers:
        return api_error('format must be json, md, csv or pdf')
    render, mimetype = renderers[file_format]
    return Response(render(), mimetype=mimetype, headers={'Content-Disposition': f'attachment; filename="{report_id}.{file_format}"'})

# ---------- Risk management ----------

@app.route('/api/risk')
def get_risk_management():
    """The scoring settings, the response policy and what they are producing now"""
    settings = correlation_engine.config['risk']
    policy = {level: {**spec, 'automatic': [{'step': step, 'title': AUTOMATION_STEPS[step][0]} for step in spec['automatic']]}
              for level, spec in PLAYBOOK['risk_policy'].items()}
    return jsonify({
        'weights': settings['weights'],
        'levels': settings['levels'],
        'policy': policy,
        'incident_distribution': get_risk_distribution(),
        'approval_required_actions': [{'action': key, 'label': value['label'], 'expected_impact': value.get('expected_impact')}
                                      for key, value in PLAYBOOK['actions'].items() if value['disruptive']],
        'recent_automation': get_automation_log(limit=30),
    })

@app.route('/api/risk/settings', methods=['PUT'])
def update_risk_settings():
    """Change weights and thresholds. Saved in the database, and applied to open incidents at once."""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    data = analyst_body()
    try:
        analyst = clean_analyst(data.get('analyst'))
        settings = validate_settings(data)
    except ResponseError as e:
        return api_error(e.message, e.status)
    except ValueError as e:
        return api_error(str(e))
    set_engine_state('risk_overrides', json.dumps(settings))
    rescored = correlation_engine.use_risk_settings(settings)
    add_audit_entry(analyst, 'risk_settings_changed', 'settings', None, None, {**settings, 'incidents_rescored': rescored})
    socketio.emit('stats_update', fetch_stats())
    return jsonify({**settings, 'incidents_rescored': rescored})

@app.route('/api/notifications')
def list_notifications():
    return jsonify(get_notifications(bounded_limit(50, 200), request.args.get('unread') == '1'))

@app.route('/api/notifications/read', methods=['POST'])
def read_notifications():
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    count = mark_notifications_read()
    socketio.emit('stats_update', fetch_stats())
    return jsonify({'marked_read': count})

@app.route('/api/incidents/<int:incident_id>/status', methods=['POST'])
def update_incident_status(incident_id):
    """An analyst moves an incident between ACTIVE, INVESTIGATING and RESOLVED"""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    incident = get_incident(incident_id)
    if not incident:
        return api_error('Incident not found', 404)
    data = analyst_body()
    status = data.get('status')
    if status not in INCIDENT_STATES:
        return api_error(f"status must be one of {', '.join(INCIDENT_STATES)}")
    try:
        analyst = clean_analyst(data.get('analyst'))
    except ResponseError as e:
        return api_error(e.message, e.status)
    set_incident_status(incident_id, status)
    add_audit_entry(analyst, 'incident_status_changed', 'incident', incident_id, incident_id,
                    {'from': incident['status'], 'to': status, 'reason': str(data.get('reason') or '')[:500]})
    updated = get_incident(incident_id)
    socketio.emit('incident_update', updated)
    socketio.emit('stats_update', fetch_stats())
    return jsonify(updated)

@app.route('/api/incidents/<int:incident_id>/response-actions')
def list_incident_responses(incident_id):
    if not get_incident(incident_id):
        return api_error('Incident not found', 404)
    return jsonify(describe_actions(get_response_actions(incident_id=incident_id)))

@app.route('/api/response-actions')
def list_responses():
    """The approval queue. Filter with ?status=PENDING, or AUTOMATED for what automation handled"""
    status = request.args.get('status')
    if status == 'AUTOMATED':
        return jsonify(describe_actions(get_response_actions(status='EXECUTED', executed_by='automation', limit=bounded_limit(200))))
    return jsonify(describe_actions(get_response_actions(status=status, limit=bounded_limit(200))))

@app.route('/api/response-actions/<int:action_id>/decision', methods=['POST'])
def decide_response(action_id):
    """Approve, reject or modify a recommended action"""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    try:
        action = decide_action(action_id, analyst_body())
    except ResponseError as e:
        return api_error(e.message, e.status)
    socketio.emit('response_update', action)
    socketio.emit('stats_update', fetch_stats())
    return jsonify(describe_actions([action])[0])

@app.route('/api/response-actions/<int:action_id>/execute', methods=['POST'])
def execute_response(action_id):
    """Run an approved action, record the result and verify it"""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    try:
        action = execute_action(action_id, analyst_body())
    except ResponseError as e:
        return api_error(e.message, e.status)
    socketio.emit('response_update', action)
    socketio.emit('stats_update', fetch_stats())
    return jsonify(describe_actions([action])[0])

@app.route('/api/response-actions/<int:action_id>/undo', methods=['POST'])
def undo_response(action_id):
    """Remove a real firewall rule that ALLSAFE added"""
    if not is_local_request():
        return api_error('Analyst actions are only accepted from this machine', 403)
    try:
        action = undo_action(action_id, analyst_body())
    except ResponseError as e:
        return api_error(e.message, e.status)
    socketio.emit('response_update', action)
    socketio.emit('stats_update', fetch_stats())
    return jsonify(describe_actions([action])[0])

@app.route('/api/response-mode')
def response_mode():
    return jsonify(real_response.status())

@app.route('/api/audit')
def get_audit():
    return jsonify(get_audit_entries(bounded_limit(200), request.args.get('incident_id', type=int),
                                     request.args.get('actor'), request.args.get('action')))

@app.route('/api/block', methods=['POST'])
def block_ip_route():
    """Record an IP on the blocklist. This changes no firewall."""
    data = request.get_json(silent=True) or {}
    ip = clean_ip(data.get('ip'))
    reason = str(data.get('reason', 'Manual block from dashboard'))[:500]

    if not ip:
        return api_error('A valid IP is required')

    success = block_ip(ip, reason)
    if success:
        return jsonify({'status': f'IP {ip} added to the blocklist'})
    else:
        return api_error('Failed to block IP', 500)

@app.route('/api/blocklist')
def get_blocklist_route():
    """API endpoint to get blocked IPs"""
    return jsonify(get_blocklist())

@app.route('/api/ticket', methods=['POST'])
def raise_ticket_route():
    """API endpoint to simulate raising a ticket"""
    data = request.get_json(silent=True) or {}
    incident_id = data.get('incident_id')
    if not isinstance(incident_id, int):
        return api_error('A numeric incident_id is required')
    logger.info(f"TICKET RAISED: Incident #{incident_id} escalated to Level 2 SOC.")
    return jsonify({'status': 'Ticket raised successfully', 'ticket_id': f'TKT-{int(time.time())}'})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    if auth_enabled() and not current_user():
        return False
    logger.info('Client connected')
    emit('connected', {'data': 'ALLSAFE Monitoring System Online'})
    emit('stats_update', fetch_stats())
    emit('logs_update', get_recent_logs(50))
    emit('incidents_update', get_recent_incidents(10))

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

def emit_stats_update():
    """Emit statistics update to all connected clients"""
    stats = fetch_stats()
    socketio.emit('stats_update', stats)

def start_collectors():
    """Start all log collectors in background threads"""

    # Start the correlation engine
    correlation_engine.start()

    # A public demo must not publish what this machine is doing
    if public_demo():
        logger.info("Public demo: live collectors are off")
        return

    def collect_application_logs():
        """Collect application logs"""
        while True:
            try:
                events = app_logger.collect_events()
                if events:
                    batch_insert_logs([normalize_log(e, 'application') for e in events])
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in application log collection: {e}")
                time.sleep(10)

    def collect_network_logs():
        """Collect network logs"""
        while True:
            try:
                events = network_collector.collect_events()
                if events:
                    batch_insert_logs([normalize_log(e, 'network', origin=e.get('origin', 'live')) for e in events])
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in network log collection: {e}")
                time.sleep(10)

    def collect_endpoint_logs():
        """Collect endpoint logs"""
        while True:
            try:
                events = endpoint_collector.collect_events()
                if events:
                    batch_insert_logs([normalize_log(e, 'endpoint') for e in events])
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in endpoint log collection: {e}")
                time.sleep(10)

    # Start collector threads
    threading.Thread(target=collect_application_logs, daemon=True).start()
    threading.Thread(target=collect_network_logs, daemon=True).start()
    threading.Thread(target=collect_endpoint_logs, daemon=True).start()

    logger.info("All log collectors started")

def periodic_stats_update():
    """Periodically update statistics"""
    with app.app_context():
        while True:
            try:
                emit_stats_update()
                time.sleep(10)
            except Exception as e:
                logger.error(f"Error in periodic stats update: {e}")
                time.sleep(30)

def initialize_storage():
    """Create or migrate the database and load the bundled threat intelligence"""
    init_db()
    load_synthetic_feed()
    interrupted = mark_interrupted_jobs()
    if interrupted:
        logger.warning('%s job(s) were cut off by a restart and are marked INTERRUPTED', interrupted)
    saved = get_engine_state('risk_overrides')
    if saved:
        correlation_engine.use_risk_settings(json.loads(saved))

def use_stored_session_key():
    """Logins survive a restart: without a configured key, one is created once and kept with the data"""
    if os.environ.get('ALLSAFE_SECRET_KEY'):
        return
    stored = get_engine_state('session_secret')
    if not stored:
        stored = secrets.token_hex(32)
        set_engine_state('session_secret', stored)
    app.config['SECRET_KEY'] = stored

if __name__ == '__main__':
    initialize_storage()
    if public_demo() and not auth_enabled():
        raise SystemExit('A public demo needs an account first, or anyone could open it. Add one with scripts/manage_users.py.')
    use_stored_session_key()
    keep_wal_open()

    # Incidents stored before the response policy follow it too
    threading.Thread(target=apply_policy_to_open_incidents, daemon=True).start()

    # Start background threads
    start_collectors()

    # Start periodic stats update
    threading.Thread(target=periodic_stats_update, daemon=True).start()

    # Train and measure the anomaly model now, so that the first request does not wait for it
    threading.Thread(target=correlation_engine.anomaly.evaluation, daemon=True).start()

    # The default is local only with the debugger off. The Werkzeug debugger allows remote code
    # execution, and this dashboard has no login yet, so exposing it is an explicit choice.
    host = os.environ.get('ALLSAFE_HOST', '127.0.0.1')
    port = int(os.environ.get('ALLSAFE_PORT', '5000'))
    debug = os.environ.get('ALLSAFE_DEBUG', '0') == '1'
    socketio.run(app, debug=debug, use_reloader=False, host=host, port=port, allow_unsafe_werkzeug=True)
