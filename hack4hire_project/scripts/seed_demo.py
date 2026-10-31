"""
seed_demo.py  -  Judge-ready demo seeder for Hack4Hire 2026
============================================================
Runs ALL attack scenarios through the real SIEM pipeline, seeds synthetic
data, IOC feeds, and creates a clean analyst account so judges can log in
immediately.

Usage:
    cd hack4hire_project
    python scripts/seed_demo.py

After this completes, start the server:
    python app.py
Then open:  http://127.0.0.1:5000
Login:      analyst / Analyst@Hack4Hire2026
"""

import io
import logging
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Force UTF-8 output on Windows
import codecs
sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

# Suppress noise
logging.disable(logging.WARNING)
os.environ['NARS_MODE'] = 'local'

print("=" * 60)
print("  Hack4Hire 2026 -- ALLSAFE SOC Platform")
print("  Demo Data Seeder")
print("=" * 60)
print()

import app as allsafe  # noqa: E402

# Initialize the database
print("[1/6] Initialising database ...", end=" ", flush=True)
allsafe.initialize_storage()
print("OK")

# Set up test client
client = allsafe.app.test_client()
allsafe.app.config['TESTING'] = True


def wait_job(path, timeout=120):
    """Poll a job endpoint until it is no longer active/running."""
    end = time.time() + timeout
    while time.time() < end:
        resp = client.get(path)
        if resp.status_code == 404:
            return {}
        body = resp.get_json() or {}
        status = body.get('status', '')
        active = body.get('active', False)
        if not active and status not in ('RUNNING', 'PAUSED', 'PROCESSING'):
            return body
        time.sleep(0.15)
    raise TimeoutError(f"Timed out waiting for: {path}")


def run_simulation(scenario):
    """Start one simulation and block until it finishes."""
    # Wait for any currently running job to finish first
    for _ in range(60):
        r = client.post('/api/simulations', json={
            'scenario': scenario, 'speed': 'instant', 'seed': 42
        })
        if r.status_code == 202:
            run_id = r.get_json().get('run_id')
            return wait_job(f'/api/simulations/{run_id}')
        elif r.status_code == 409:
            # Another job running, wait
            time.sleep(1)
        else:
            return None
    return None


# Seed IOC threat feeds
print("[2/6] Loading synthetic IOC threat feeds ...", end=" ", flush=True)
try:
    from utils.ioc_engine import load_synthetic_feed
    load_synthetic_feed()
    print("OK")
except Exception as e:
    print("WARN ({})".format(e))


# Run attack scenarios one by one
SCENARIOS_TO_RUN = [
    ('multi_stage',          'Multi-Stage APT Attack (CRITICAL)'),
    ('brute_force',          'Brute Force Login Attack'),
    ('credential_abuse',     'Credential Abuse / Password Spray'),
    ('privilege_escalation', 'Privilege Escalation'),
    ('lateral',              'Lateral Movement'),
    ('exfil',                'Data Exfiltration'),
    ('port_scan',            'Port Scanning / Recon'),
    ('webshell',             'Webshell Deployment'),
    ('beacon',               'C2 Beaconing'),
    ('suspicious_process',   'Suspicious Process Execution'),
    ('cred_dump',            'Credential Dumping'),
]

print("[3/6] Running {} attack scenarios through the SIEM pipeline ...".format(len(SCENARIOS_TO_RUN)))
successes = 0
for scenario, label in SCENARIOS_TO_RUN:
    try:
        result = run_simulation(scenario)
        if result is None:
            print("      SKIP  {}".format(label))
            continue
        alerts = result.get('alert_count', 0)
        incidents = len(result.get('incidents', []))
        print("      OK    {:<42} alerts={:>3}  incidents={:>2}".format(label, alerts, incidents))
        successes += 1
    except Exception as e:
        print("      WARN  {}: {}".format(label, e))

print("      --> {}/{} scenarios completed".format(successes, len(SCENARIOS_TO_RUN)))


# Upload sample CSV datasets
print("[4/6] Uploading synthetic CSV/log datasets ...")
SAMPLES_DIR = os.path.join(ROOT, 'data', 'samples')
DATASETS_TO_LOAD = [
    ('network_flows_cicids.csv',   'Network Flow Dataset (CIC-IDS style)'),
    ('brute_force_windows.csv',    'Windows Brute Force Logs'),
    ('exfiltration.csv',           'Data Exfiltration Log Dataset'),
    ('privilege_escalation.jsonl', 'Privilege Escalation Events (JSONL)'),
    ('suspicious_network.csv',     'Suspicious Network Traffic'),
    ('clean_activity.csv',         'Baseline Normal Activity'),
]
dataset_successes = 0
for filename, label in DATASETS_TO_LOAD:
    filepath = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(filepath):
        print("      SKIP  {} (file not found)".format(label))
        continue
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        r = client.post(
            '/api/datasets/upload',
            data={'file': (io.BytesIO(data), filename), 'profile': 'mixed'},
            content_type='multipart/form-data'
        )
        if r.status_code not in (200, 201, 202):
            print("      SKIP  {}  (HTTP {})".format(label, r.status_code))
            continue
        rj = r.get_json() or {}
        ds_id = rj.get('dataset', {}).get('dataset_id')
        if ds_id:
            wait_job('/api/datasets/{}'.format(ds_id))
        print("      OK    {}".format(label))
        dataset_successes += 1
    except Exception as e:
        print("      WARN  {}: {}".format(label, e))
print("      --> {}/{} datasets uploaded".format(dataset_successes, len(DATASETS_TO_LOAD)))


# Create analyst account
print("[5/6] Creating demo analyst account ...", end=" ", flush=True)
try:
    r = client.post('/api/auth/register', json={
        'username': 'analyst',
        'password': 'Analyst@Hack4Hire2026',
        'role': 'analyst'
    })
    if r.status_code in (200, 201, 409):
        print("OK  (analyst / Analyst@Hack4Hire2026)")
    else:
        print("WARN (HTTP {})".format(r.status_code))
except Exception as e:
    print("WARN ({})".format(e))


# Summary counts
print("[6/6] Fetching summary counts ...", end=" ", flush=True)
try:
    r = client.get('/api/dashboard/counts')
    counts = r.get_json() or {}
    print("OK")
    print()
    print("-" * 60)
    print("  Total Logs Ingested : {}".format(counts.get('logs', '?')))
    print("  Total Alerts        : {}".format(counts.get('alerts', '?')))
    print("  Open Incidents      : {}".format(counts.get('incidents', '?')))
    print("-" * 60)
except Exception as e:
    print("WARN ({})".format(e))

print()
print("Demo data seeding complete!")
print()
print("  Next steps:")
print("  1. Run:    python app.py")
print("  2. Open:   http://127.0.0.1:5000")
print("  3. Login:  analyst / Analyst@Hack4Hire2026")
print()
