import sqlite3
import datetime
import json
import os
import threading
from contextlib import contextmanager

# Absolute by default so the database does not depend on the working directory.
DATABASE_NAME = os.environ.get('ALLSAFE_DB_PATH') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'security_monitoring.db'
)

# Columns added to the original `logs` table. Existing names (source, src_ip,
# dst_ip, method, endpoint, ...) are kept so the dashboard and old rows keep working.
LOG_EXTRA_COLUMNS = {
    'event_id': 'TEXT',
    'ingestion_timestamp': 'TEXT',
    'ts_epoch': 'REAL',
    'event_category': 'TEXT',
    'hostname': 'TEXT',
    'process_id': 'INTEGER',
    'command_line': 'TEXT',
    'file_hash': 'TEXT',
    'domain': 'TEXT',
    'url': 'TEXT',
    'session_id': 'TEXT',
    'auth_result': 'TEXT',
    'bytes_in': 'INTEGER',
    'bytes_out': 'INTEGER',
    'packet_count': 'INTEGER',
    'connection_status': 'TEXT',
    'origin': 'TEXT',
    'ingest_batch': 'TEXT',
    'raw_event': 'TEXT',
    'normalized_fields': 'TEXT',
}

INCIDENT_EXTRA_COLUMNS = {
    'incident_uid': 'TEXT',
    'confidence': 'INTEGER',
    'risk_score': 'INTEGER',
    'risk_level': 'TEXT',
    'score_breakdown': 'TEXT',
    'correlation_confidence': 'REAL',
    'first_seen': 'TEXT',
    'last_seen': 'TEXT',
    'first_seen_ts': 'REAL',
    'last_seen_ts': 'REAL',
    'alert_count': 'INTEGER DEFAULT 0',
    'event_count': 'INTEGER DEFAULT 0',
    'entities': 'TEXT',
    'mitre': 'TEXT',
    'stages': 'TEXT',
    'remediation': 'TEXT',
    'updated_at': 'TEXT',
    'priority': 'TEXT',
    'tags': 'TEXT',
    'automation_status': 'TEXT',
    'response_status': 'TEXT',
    'disruptive_pending': 'INTEGER DEFAULT 0',
}

ALERT_EXTRA_COLUMNS = {
    'risk_score': 'INTEGER',
    'risk_level': 'TEXT',
    'tags': 'TEXT',
    'automation_status': 'TEXT',
}

SIMULATION_EXTRA_COLUMNS = {
    'status': 'TEXT',
    'completed_at': 'TEXT',
    'intensity': 'TEXT',
    'speed': 'TEXT',
    'seed': 'INTEGER',
    'background_events': 'INTEGER DEFAULT 0',
    'processed_count': 'INTEGER DEFAULT 0',
    'failed_count': 'INTEGER DEFAULT 0',
    'error': 'TEXT',
}

# An incident in one of these states still collects related activity. Once closed it stays
# as the analyst left it, and new activity opens a new incident.
OPEN_INCIDENT_STATES = ('ACTIVE', 'INVESTIGATING')
INCIDENT_STATES = OPEN_INCIDENT_STATES + ('RESOLVED',)

LOG_INSERT_COLUMNS = (
    'source', 'event_type', 'timestamp', 'user', 'src_ip', 'dst_ip',
    'src_port', 'dst_port', 'protocol', 'bytes', 'duration', 'flags',
    'process_name', 'ppid', 'parent_process_name', 'file_path', 'registry_key',
    'method', 'endpoint', 'status_code', 'payload_size', 'user_agent', 'geo_location',
    'details',
) + tuple(LOG_EXTRA_COLUMNS)

def _ensure_columns(cursor, table, columns):
    """Additive migration: add any column the table does not have yet"""
    existing = {row[1] for row in cursor.execute(f'PRAGMA table_info({table})').fetchall()}
    for name, col_type in columns.items():
        if name not in existing:
            cursor.execute(f'ALTER TABLE {table} ADD COLUMN {name} {col_type}')

def init_db():
    """Initialize the SQLite database with the logs table"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Enable WAL (Write-Ahead Logging) for higher throughput
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,           -- application, network, endpoint
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            user TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            bytes INTEGER,
            duration REAL,
            flags TEXT,
            process_name TEXT,
            ppid INTEGER,
            parent_process_name TEXT,
            file_path TEXT,
            registry_key TEXT,
            method TEXT,
            endpoint TEXT,
            status_code INTEGER,
            payload_size INTEGER,
            user_agent TEXT,
            geo_location TEXT,
            details TEXT
        )
    ''')

    # Blocklist Table for automated response
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            reason TEXT,
            timestamp DATETIME DEFAULT (datetime('now','localtime'))
        )
    ''')

    # Security Incidents Table (Correlated Events)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp DATETIME DEFAULT (datetime('now','localtime')),
            source_ip TEXT,
            status TEXT DEFAULT 'ACTIVE'
        )
    ''')

    _ensure_columns(cursor, 'logs', LOG_EXTRA_COLUMNS)
    _ensure_columns(cursor, 'incidents', INCIDENT_EXTRA_COLUMNS)

    # Rows written before this migration get a stable identifier
    cursor.execute("UPDATE logs SET event_id = 'legacy-' || id WHERE event_id IS NULL")

    # Detections produced by the rule and IOC engines
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_uid TEXT NOT NULL UNIQUE,
            dedupe_key TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            detection_type TEXT NOT NULL,      -- IOA or IOC
            severity TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            explanation TEXT,
            evidence TEXT,
            mitre TEXT,
            recommendations TEXT,
            entities TEXT,
            observed REAL,
            event_count INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            first_seen_ts REAL,
            last_seen_ts REAL,
            incident_id INTEGER REFERENCES incidents(id),
            correlation_score REAL,
            correlation_reasons TEXT,
            created_at TEXT
        )
    ''')

    # Evidence: which stored events support which alert
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_events (
            alert_id INTEGER NOT NULL REFERENCES alerts(id),
            log_id INTEGER NOT NULL REFERENCES logs(id),
            PRIMARY KEY (alert_id, log_id)
        )
    ''')

    # Local threat intelligence
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT NOT NULL,            -- ip, domain, url, file_hash
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            confidence INTEGER NOT NULL DEFAULT 60,
            description TEXT,
            added_at TEXT,
            UNIQUE (ioc_type, value)
        )
    ''')

    # Ground truth for every simulated scenario run
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS simulation_runs (
            run_id TEXT PRIMARY KEY,
            scenario TEXT NOT NULL,
            is_malicious INTEGER NOT NULL,
            expected_rules TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            started_at TEXT NOT NULL
        )
    ''')

    _ensure_columns(cursor, 'alerts', ALERT_EXTRA_COLUMNS)
    _ensure_columns(cursor, 'simulation_runs', SIMULATION_EXTRA_COLUMNS)

    # What each synthetic or labelled event really is. Kept apart from the logs table, which is
    # all that detection reads, so a label can never become a detection input.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ground_truth (
            event_id TEXT PRIMARY KEY,
            batch_id TEXT NOT NULL,
            label TEXT NOT NULL,
            attack_type TEXT
        )
    ''')

    # Uploaded or generated datasets and their processing jobs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS datasets (
            dataset_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL,
            sha256 TEXT,
            params TEXT,
            summary TEXT,
            invalid_records TEXT,
            metrics TEXT,
            expected_rules TEXT,
            total_events INTEGER DEFAULT 0,
            processed_events INTEGER DEFAULT 0,
            error TEXT,
            created_at TEXT NOT NULL,
            completed_at TEXT
        )
    ''')
    _ensure_columns(cursor, 'datasets', {'verdict': 'TEXT', 'analysis': 'TEXT'})

    # Proof of what each detection engine did for each dataset or run
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS engine_runs (
            batch_id TEXT NOT NULL,
            engine TEXT NOT NULL,
            events_seen INTEGER NOT NULL DEFAULT 0,
            applicable INTEGER NOT NULL DEFAULT 0,
            findings INTEGER NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0,
            detail TEXT,
            last_run TEXT,
            PRIMARY KEY (batch_id, engine)
        )
    ''')

    # What the saved network model said about each flow it was given
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ml_predictions (
            log_id INTEGER PRIMARY KEY,
            batch_id TEXT,
            event_id TEXT,
            predicted_label TEXT NOT NULL,
            model_version TEXT
        )
    ''')

    # Statistically unusual activity windows. Signals for an analyst, not alerts.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT,
            scope TEXT,
            entity TEXT NOT NULL,
            window_start_ts REAL NOT NULL,
            window_end_ts REAL NOT NULL,
            strength INTEGER NOT NULL,
            score REAL NOT NULL,
            event_count INTEGER NOT NULL,
            explanation TEXT,
            features TEXT,
            event_log_ids TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (batch_id, entity, window_start_ts)
        )
    ''')

    # Safe steps the platform took by itself. Each runs once per subject and risk tier.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS automation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            incident_id INTEGER,
            risk_level TEXT NOT NULL,
            step TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (subject, risk_level, step)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            read_at TEXT,
            UNIQUE (incident_id, level)
        )
    ''')

    # Investigation reports, as generated from the stored results at that moment
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            generated_at TEXT NOT NULL
        )
    ''')

    # Recommended responses and the analyst's decision on each. Every action is simulated.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id),
            action_type TEXT NOT NULL,
            label TEXT NOT NULL,
            description TEXT,
            target_type TEXT NOT NULL,
            target TEXT NOT NULL,
            original_target TEXT NOT NULL,
            disruptive INTEGER NOT NULL DEFAULT 0,
            mode TEXT NOT NULL DEFAULT 'simulated',
            status TEXT NOT NULL DEFAULT 'PENDING',
            recommended_by TEXT NOT NULL,
            rationale TEXT,
            decided_by TEXT,
            decision_reason TEXT,
            decided_at TEXT,
            executed_by TEXT,
            executed_at TEXT,
            result TEXT,
            verification TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (incident_id, action_type, original_target)
        )
    ''')

    # What simulated responses would have enforced. Read back to verify an action.
    _ensure_columns(cursor, 'response_actions', {'expected_impact': 'TEXT'})

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS simulated_enforcement (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id INTEGER NOT NULL REFERENCES response_actions(id),
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')

    # Append-only record of who did what
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT,
            entity_id INTEGER,
            incident_id INTEGER,
            details TEXT
        )
    ''')
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    ''')
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END
    ''')

    # Detection cursor, persisted so a restart neither skips nor repeats events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS engine_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # Rows that existed before the first engine run are history, not new telemetry
    cursor.execute('''
        INSERT OR IGNORE INTO engine_state (key, value)
        SELECT 'last_log_id', COALESCE(MAX(id), 0) FROM logs
    ''')

    cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_event_id ON logs(event_id)')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            recipients TEXT,
            subject TEXT,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    # Optional accounts: while this table has no active user, the dashboard stays local only
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_ts_epoch ON logs(ts_epoch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_batch ON logs(ingest_batch)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_user_type ON logs(user, event_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_truth_batch ON ground_truth(batch_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_batch ON ml_predictions(batch_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_batch ON anomaly_findings(batch_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_entity ON anomaly_findings(entity, window_start_ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(dedupe_key, last_seen_ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_events_log ON alert_events(log_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_window ON incidents(status, last_seen_ts)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_response_status ON response_actions(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_incident ON audit_log(incident_id)')

    conn.commit()
    conn.close()

_wal_anchor = None
_thread_state = threading.local()

def _open_connection():
    conn = sqlite3.connect(DATABASE_NAME, timeout=30)
    conn.row_factory = sqlite3.Row
    # This setting is per connection, so setting it once in init_db would not apply here
    conn.execute('PRAGMA synchronous=NORMAL')
    return conn

def _thread_connection():
    conn = getattr(_thread_state, 'conn', None)
    if conn is None:
        conn = _thread_state.conn = _open_connection()
    return conn

@contextmanager
def get_db_connection():
    """Context manager for database connections.

    In the server a thread keeps its connection, because opening and closing one for every query was
    most of the time detection spent on an uploaded log. A nested use gets a connection of its own.
    """
    reuse = _wal_anchor is not None and not getattr(_thread_state, 'in_use', False)
    conn = _thread_connection() if reuse else _open_connection()
    if reuse:
        _thread_state.in_use = True
    try:
        yield conn
    finally:
        if reuse:
            _thread_state.in_use = False
            # Anything not committed is dropped, as closing the connection would do
            if conn.in_transaction:
                conn.rollback()
        else:
            conn.close()

def insert_log(log_data):
    """Insert a single log entry"""
    return batch_insert_logs([log_data])[0]

def batch_insert_logs(logs_list):
    """Insert multiple log entries in a single transaction for performance.

    Returns one row id per input log, or None where the event_id already existed
    (re-uploading a file does not duplicate its events).
    """
    if not logs_list:
        return []

    placeholders = ', '.join('?' for _ in LOG_INSERT_COLUMNS)
    sql = f"INSERT OR IGNORE INTO logs ({', '.join(LOG_INSERT_COLUMNS)}) VALUES ({placeholders})"

    row_ids = []
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for log in logs_list:
            cursor.execute(sql, tuple(log.get(col) for col in LOG_INSERT_COLUMNS))
            row_ids.append(cursor.lastrowid if cursor.rowcount else None)
        conn.commit()
    return row_ids

def get_recent_logs(limit=100, source_filter=None):
    """Get recent logs from the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if source_filter:
            cursor.execute('''
                SELECT * FROM logs
                WHERE source = ?
                ORDER BY id DESC
                LIMIT ?
            ''', (source_filter, limit))
        else:
            cursor.execute('''
                SELECT * FROM logs
                ORDER BY id DESC
                LIMIT ?
            ''', (limit,))
        return [_public_log(row) for row in cursor.fetchall()]

def _public_log(row):
    """Log row for list views: the raw payload is only returned by the evidence APIs"""
    log = dict(row)
    log.pop('raw_event', None)
    return log

def get_log_counts():
    """Get log counts by source"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT source, COUNT(*) as count
            FROM logs
            GROUP BY source
        ''')
        return {row['source']: row['count'] for row in cursor.fetchall()}

def get_log_origin_counts():
    """Log counts by where they came from: live collectors, simulation or upload"""
    with get_db_connection() as conn:
        rows = conn.execute("SELECT COALESCE(origin, 'legacy') AS origin, COUNT(*) AS count FROM logs GROUP BY 1").fetchall()
    return {row['origin']: row['count'] for row in rows}

def get_total_log_count():
    """Get total number of logs"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as total FROM logs')
        row = cursor.fetchone()
        return row['total'] if row else 0

def insert_incident(incident_data):
    """Insert a correlated incident into the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (title, description, severity, source_ip)
            VALUES (?, ?, ?, ?)
        ''', (
            incident_data.get('title'),
            incident_data.get('description'),
            incident_data.get('severity', 'LOW'),
            incident_data.get('source_ip')
        ))
        conn.commit()
        return cursor.lastrowid

def get_recent_incidents(limit=20):
    """Fetch the most recent security incidents"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT ?', (limit,))
        return [_incident_from_row(row) for row in cursor.fetchall()]

def resolve_incident(incident_id):
    """Mark an incident as resolved"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE incidents SET status = 'RESOLVED' WHERE id = ?", (incident_id,))
        conn.commit()
        return True

def block_ip(ip, reason=""):
    """Add an IP to the blocklist"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO blocklist (ip, reason) VALUES (?, ?)', (ip, reason))
            conn.commit()
            return True
    except Exception as e:
        print(f"Error blocking IP: {e}")
        return False

def is_ip_blocked(ip):
    """Check if an IP is in the blocklist"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM blocklist WHERE ip = ?', (ip,))
        return cursor.fetchone() is not None

def get_blocklist():
    """Get all blocked IPs"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM blocklist ORDER BY timestamp DESC')
        return [dict(row) for row in cursor.fetchall()]

# ---------------------------------------------------------------------------
# Detection pipeline storage
# ---------------------------------------------------------------------------

ALERT_JSON_FIELDS = ('evidence', 'mitre', 'recommendations', 'entities', 'correlation_reasons', 'tags')
INCIDENT_JSON_FIELDS = ('score_breakdown', 'entities', 'mitre', 'stages', 'remediation', 'tags')

def _decode(row, json_fields):
    item = dict(row)
    for field in json_fields:
        if item.get(field):
            try:
                item[field] = json.loads(item[field])
            except (TypeError, ValueError):
                pass
    return item

def _incident_from_row(row):
    return _decode(row, INCIDENT_JSON_FIELDS)

def _alert_from_row(row):
    return _decode(row, ALERT_JSON_FIELDS)

def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_engine_state(key, default=None):
    with get_db_connection() as conn:
        row = conn.execute('SELECT value FROM engine_state WHERE key = ?', (key,)).fetchone()
        return row['value'] if row else default

def set_engine_state(key, value):
    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO engine_state (key, value) VALUES (?, ?) '
            'ON CONFLICT(key) DO UPDATE SET value = excluded.value', (key, str(value)))
        conn.commit()

def get_logs_after(last_id, limit=5000):
    """New events for the detection engine, in ingestion order"""
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM logs WHERE id > ? ORDER BY id LIMIT ?', (last_id, limit)).fetchall()
        return [dict(row) for row in rows]

def get_logs_in_window(start_ts, end_ts, limit=100000):
    """Security-relevant events by event time, for windowed rule evaluation"""
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM logs
               WHERE ts_epoch BETWEEN ? AND ? AND COALESCE(event_category, '') != 'system'
               ORDER BY ts_epoch, id LIMIT ?""", (start_ts, end_ts, limit)).fetchall()
        return [dict(row) for row in rows]

def get_logs_by_ids(log_ids):
    if not log_ids:
        return []
    results = []
    with get_db_connection() as conn:
        ids = list(log_ids)
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ','.join('?' for _ in chunk)
            results.extend(dict(r) for r in conn.execute(f'SELECT * FROM logs WHERE id IN ({marks})', chunk).fetchall())
    return results

def find_open_alert(dedupe_key, earliest_ts):
    """Most recent alert for the same rule and entity that the new finding overlaps"""
    with get_db_connection() as conn:
        row = conn.execute(
            """SELECT a.* FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id
               WHERE a.dedupe_key = ? AND a.last_seen_ts >= ?
                 AND (a.incident_id IS NULL OR i.status IN ('ACTIVE', 'INVESTIGATING'))
               ORDER BY a.id DESC LIMIT 1""",
            (dedupe_key, earliest_ts)).fetchone()
        return _alert_from_row(row) if row else None

def insert_alert(alert, log_ids):
    columns = ('alert_uid', 'dedupe_key', 'rule_id', 'rule_name', 'detection_type', 'severity',
               'confidence', 'explanation', 'evidence', 'mitre', 'recommendations', 'entities',
               'observed', 'event_count', 'first_seen', 'last_seen', 'first_seen_ts',
               'last_seen_ts', 'created_at')
    values = [json.dumps(alert[c]) if c in ALERT_JSON_FIELDS else alert.get(c) for c in columns[:-1]]
    values.append(_utc_now())
    marks = ', '.join('?' for _ in columns)
    with get_db_connection() as conn:
        cursor = conn.execute(f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({marks})", values)
        alert_id = cursor.lastrowid
        conn.executemany('INSERT OR IGNORE INTO alert_events (alert_id, log_id) VALUES (?, ?)',
                         [(alert_id, log_id) for log_id in log_ids])
        conn.commit()
    return alert_id

def update_alert(alert_id, fields, log_ids=()):
    """Merge a repeat finding into its existing alert. Column names come from callers in this package."""
    assignments = ', '.join(f'{name} = ?' for name in fields)
    values = [json.dumps(v) if k in ALERT_JSON_FIELDS else v for k, v in fields.items()]
    with get_db_connection() as conn:
        if fields:
            conn.execute(f'UPDATE alerts SET {assignments} WHERE id = ?', values + [alert_id])
        conn.executemany('INSERT OR IGNORE INTO alert_events (alert_id, log_id) VALUES (?, ?)',
                         [(alert_id, log_id) for log_id in log_ids])
        count = conn.execute('SELECT COUNT(*) AS n FROM alert_events WHERE alert_id = ?', (alert_id,)).fetchone()['n']
        conn.execute('UPDATE alerts SET event_count = ? WHERE id = ?', (count, alert_id))
        conn.commit()
    return count

def get_alert(alert_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,)).fetchone()
        return _alert_from_row(row) if row else None

def get_recent_alerts(limit=100, severity=None, rule_id=None):
    sql = 'SELECT * FROM alerts'
    clauses, params = [], []
    if severity:
        clauses.append('severity = ?')
        params.append(severity)
    if rule_id:
        clauses.append('rule_id = ?')
        params.append(rule_id)
    if clauses:
        sql += ' WHERE ' + ' AND '.join(clauses)
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY last_seen_ts DESC LIMIT ?', params + [limit]).fetchall()
        return [_alert_from_row(row) for row in rows]

def get_alerts_for_incident(incident_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM alerts WHERE incident_id = ? ORDER BY first_seen_ts, id',
                            (incident_id,)).fetchall()
        return [_alert_from_row(row) for row in rows]

def get_unassigned_alerts(start_ts, end_ts):
    with get_db_connection() as conn:
        rows = conn.execute(
            'SELECT * FROM alerts WHERE incident_id IS NULL AND last_seen_ts >= ? AND first_seen_ts <= ?',
            (start_ts, end_ts)).fetchall()
        return [_alert_from_row(row) for row in rows]

def get_open_incidents_in_window(start_ts, end_ts):
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM incidents WHERE status IN ('ACTIVE', 'INVESTIGATING')
               AND last_seen_ts >= ? AND first_seen_ts <= ? ORDER BY id""", (start_ts, end_ts)).fetchall()
        return [_incident_from_row(row) for row in rows]

def create_incident(fields):
    """Create a correlated incident. Legacy columns stay populated for the existing dashboard."""
    with get_db_connection() as conn:
        cursor = conn.execute(
            'INSERT INTO incidents (title, description, severity, source_ip, status, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
            (fields['title'], fields['description'], fields['severity'], fields.get('source_ip'),
             'ACTIVE', _utc_now()))
        conn.commit()
        return cursor.lastrowid

def update_incident(incident_id, fields):
    """Update incident columns. Column names come from callers in this package."""
    stored = {k: (json.dumps(v) if k in INCIDENT_JSON_FIELDS else v) for k, v in fields.items()}
    stored['updated_at'] = _utc_now()
    assignments = ', '.join(f'{name} = ?' for name in stored)
    with get_db_connection() as conn:
        conn.execute(f'UPDATE incidents SET {assignments} WHERE id = ?', list(stored.values()) + [incident_id])
        conn.commit()

def get_incident(incident_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,)).fetchone()
        return _incident_from_row(row) if row else None

def get_alert_event_ids(alert_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT log_id FROM alert_events WHERE alert_id = ?', (alert_id,)).fetchall()
        return [row['log_id'] for row in rows]

def get_detections_for_logs(log_ids):
    """Map log id -> list of its detections, for the live event stream"""
    result = {}
    ids = list(log_ids)
    with get_db_connection() as conn:
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ','.join('?' for _ in chunk)
            rows = conn.execute(
                f"""SELECT ae.log_id, a.id AS alert_id, a.rule_id, a.severity, a.incident_id, a.confidence, a.detection_type
                    FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id
                    WHERE ae.log_id IN ({marks})""", chunk).fetchall()
            for row in rows:
                result.setdefault(row['log_id'], []).append(
                    {'alert_id': row['alert_id'], 'rule_id': row['rule_id'], 'severity': row['severity'], 'incident_id': row['incident_id'],
                     'confidence': row['confidence'], 'detection_type': row['detection_type']})
    return result

def _like(text):
    """A LIKE pattern matching the text literally, used with ESCAPE '\\'"""
    return '%' + text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'

def _search_clause(columns, text):
    clause = '(' + ' OR '.join(f"COALESCE({column}, '') LIKE ? ESCAPE '\\'" for column in columns) + ')'
    return clause, [_like(text)] * len(columns)

LOG_SEARCH_COLUMNS = ('src_ip', 'dst_ip', 'user', 'hostname', 'process_name', 'command_line', 'endpoint',
                      'details', 'event_type', 'event_id', 'file_path', 'domain', 'url')

def search_logs(limit=100, source=None, event_type=None, origin=None, text=None, detected=False,
                exclude_system=False, before_id=None):
    """Events for the live stream, newest first. All values are bound as parameters."""
    clauses, params = [], []
    for column, value in (('source', source), ('event_type', event_type), ('origin', origin)):
        if value:
            clauses.append(f'{column} = ?')
            params.append(value)
    if text:
        clause, values = _search_clause(LOG_SEARCH_COLUMNS, text)
        clauses.append(clause)
        params.extend(values)
    if detected:
        clauses.append('EXISTS (SELECT 1 FROM alert_events ae WHERE ae.log_id = logs.id)')
    if exclude_system:
        clauses.append("COALESCE(event_category, '') != 'system'")
    if before_id:
        clauses.append('id < ?')
        params.append(before_id)
    sql = 'SELECT * FROM logs' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY id DESC LIMIT ?', params + [limit]).fetchall()
    return [dict(row) for row in rows]

def get_log(log_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM logs WHERE id = ?', (log_id,)).fetchone()
        return dict(row) if row else None

def get_log_facets():
    """The filter values that actually exist in the data"""
    with get_db_connection() as conn:
        distinct = lambda column: [row[0] for row in conn.execute(
            f'SELECT DISTINCT {column} FROM logs WHERE {column} IS NOT NULL ORDER BY 1').fetchall()]
        return {'sources': distinct('source'), 'event_types': distinct('event_type'), 'origins': distinct('origin')}

def search_alerts(limit=100, severity=None, rule_id=None, detection_type=None, text=None):
    clauses, params = [], []
    for column, value in (('severity', severity), ('rule_id', rule_id), ('detection_type', detection_type)):
        if value:
            clauses.append(f'{column} = ?')
            params.append(value)
    if text:
        clause, values = _search_clause(('rule_id', 'rule_name', 'explanation', 'entities'), text)
        clauses.append(clause)
        params.extend(values)
    sql = 'SELECT * FROM alerts' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY last_seen_ts DESC, id DESC LIMIT ?', params + [limit]).fetchall()
    return [_alert_from_row(row) for row in rows]

def search_incidents(limit=100, status=None, severity=None, text=None, sort='recent', risk=None, data=None):
    clauses, params = [], []
    # Each uploaded file or simulation run is its own world, and its incidents name it in their entities
    if data == 'logs':
        clauses.append("entities LIKE '%\"simulation_run\": [\"ds-%'")
    elif data == 'simulation':
        clauses.append("entities LIKE '%\"simulation_run\": [\"sim-%'")
    elif data == 'live':
        clauses.append("COALESCE(entities, '') NOT LIKE '%\"simulation_run\"%'")
    if risk == 'HIGH_PLUS':
        clauses.append("risk_level IN ('HIGH', 'CRITICAL')")
    if status == 'OPEN':
        clauses.append("status IN ('ACTIVE', 'INVESTIGATING')")
    elif status:
        clauses.append('status = ?')
        params.append(status)
    if severity:
        clauses.append('severity = ?')
        params.append(severity)
    if text:
        clause, values = _search_clause(('incident_uid', 'title', 'description', 'source_ip', 'entities'), text)
        clauses.append(clause)
        params.extend(values)
    order = 'COALESCE(risk_score, -1) DESC, id DESC' if sort == 'risk' else 'id DESC'
    sql = 'SELECT * FROM incidents' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(f'{sql} ORDER BY {order} LIMIT ?', params + [limit]).fetchall()
    return [_incident_from_row(row) for row in rows]

def get_rule_activity():
    """rule_id -> how often a rule has fired and when last"""
    with get_db_connection() as conn:
        rows = conn.execute('SELECT rule_id, COUNT(*) AS alerts, MAX(last_seen) AS last_fired FROM alerts GROUP BY rule_id').fetchall()
    return {row['rule_id']: {'alerts': row['alerts'], 'last_fired': row['last_fired']} for row in rows}

def get_ioc_match_counts():
    """indicator value -> number of alerts it produced"""
    counts = {}
    with get_db_connection() as conn:
        rows = conn.execute("SELECT evidence FROM alerts WHERE detection_type = 'IOC'").fetchall()
    for row in rows:
        try:
            value = json.loads(row['evidence']).get('matched_indicator')
        except (TypeError, ValueError):
            continue
        counts[value] = counts.get(value, 0) + 1
    return counts

def get_overview(minutes):
    """Charts for the overview: everything is computed from stored rows within the time range.
    minutes=0 covers all stored events. A range means when logs arrived, not when they say they happened,
    because an uploaded log can be years old and must still show up as soon as it is analyzed."""
    arrived = "COALESCE(ingestion_timestamp, timestamp)"
    with get_db_connection() as conn:
        # One snapshot, so that the chart and its total agree while live logs keep arriving
        conn.execute('BEGIN')
        conn.execute('SELECT 1 FROM logs LIMIT 1').fetchone()
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if minutes:
            start = now - minutes * 60
        else:
            first = conn.execute(f"SELECT CAST(strftime('%s', MIN({arrived})) AS REAL) FROM logs").fetchone()[0]
            start = first if first is not None else now - 3600
        since = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).isoformat()
        span = max(now - start, 60)
        # About 24 points, on round bucket sizes
        bucket = next((size for size in (60, 300, 900, 3600, 21600, 86400, 604800) if span / size <= 30), 2592000)
        rows = conn.execute(
            f"""SELECT CAST(CAST(strftime('%s', {arrived}) AS INTEGER) / ? AS INTEGER) * ? AS bucket, source, COUNT(*) AS n FROM logs
               WHERE {arrived} >= ? GROUP BY 1, 2""", (bucket, bucket, since)).fetchall()
        severity = {row[0]: row[1] for row in conn.execute(
            'SELECT severity, COUNT(*) FROM alerts WHERE created_at >= ? GROUP BY 1', (since,)).fetchall()}
        rules = conn.execute(
            """SELECT rule_id, rule_name, COUNT(*) AS alerts FROM alerts WHERE created_at >= ?
               GROUP BY 1, 2 ORDER BY alerts DESC, rule_id LIMIT 8""", (since,)).fetchall()
        types = {row[0]: row[1] for row in conn.execute(
            'SELECT detection_type, COUNT(*) FROM alerts WHERE created_at >= ? GROUP BY 1', (since,)).fetchall()}
        in_range = conn.execute(f'SELECT COUNT(*) FROM logs WHERE {arrived} >= ?', (since,)).fetchone()[0]

    series = {}
    for row in rows:
        series.setdefault(row['bucket'], {})[row['source']] = row['n']
    first_bucket = int(start // bucket) * bucket
    timeline = []
    current = first_bucket
    while current <= now:
        counts = series.get(current, {})
        timeline.append({'time': datetime.datetime.fromtimestamp(current, datetime.timezone.utc).isoformat(),
                         'network': counts.get('network', 0), 'endpoint': counts.get('endpoint', 0),
                         'application': counts.get('application', 0)})
        current += bucket
    return {
        'minutes': minutes,
        'bucket_seconds': bucket,
        'events_in_range': in_range,
        'timeline': timeline,
        'alerts_by_severity': {name: severity.get(name, 0) for name in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')},
        'alerts_by_type': {name: types.get(name, 0) for name in ('IOA', 'IOC', 'UEBA')},
        'top_rules': [dict(row) for row in rules],
    }

def keep_wal_open():
    """Hold one connection for the life of the server. Otherwise each time the last connection
    closes, SQLite checkpoints and removes the WAL file, which costs several ms per query."""
    global _wal_anchor
    _wal_anchor = sqlite3.connect(DATABASE_NAME, check_same_thread=False)

def get_dashboard_counts():
    """Aggregate counters, all computed from stored data"""
    with get_db_connection() as conn:
        one = lambda sql: conn.execute(sql).fetchone()[0]
        return {
            'alerts': one('SELECT COUNT(*) FROM alerts'),
            'critical_alerts': one("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'"),
            'incidents_open': one("SELECT COUNT(*) FROM incidents WHERE status IN ('ACTIVE', 'INVESTIGATING')"),
            'incidents_investigating': one("SELECT COUNT(*) FROM incidents WHERE status = 'INVESTIGATING'"),
            'responses_pending': one("SELECT COUNT(*) FROM response_actions WHERE status = 'PENDING'"),
            'responses_needs_investigation': one("SELECT COUNT(*) FROM response_actions WHERE status = 'NEEDS_INVESTIGATION'"),
            'notifications_unread': one('SELECT COUNT(*) FROM notifications WHERE read_at IS NULL'),
            'responses_executed': one("SELECT COUNT(*) FROM response_actions WHERE status = 'EXECUTED'"),
            'responses_automated': one("SELECT COUNT(*) FROM response_actions WHERE status = 'EXECUTED' AND executed_by = 'automation'"),
            'responses_held': one("SELECT COUNT(*) FROM response_actions WHERE status = 'HELD'"),
            'incidents_resolved': one("SELECT COUNT(*) FROM incidents WHERE status = 'RESOLVED'"),
            'high_risk_incidents': one("SELECT COUNT(*) FROM incidents WHERE risk_level IN ('HIGH', 'CRITICAL')"),
            'blocked_ips': one('SELECT COUNT(*) FROM blocklist'),
        }

def upsert_ioc(ioc):
    """Add or refresh one indicator. Returns True when a new row was created."""
    with get_db_connection() as conn:
        exists = conn.execute('SELECT 1 FROM iocs WHERE ioc_type = ? AND value = ?',
                              (ioc['ioc_type'], ioc['value'])).fetchone()
        conn.execute(
            """INSERT INTO iocs (ioc_type, value, source, severity, confidence, description, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ioc_type, value) DO UPDATE SET
                   source = excluded.source, severity = excluded.severity,
                   confidence = excluded.confidence, description = excluded.description""",
            (ioc['ioc_type'], ioc['value'], ioc['source'], ioc['severity'], ioc['confidence'],
             ioc.get('description'), _utc_now()))
        conn.commit()
        return exists is None

def get_all_iocs(limit=None):
    with get_db_connection() as conn:
        sql = 'SELECT * FROM iocs ORDER BY id DESC'
        rows = conn.execute(sql + ' LIMIT ?', (limit,)) if limit else conn.execute(sql)
        return [dict(row) for row in rows.fetchall()]

_CONTEXT_COLUMNS = ('src_ip', 'dst_ip', 'user', 'hostname', 'dst_port', 'process_name')

def get_log_context(batch, start_ts, end_ts, group=None, limit=5000):
    """Logs around a moment, in the same world as one log: its batch, or real telemetry when it has none"""
    clauses, params = ['ts_epoch BETWEEN ? AND ?'], [start_ts, end_ts]
    if batch:
        clauses.append('ingest_batch = ?')
        params.append(batch)
    else:
        clauses.append("COALESCE(origin, 'live') NOT IN ('simulation', 'dataset')")
    for column, value in (group or {}).items():
        if column not in _CONTEXT_COLUMNS:
            raise ValueError(f'cannot group by {column}')
        clauses.append(f'{column} IS ?')
        params.append(value)
    with get_db_connection() as conn:
        rows = conn.execute(f"SELECT * FROM logs WHERE {' AND '.join(clauses)} ORDER BY ts_epoch, id LIMIT ?", params + [limit]).fetchall()
    return [dict(row) for row in rows]

def get_alerts_by_ids(alert_ids):
    ids = list(alert_ids)
    if not ids:
        return []
    with get_db_connection() as conn:
        rows = conn.execute(f"SELECT * FROM alerts WHERE id IN ({','.join('?' * len(ids))})", ids).fetchall()
    return [_alert_from_row(row) for row in rows]

def get_batch_evidence_ids(batch_id):
    """The logs in a batch that support a detection"""
    with get_db_connection() as conn:
        rows = conn.execute('SELECT DISTINCT ae.log_id FROM alert_events ae JOIN logs l ON l.id = ae.log_id WHERE l.ingest_batch = ?', (batch_id,)).fetchall()
    return {row[0] for row in rows}

def get_all_batch_events(batch_id, limit=50000):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM logs WHERE ingest_batch = ? ORDER BY ts_epoch, id LIMIT ?', (batch_id, limit)).fetchall()
    return [dict(row) for row in rows]

def get_flow(minutes, origin, minimum_confidence):
    """How stored logs moved through detection: log type, then verdict, then outcome.

    Each log is counted once, under the strongest detection it supports."""
    clauses, params = [], []
    if minutes:
        # When a log arrived, not when it says it happened, so that an old log file shows up as soon as it is added
        clauses.append('COALESCE(l.ingestion_timestamp, l.timestamp) >= ?')
        params.append((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)).isoformat())
    if origin:
        clauses.append('l.origin = ?')
        params.append(origin)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    with get_db_connection() as conn:
        rows = conn.execute(
            f"""SELECT COALESCE(l.event_category, l.source, 'other') AS category, COALESCE(d.confirmed, -1) AS strength, COALESCE(d.in_incident, 0) AS in_incident, COUNT(*) AS logs
                FROM logs l LEFT JOIN (
                    SELECT ae.log_id,
                           MAX(a.detection_type IN ('IOA', 'IOC') AND a.confidence >= ? AND a.severity != 'LOW') AS confirmed,
                           MAX(a.incident_id IS NOT NULL) AS in_incident
                    FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id GROUP BY ae.log_id) d ON d.log_id = l.id
                {where} GROUP BY 1, 2, 3""", [minimum_confidence] + params).fetchall()
    return [dict(row) for row in rows]

def save_email_log(incident_id, recipients, subject, status, error=None):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO email_log (incident_id, recipients, subject, status, error, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                     (incident_id, recipients, subject, status, error, _utc_now()))
        conn.commit()

def get_email_log(limit=20):
    with get_db_connection() as conn:
        return [dict(row) for row in conn.execute('SELECT * FROM email_log ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]

def count_emails_sent_since(iso_time):
    with get_db_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM email_log WHERE status = 'SENT' AND created_at >= ?", (iso_time,)).fetchone()[0]

def bulk_upsert_iocs(iocs):
    """Add or refresh many indicators in one transaction. Returns (added, updated)."""
    added = updated = 0
    now = _utc_now()
    with get_db_connection() as conn:
        for ioc in iocs:
            exists = conn.execute('SELECT 1 FROM iocs WHERE ioc_type = ? AND value = ?',
                                  (ioc['ioc_type'], ioc['value'])).fetchone()
            conn.execute(
                """INSERT INTO iocs (ioc_type, value, source, severity, confidence, description, added_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, value) DO UPDATE SET
                       source = excluded.source, severity = excluded.severity,
                       confidence = excluded.confidence, description = excluded.description""",
                (ioc['ioc_type'], ioc['value'], ioc['source'], ioc['severity'], ioc['confidence'],
                 ioc.get('description'), now))
            if exists:
                updated += 1
            else:
                added += 1
        conn.commit()
    return added, updated

def find_ioc(value):
    """The indicator with this exact value, or None"""
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM iocs WHERE value = ? ORDER BY id DESC LIMIT 1', (value,)).fetchone()
        return dict(row) if row else None

def delete_iocs_by_source(source):
    with get_db_connection() as conn:
        count = conn.execute('DELETE FROM iocs WHERE source = ?', (source,)).rowcount
        conn.commit()
        return count

_IOC_LOG_COLUMNS = ('src_ip', 'dst_ip', 'domain', 'url', 'file_hash')
_MATCH_CHUNK = 500

def find_log_matches(column, values):
    """Stored events whose column holds one of these values, grouped by value and origin"""
    if column not in _IOC_LOG_COLUMNS:
        raise ValueError(f'cannot search {column}')
    values = list(values)
    matches = []
    with get_db_connection() as conn:
        for start in range(0, len(values), _MATCH_CHUNK):
            chunk = values[start:start + _MATCH_CHUNK]
            marks = ','.join('?' * len(chunk))
            matches.extend(dict(row) for row in conn.execute(
                f"""SELECT {column} AS value, COALESCE(origin, 'legacy') AS origin, COUNT(*) AS events,
                           MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen
                    FROM logs WHERE {column} IN ({marks}) GROUP BY 1, 2""", chunk).fetchall())
    return matches

def get_distinct_log_values(column):
    if column not in _IOC_LOG_COLUMNS:
        raise ValueError(f'cannot search {column}')
    with get_db_connection() as conn:
        return [row[0] for row in conn.execute(f'SELECT DISTINCT {column} FROM logs WHERE {column} IS NOT NULL').fetchall()]

# ---------- User accounts ----------

def count_active_users():
    with get_db_connection() as conn:
        return conn.execute('SELECT COUNT(*) FROM users WHERE disabled = 0').fetchone()[0]

def get_user(username):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        return dict(row) if row else None

def username_taken(username):
    """Names differing only in case would read as the same person in the audit log"""
    with get_db_connection() as conn:
        return conn.execute('SELECT 1 FROM users WHERE lower(username) = lower(?)', (username,)).fetchone() is not None

def get_users():
    with get_db_connection() as conn:
        return [dict(row) for row in conn.execute(
            'SELECT username, role, disabled, created_at, last_login_at FROM users ORDER BY username').fetchall()]

def save_user(username, password_hash, role):
    """Create the account, or replace its password and role and enable it again"""
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO users (username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, 0, ?)
               ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role, disabled = 0""",
            (username, password_hash, role, _utc_now()))
        conn.commit()

def set_user_disabled(username, disabled):
    with get_db_connection() as conn:
        count = conn.execute('UPDATE users SET disabled = ? WHERE username = ?', (1 if disabled else 0, username)).rowcount
        conn.commit()
        return count > 0

def record_user_login(username):
    with get_db_connection() as conn:
        conn.execute('UPDATE users SET last_login_at = ? WHERE username = ?', (_utc_now(), username))
        conn.commit()

def insert_simulation_run(run):
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO simulation_runs (run_id, scenario, is_malicious, expected_rules, event_count, started_at,
                   status, intensity, speed, seed, background_events)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run['run_id'], run['scenario'], int(run['is_malicious']), json.dumps(run['expected_rules']),
             run['event_count'], run['started_at'], run.get('status', 'COMPLETED'), run.get('intensity'),
             run.get('speed'), run.get('seed'), run.get('background_events', 0)))
        conn.commit()

def update_simulation_run(run_id, fields):
    """Column names come from callers in this package"""
    assignments = ', '.join(f'{name} = ?' for name in fields)
    with get_db_connection() as conn:
        conn.execute(f'UPDATE simulation_runs SET {assignments} WHERE run_id = ?', list(fields.values()) + [run_id])
        conn.commit()

def mark_interrupted_jobs():
    """Jobs still marked as running when the server starts were cut off by a restart"""
    with get_db_connection() as conn:
        runs = conn.execute("UPDATE simulation_runs SET status = 'INTERRUPTED', error = 'The server restarted during this run.', "
                            "completed_at = ? WHERE status IN ('RUNNING', 'PAUSED')", (_utc_now(),)).rowcount
        datasets = conn.execute("UPDATE datasets SET status = 'INTERRUPTED', verdict = 'ANALYSIS_INCOMPLETE', error = 'The server restarted during processing.', "
                                "completed_at = ? WHERE status IN ('QUEUED', 'PROCESSING')", (_utc_now(),)).rowcount
        conn.commit()
    return runs + datasets

def get_simulation_outcome(run_id):
    """Compare a run's recorded ground truth with what the engine actually produced"""
    with get_db_connection() as conn:
        run = conn.execute('SELECT * FROM simulation_runs WHERE run_id = ?', (run_id,)).fetchone()
        if not run:
            return None
        rows = conn.execute(
            """SELECT DISTINCT a.rule_id, a.severity, a.incident_id
               FROM logs l
               JOIN alert_events ae ON ae.log_id = l.id
               JOIN alerts a ON a.id = ae.alert_id
               WHERE l.ingest_batch = ?""", (run_id,)).fetchall()
    expected = json.loads(run['expected_rules'])
    fired = sorted({row['rule_id'] for row in rows})
    return {
        'run_id': run_id,
        'scenario': run['scenario'],
        'is_malicious': bool(run['is_malicious']),
        'event_count': run['event_count'],
        'started_at': run['started_at'],
        'status': run['status'] or 'COMPLETED',
        'completed_at': run['completed_at'],
        'intensity': run['intensity'],
        'speed': run['speed'],
        'seed': run['seed'],
        'background_events': run['background_events'] or 0,
        'processed_count': run['processed_count'] if run['status'] else run['event_count'],
        'failed_count': run['failed_count'] or 0,
        'error': run['error'],
        'expected_rules': expected,
        'fired_rules': fired,
        'missed_rules': sorted(set(expected) - set(fired)),
        'unexpected_rules': sorted(set(fired) - set(expected)),
        'incident_ids': sorted({row['incident_id'] for row in rows if row['incident_id']}),
    }

def get_detection_watermark():
    """Highest alert and incident ids, to tell what a later ingest created"""
    with get_db_connection() as conn:
        return (conn.execute('SELECT COALESCE(MAX(id), 0) FROM alerts').fetchone()[0],
                conn.execute('SELECT COALESCE(MAX(id), 0) FROM incidents').fetchone()[0])

def get_batch_detection(batch_id, watermark):
    """What an ingested batch led to, read from stored results. The background engine may have
    processed the batch first, so this cannot rely on who happened to run the engine."""
    alert_mark, incident_mark = watermark
    with get_db_connection() as conn:
        events = conn.execute('SELECT COUNT(*) FROM logs WHERE ingest_batch = ?', (batch_id,)).fetchone()[0]
        rows = conn.execute(
            """SELECT DISTINCT a.id, a.incident_id FROM logs l
               JOIN alert_events ae ON ae.log_id = l.id
               JOIN alerts a ON a.id = ae.alert_id
               WHERE l.ingest_batch = ?""", (batch_id,)).fetchall()
    incidents = {row['incident_id'] for row in rows if row['incident_id']}
    created = sorted(i for i in incidents if i > incident_mark)
    new_alerts = sum(1 for row in rows if row['id'] > alert_mark)
    return {
        'events': events,
        'alerts_created': new_alerts,
        'alerts_updated': len(rows) - new_alerts,
        'incidents_created': created,
        'incidents_updated': sorted(incidents - set(created)),
    }

def add_audit_entry(actor, action, entity_type=None, entity_id=None, incident_id=None, details=None):
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO audit_log (timestamp, actor, action, entity_type, entity_id, incident_id, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (_utc_now(), actor, action, entity_type, entity_id, incident_id,
             json.dumps(details) if details is not None else None))
        conn.commit()

def get_audit_entries(limit=200, incident_id=None, actor=None, action=None):
    clauses, params = [], []
    for column, value in (('incident_id', incident_id), ('actor', actor), ('action', action)):
        if value not in (None, ''):
            clauses.append(f'{column} = ?')
            params.append(value)
    sql = 'SELECT * FROM audit_log' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY id DESC LIMIT ?', params + [limit]).fetchall()
    return [_decode(row, ('details',)) for row in rows]

RESPONSE_JSON_FIELDS = ('result', 'verification')

def insert_response_action(action):
    """Store a recommendation once. Returns its id if new, None if it already existed."""
    with get_db_connection() as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO response_actions
               (incident_id, action_type, label, description, target_type, target, original_target,
                disruptive, recommended_by, rationale, created_at, expected_impact)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (action['incident_id'], action['action_type'], action['label'], action['description'],
             action['target_type'], action['target'], action['target'], int(action['disruptive']),
             action['recommended_by'], action['rationale'], _utc_now(), action.get('expected_impact')))
        conn.commit()
        return cursor.lastrowid if cursor.rowcount else None

def get_response_action(action_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM response_actions WHERE id = ?', (action_id,)).fetchone()
        return _decode(row, RESPONSE_JSON_FIELDS) if row else None

def get_response_actions(incident_id=None, status=None, limit=200, executed_by=None):
    clauses, params = [], []
    if executed_by:
        clauses.append('executed_by = ?')
        params.append(executed_by)
    if incident_id is not None:
        clauses.append('incident_id = ?')
        params.append(incident_id)
    if status:
        clauses.append('status = ?')
        params.append(status)
    sql = 'SELECT * FROM response_actions' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY id LIMIT ?', params + [limit]).fetchall()
    return [_decode(row, RESPONSE_JSON_FIELDS) for row in rows]

def update_response_action(action_id, expected_status, fields):
    """Change an action only if it is still in the expected state, so two analysts cannot both
    act on it. Column names come from callers in this package. Returns False if it had moved on."""
    stored = {k: (json.dumps(v) if k in RESPONSE_JSON_FIELDS else v) for k, v in fields.items()}
    assignments = ', '.join(f'{name} = ?' for name in stored)
    with get_db_connection() as conn:
        cursor = conn.execute(f'UPDATE response_actions SET {assignments} WHERE id = ? AND status = ?',
                              list(stored.values()) + [action_id, expected_status])
        conn.commit()
        return cursor.rowcount == 1

def record_simulated_enforcement(action_id, action_type, target):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO simulated_enforcement (action_id, action_type, target, created_at) VALUES (?, ?, ?, ?)',
                     (action_id, action_type, target, _utc_now()))
        conn.commit()

def has_simulated_enforcement(action_id, action_type, target):
    with get_db_connection() as conn:
        return conn.execute('SELECT 1 FROM simulated_enforcement WHERE action_id = ? AND action_type = ? AND target = ?',
                            (action_id, action_type, target)).fetchone() is not None

def set_incident_status(incident_id, status):
    with get_db_connection() as conn:
        conn.execute('UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?', (status, _utc_now(), incident_id))
        conn.commit()

def count_simulation_runs():
    with get_db_connection() as conn:
        return conn.execute('SELECT COUNT(*) AS total FROM simulation_runs').fetchone()['total']

def get_recent_simulation_runs(limit=20):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT run_id FROM simulation_runs ORDER BY started_at DESC LIMIT ?', (limit,)).fetchall()
    return [get_simulation_outcome(row['run_id']) for row in rows]

# ---------------------------------------------------------------------------
# Behavioral baselines
# ---------------------------------------------------------------------------

def _baseline_scope(run):
    """A run is compared only with itself. Real telemetry is never compared with synthetic data."""
    if run:
        return 'ingest_batch = ?', [run]
    return "COALESCE(origin, '') NOT IN ('simulation', 'dataset')", []

def get_user_login_history(user, run, limit=5000):
    """A user's successful logins, for comparing a new one with what is usual for them"""
    scope, params = _baseline_scope(run)
    with get_db_connection() as conn:
        rows = conn.execute(
            f"""SELECT id, ts_epoch, src_ip FROM logs
                WHERE user = ? AND event_type = 'authentication_success' AND ts_epoch IS NOT NULL AND {scope}
                ORDER BY ts_epoch, id LIMIT ?""", [user] + params + [limit]).fetchall()
    return [dict(row) for row in rows]

def get_outbound_sizes(src_ip, before_ts, before_id, run, limit=500):
    """Outbound transfer sizes from an address before this event, most recent first"""
    scope, params = _baseline_scope(run)
    with get_db_connection() as conn:
        rows = conn.execute(
            f"""SELECT bytes_out FROM logs
                WHERE src_ip = ? AND bytes_out > 0 AND (ts_epoch < ? OR (ts_epoch = ? AND id < ?)) AND {scope}
                ORDER BY ts_epoch DESC LIMIT ?""", [src_ip, before_ts, before_ts, before_id] + params + [limit]).fetchall()
    return [row['bytes_out'] for row in rows]

# ---------------------------------------------------------------------------
# Automation and notifications
# ---------------------------------------------------------------------------

def insert_automation_step(subject, incident_id, risk_level, step, detail):
    """Record an automatic step once. Returns True only the first time."""
    with get_db_connection() as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO automation_log (subject, incident_id, risk_level, step, detail, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""", (subject, incident_id, risk_level, step, json.dumps(detail), _utc_now()))
        conn.commit()
        return cursor.rowcount == 1

def get_automation_log(incident_id=None, subject=None, limit=200):
    clauses, params = [], []
    for column, value in (('incident_id', incident_id), ('subject', subject)):
        if value is not None:
            clauses.append(f'{column} = ?')
            params.append(value)
    sql = 'SELECT * FROM automation_log' + (' WHERE ' + ' AND '.join(clauses) if clauses else '')
    with get_db_connection() as conn:
        rows = conn.execute(sql + ' ORDER BY id DESC LIMIT ?', params + [limit]).fetchall()
    return [_decode(row, ('detail',)) for row in rows]

def insert_notification(incident_id, level, message):
    """One notification per incident and risk level. Returns True only the first time."""
    with get_db_connection() as conn:
        cursor = conn.execute(
            'INSERT OR IGNORE INTO notifications (incident_id, level, message, created_at) VALUES (?, ?, ?, ?)',
            (incident_id, level, message, _utc_now()))
        conn.commit()
        return cursor.rowcount == 1

def get_notifications(limit=50, unread_only=False):
    sql = 'SELECT * FROM notifications' + (' WHERE read_at IS NULL' if unread_only else '')
    with get_db_connection() as conn:
        return [dict(row) for row in conn.execute(sql + ' ORDER BY id DESC LIMIT ?', (limit,)).fetchall()]

def mark_notifications_read():
    with get_db_connection() as conn:
        count = conn.execute('UPDATE notifications SET read_at = ? WHERE read_at IS NULL', (_utc_now(),)).rowcount
        conn.commit()
    return count

def get_risk_distribution():
    with get_db_connection() as conn:
        rows = conn.execute("SELECT risk_level, COUNT(*) AS n FROM incidents WHERE risk_level IS NOT NULL GROUP BY risk_level").fetchall()
    return {row['risk_level']: row['n'] for row in rows}

# ---------------------------------------------------------------------------
# Ground truth, batches and datasets
# ---------------------------------------------------------------------------

def insert_ground_truth(rows):
    """rows: (event_id, batch_id, label, attack_type)"""
    with get_db_connection() as conn:
        conn.executemany('INSERT OR REPLACE INTO ground_truth (event_id, batch_id, label, attack_type) VALUES (?, ?, ?, ?)', rows)
        conn.commit()

def get_ground_truth(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT event_id, label, attack_type FROM ground_truth WHERE batch_id = ?', (batch_id,)).fetchall()
    return {row['event_id']: dict(row) for row in rows}

def get_batch_events(batch_id, limit=200, offset=0):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM logs WHERE ingest_batch = ? ORDER BY ts_epoch, id LIMIT ? OFFSET ?',
                            (batch_id, limit, offset)).fetchall()
    return [_public_log(row) for row in rows]

def get_batch_event_summary(batch_id):
    """Each event's id and whether any alert cites it"""
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT l.id, l.event_id, l.ingestion_timestamp,
                      (EXISTS (SELECT 1 FROM alert_events ae WHERE ae.log_id = l.id)
                       OR EXISTS (SELECT 1 FROM ml_predictions p WHERE p.log_id = l.id AND p.predicted_label != 'BENIGN')) AS detected
               FROM logs l WHERE l.ingest_batch = ?""", (batch_id,)).fetchall()
    return [dict(row) for row in rows]

def get_batch_alerts(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute(
            """SELECT DISTINCT a.* FROM alerts a
               JOIN alert_events ae ON ae.alert_id = a.id
               JOIN logs l ON l.id = ae.log_id
               WHERE l.ingest_batch = ? ORDER BY a.first_seen_ts, a.id""", (batch_id,)).fetchall()
    return [_alert_from_row(row) for row in rows]

def get_alert_batch_event_ids(alert_id):
    """The event identifiers an alert cites, for comparing with ground truth"""
    with get_db_connection() as conn:
        rows = conn.execute('SELECT l.event_id FROM alert_events ae JOIN logs l ON l.id = ae.log_id WHERE ae.alert_id = ?',
                            (alert_id,)).fetchall()
    return [row['event_id'] for row in rows]

def get_batch_counts(batch_id):
    with get_db_connection() as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS total,
                      COALESCE(SUM(l.ts_epoch IS NULL), 0) AS without_timestamp,
                      COALESCE(SUM(l.ts_epoch IS NULL AND p.log_id IS NOT NULL), 0) AS without_timestamp_classified
               FROM logs l LEFT JOIN ml_predictions p ON p.log_id = l.id
               WHERE l.ingest_batch = ?""", (batch_id,)).fetchone()
    return dict(row)

def record_engine_run(batch_id, engine, seen, applicable, findings, failures, detail=None):
    """Add to what an engine has done for a batch. A batch can span several processing passes."""
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO engine_runs (batch_id, engine, events_seen, applicable, findings, failures, detail, last_run)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(batch_id, engine) DO UPDATE SET
                   events_seen = events_seen + excluded.events_seen, applicable = applicable + excluded.applicable,
                   findings = findings + excluded.findings, failures = failures + excluded.failures,
                   detail = COALESCE(excluded.detail, detail), last_run = excluded.last_run""",
            (batch_id, engine, seen, applicable, findings, failures, json.dumps(detail) if detail else None, _utc_now()))
        conn.commit()

def get_engine_runs(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM engine_runs WHERE batch_id = ?', (batch_id,)).fetchall()
    return [_decode(row, ('detail',)) for row in rows]

def insert_ml_predictions(rows):
    """rows: (log_id, batch_id, event_id, predicted_label, model_version)"""
    with get_db_connection() as conn:
        conn.executemany('INSERT OR REPLACE INTO ml_predictions (log_id, batch_id, event_id, predicted_label, model_version) VALUES (?, ?, ?, ?, ?)', rows)
        conn.commit()

def get_ml_prediction_counts(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT predicted_label, COUNT(*) AS n FROM ml_predictions WHERE batch_id = ? GROUP BY predicted_label', (batch_id,)).fetchall()
    return {row['predicted_label']: row['n'] for row in rows}

def get_ml_flagged_log_ids(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute("SELECT log_id FROM ml_predictions WHERE batch_id = ? AND predicted_label != 'BENIGN'", (batch_id,)).fetchall()
    return [row['log_id'] for row in rows]

def get_ml_predictions(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT event_id, predicted_label, model_version FROM ml_predictions WHERE batch_id = ?', (batch_id,)).fetchall()
    return {row['event_id']: dict(row) for row in rows}

ANOMALY_JSON_FIELDS = ('features', 'event_log_ids')

def upsert_anomaly(finding):
    """Store an unusual window, or update it if more of its events have arrived"""
    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO anomaly_findings (batch_id, scope, entity, window_start_ts, window_end_ts, strength, score,
                   event_count, explanation, features, event_log_ids, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(batch_id, entity, window_start_ts) DO UPDATE SET
                   strength = excluded.strength, score = excluded.score, event_count = excluded.event_count,
                   explanation = excluded.explanation, features = excluded.features, event_log_ids = excluded.event_log_ids""",
            (finding['batch_id'], finding['scope'], finding['entity'], finding['window_start_ts'], finding['window_end_ts'],
             finding['strength'], finding['score'], finding['event_count'], finding['explanation'],
             json.dumps(finding['features']), json.dumps(finding['event_log_ids']), _utc_now()))
        conn.commit()

def get_batch_anomalies(batch_id):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM anomaly_findings WHERE batch_id = ? ORDER BY strength DESC, window_start_ts', (batch_id,)).fetchall()
    return [_decode(row, ANOMALY_JSON_FIELDS) for row in rows]

def get_anomalies_for_incident(entities, start_ts, end_ts):
    """Unusual windows about the same sources and hosts as an incident, in the same run"""
    values = sorted(set(entities.get('src_ip', [])) | set(entities.get('hostname', [])))
    if not values:
        return []
    run = (entities.get('simulation_run') or [None])[0]
    marks = ','.join('?' for _ in values)
    scope = 'scope = ?' if run else 'scope IS NULL'
    params = values + ([run] if run else []) + [end_ts, start_ts]
    with get_db_connection() as conn:
        rows = conn.execute(f'SELECT * FROM anomaly_findings WHERE entity IN ({marks}) AND {scope} AND window_start_ts <= ? AND window_end_ts >= ?', params).fetchall()
    return [_decode(row, ANOMALY_JSON_FIELDS) for row in rows]

DATASET_JSON_FIELDS = ('params', 'summary', 'invalid_records', 'metrics', 'expected_rules', 'analysis')

def insert_dataset(dataset):
    columns = ('dataset_id', 'name', 'kind', 'status', 'sha256', 'params', 'summary', 'invalid_records', 'expected_rules', 'total_events', 'verdict', 'error', 'created_at')
    values = [json.dumps(dataset.get(c)) if c in DATASET_JSON_FIELDS else dataset.get(c) for c in columns[:-1]] + [_utc_now()]
    with get_db_connection() as conn:
        conn.execute(f"INSERT INTO datasets ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})", values)
        conn.commit()

def update_dataset(dataset_id, fields):
    """Column names come from callers in this package"""
    stored = {k: (json.dumps(v) if k in DATASET_JSON_FIELDS else v) for k, v in fields.items()}
    assignments = ', '.join(f'{name} = ?' for name in stored)
    with get_db_connection() as conn:
        conn.execute(f'UPDATE datasets SET {assignments} WHERE dataset_id = ?', list(stored.values()) + [dataset_id])
        conn.commit()

def get_dataset(dataset_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM datasets WHERE dataset_id = ?', (dataset_id,)).fetchone()
    return _decode(row, DATASET_JSON_FIELDS) if row else None

def get_datasets(limit=50):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT * FROM datasets ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
    return [_decode(row, DATASET_JSON_FIELDS) for row in rows]

def find_completed_dataset(sha256):
    with get_db_connection() as conn:
        row = conn.execute("SELECT dataset_id FROM datasets WHERE sha256 = ? AND status = 'COMPLETED' ORDER BY created_at DESC LIMIT 1",
                           (sha256,)).fetchone()
    return row['dataset_id'] if row else None

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def insert_report(report):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO reports (report_id, subject_type, subject_id, title, content, generated_at) VALUES (?, ?, ?, ?, ?, ?)',
                     (report['report_id'], report['subject_type'], report['subject_id'], report['title'],
                      json.dumps(report['content']), report['generated_at']))
        conn.commit()

def get_report(report_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT * FROM reports WHERE report_id = ?', (report_id,)).fetchone()
    return _decode(row, ('content',)) if row else None

def get_latest_report_id(subject_id):
    with get_db_connection() as conn:
        row = conn.execute('SELECT report_id FROM reports WHERE subject_id = ? ORDER BY generated_at DESC LIMIT 1', (subject_id,)).fetchone()
    return row['report_id'] if row else None

def get_reports(limit=100):
    with get_db_connection() as conn:
        rows = conn.execute('SELECT report_id, subject_type, subject_id, title, generated_at FROM reports ORDER BY generated_at DESC LIMIT ?',
                            (limit,)).fetchall()
    return [dict(row) for row in rows]
