import random
from datetime import datetime, timedelta, timezone

from utils.simulator import MB, SCENARIOS, _auth, _conn, _proc, event_label

# Reproducible synthetic datasets. Labels are returned next to each event, never inside it, so
# nothing the detection engine reads can reveal them. All addresses are private or from the
# RFC 5737 documentation ranges, and nothing here sends network traffic.

MAX_GENERATED_EVENTS = 20000
BENIGN_PROCESSES = (('dotnet.exe', 'dotnet build'), ('git.exe', 'git status'), ('python.exe', 'python report.py'),
                    ('code.exe', 'code .'), ('powershell.exe', 'powershell.exe Get-Date'), ('net.exe', 'net view'))


def _suspicious_login():
    """An established account signs in from a new external address after a few failures"""
    user, host, known, new = 'mrao', 'crm-02', '10.91.0.5', '203.0.113.33'
    events = [_auth(-gap, True, known, user, host) for gap in (5000, 4100, 3200, 2500, 1700, 900)]
    return events + [_auth(0, False, new, user, host), _auth(15, False, new, user, host), _auth(40, True, new, user, host)]


def _unusual_network():
    """A workstation repeatedly reaches an external address on a port nothing else uses"""
    return [_conn(i * 45 + (i % 3) * 7, 'wks-41', '10.91.0.41', '198.51.100.66', 4444, 2000) for i in range(5)]


CUSTOM = {
    'suspicious_login': {'build': _suspicious_login, 'malicious': True, 'label': 'suspicious', 'expected_rules': ['UEBA-001']},
    'unusual_network': {'build': _unusual_network, 'malicious': True, 'label': 'suspicious', 'expected_rules': ['IOA-006']},
}

PROFILES = {
    'normal': {'name': 'Normal activity', 'attacks': []},
    'suspicious_login': {'name': 'Suspicious login behavior', 'attacks': ['suspicious_login']},
    'brute_force': {'name': 'Brute-force activity', 'attacks': ['brute_force']},
    'port_scan': {'name': 'Port scanning activity', 'attacks': ['port_scan']},
    'privilege_misuse': {'name': 'Privilege misuse', 'attacks': ['privilege_escalation']},
    'lateral_movement': {'name': 'Lateral movement', 'attacks': ['lateral']},
    'unusual_network': {'name': 'Unusual network traffic', 'attacks': ['unusual_network']},
    'exfiltration': {'name': 'Potential exfiltration', 'attacks': ['exfil']},
    'mixed': {'name': 'Mixed benign and malicious', 'attacks': ['brute_force', 'privilege_escalation', 'lateral', 'exfil']},
}


def _definition(name):
    return CUSTOM.get(name) or SCENARIOS[name]


def expected_rules_for(profile):
    return sorted({rule for name in PROFILES[profile]['attacks'] for rule in _definition(name)['expected_rules']})


def normal_events(rng, count, start_ts, end_ts):
    """Ordinary activity from a fixed population: each host has one user and uses the same services.
    Returns (timestamp, source, fields). The population is sized so this stays below every threshold."""
    population = max(20, count // 40)
    events = []
    for _ in range(count):
        when = rng.uniform(start_ts, end_ts)
        index = rng.randrange(population)
        src, user, host = f'10.90.{index // 250}.{index % 250 + 1}', f'user{index:04d}', f'wks-n{index:04d}'
        kind = rng.random()
        if kind < 0.25:
            # A mistyped password now and then, then the same person from the same place
            ok = rng.random() > 0.02
            fields = _auth(0, ok, src, user, host)
        elif kind < 0.55:
            fields = (0, 'application', {'event_type': 'http_request', 'src_ip': src, 'user': user, 'hostname': 'intranet-01',
                                         'method': 'GET', 'endpoint': rng.choice(('/home', '/reports', '/search', '/profile')),
                                         'status_code': 200, 'details': 'Page view'})
        elif kind < 0.75:
            name, command = rng.choice(BENIGN_PROCESSES)
            fields = _proc(0, host, user, name, command)
        else:
            destination = f'198.51.100.{rng.randint(40, 49)}'
            fields = _conn(0, host, src, destination, 443, rng.randint(500, 200000), protocol='HTTPS')
        events.append((when, fields[1], fields[2]))
    return events


MAX_FEED_TEST_CONTACTS = 200
_FEED_RULES = {'ip': 'IOC-IP', 'domain': 'IOC-DOMAIN', 'url': 'IOC-URL', 'file_hash': 'IOC-HASH'}


def _contact(indicator, rng, index):
    """One synthetic log of an internal host touching this indicator. Nothing is sent to it."""
    host_index = index % 3
    host, src, user = f'wks-c{host_index:02d}', f'10.92.0.{host_index + 10}', f'user-c{host_index:02d}'
    value, kind = indicator['value'], indicator['ioc_type']
    if kind == 'file_hash':
        return _proc(0, host, user, 'update.exe', 'update.exe --silent', details='File with a known hash ran') + ({'file_hash': value},)
    if kind == 'ip':
        return _conn(0, host, src, value, 443, rng.randint(2000, 200000), protocol='HTTPS') + ({},)
    extra = {'domain': value} if kind == 'domain' else {'url': value}
    return _conn(0, host, src, '192.0.2.200', 443, rng.randint(2000, 200000), protocol='HTTPS') + (extra,)


def generate_feed_test(indicators, count, duration_seconds, seed, batch_id, contacts=25, end_time=None):
    """Normal synthetic logs with a sample of a feed's indicators planted in them, labelled so that the
    result can be scored. Returns (rows as generate_dataset does, the rules expected to fire)."""
    if not indicators:
        raise ValueError('This feed has no indicators to test')
    if not 1 <= count <= MAX_GENERATED_EVENTS:
        raise ValueError(f'Event count must be between 1 and {MAX_GENERATED_EVENTS}')
    if not 60 <= duration_seconds <= 30 * 86400:
        raise ValueError('Duration must be between 60 seconds and 30 days')
    if not 1 <= contacts <= MAX_FEED_TEST_CONTACTS:
        raise ValueError(f'Planted indicators must be between 1 and {MAX_FEED_TEST_CONTACTS}')
    rng = random.Random(seed)
    end_ts = (end_time or datetime.now(timezone.utc)).timestamp()
    start_ts = end_ts - duration_seconds
    planted = rng.sample(sorted(indicators, key=lambda item: (item['ioc_type'], item['value'])), min(contacts, len(indicators)))

    rows = []
    for index, indicator in enumerate(planted):
        _, source, fields, extra = _contact(indicator, rng, index)
        rows.append((rng.uniform(start_ts, end_ts), source, {**fields, **extra}, 'malicious', 'feed_indicator'))
    for when, source, fields in normal_events(rng, max(0, count - len(rows)), start_ts, end_ts):
        rows.append((when, source, fields, 'normal', None))
    rows.sort(key=lambda row: row[0])
    built = []
    for sequence, (when, source, fields, label, attack) in enumerate(rows):
        raw = {key: value for key, value in fields.items() if value is not None}
        raw['timestamp'] = datetime.fromtimestamp(when, timezone.utc).isoformat()
        raw['event_id'] = f'{batch_id}-{sequence:06d}'
        raw['synthetic'] = True
        built.append((raw, source, label, attack))
    return built, sorted({_FEED_RULES[item['ioc_type']] for item in planted})


def generate_dataset(profile, count, duration_seconds, seed, batch_id, end_time=None):
    """Build a labelled dataset. The same profile, count, duration and seed give the same events
    relative to end_time. Returns a list of (raw, source, label, attack_type) in time order."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile. Choose one of: {', '.join(PROFILES)}")
    if not 1 <= count <= MAX_GENERATED_EVENTS:
        raise ValueError(f'Event count must be between 1 and {MAX_GENERATED_EVENTS}')
    if not 60 <= duration_seconds <= 30 * 86400:
        raise ValueError('Duration must be between 60 seconds and 30 days')

    rng = random.Random(seed)
    end_time = end_time or datetime.now(timezone.utc)
    end_ts = end_time.timestamp()
    start_ts = end_ts - duration_seconds

    rows = []
    for name in PROFILES[profile]['attacks']:
        definition = _definition(name)
        block = sorted(definition['build'](), key=lambda item: item[0])
        last_offset = block[-1][0]
        # The whole attack ends inside the dataset's time span, at a place the seed decides
        finish = rng.uniform(start_ts + min(last_offset, duration_seconds * 0.5), end_ts)
        for offset, source, fields in block:
            rows.append((finish - (last_offset - offset), source, fields, event_label(definition, offset), name))

    for when, source, fields in normal_events(rng, max(0, count - len(rows)), start_ts, end_ts):
        rows.append((when, source, fields, 'normal', None))

    rows.sort(key=lambda row: row[0])
    built = []
    for sequence, (when, source, fields, label, attack) in enumerate(rows):
        raw = {key: value for key, value in fields.items() if value is not None}
        raw['timestamp'] = datetime.fromtimestamp(when, timezone.utc).isoformat()
        raw['event_id'] = f'{batch_id}-{sequence:06d}'
        raw['synthetic'] = True
        built.append((raw, source, label, attack))
    return built
