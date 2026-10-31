import datetime
import functools
import ipaddress
import json
import re
import uuid
from urllib.parse import urlsplit

# Address space treated as internal. Everything else that parses as an IP is external,
# including the RFC 5737 documentation ranges used by the synthetic scenarios.
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
    '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
)]

VALID_SOURCES = {'application', 'network', 'endpoint'}
SOURCE_ALIASES = {
    'app': 'application', 'http': 'application', 'web': 'application', 'auth': 'application',
    'host': 'endpoint', 'edr': 'endpoint', 'process': 'endpoint',
    'net': 'network', 'flow': 'network', 'firewall': 'network', 'pcap': 'network',
}

# Canonical field -> accepted input names. The stored column names predate this schema:
# source=source_type, src_ip=source_ip, dst_ip=destination_ip, src_port=source_port,
# dst_port=destination_port, user=username, method=http_method, status_code=status,
# ppid=parent_process_id.
FIELD_ALIASES = {
    'timestamp': ('timestamp', '@timestamp', 'time', 'ts', 'event_time', 'datetime', 'date', 'timestamp_utc', 'event_timestamp', 'eventtime',
                  'event_date', 'created_at', 'log_time', 'logtime', 'date_time', 'time_stamp', 'received_at', 'generated_at', 'occurred_at', 'start_time', '_time'),
    'event_type': ('event_type', 'action', 'eventtype', 'type', 'event_name', 'eventname', 'event', 'activity', 'operation', 'event_action'),
    'src_ip': ('src_ip', 'source_ip', 'srcip', 'client_ip', 'remote_addr', 'ip', 'src_addr', 'src_address', 'source_address', 'source_ip_address', 'sourceipaddress',
               'source_ipaddress', 'client_address', 'clientip', 'c_ip', 'attacker_ip', 'remote_ip', 'remote_address', 'ip_address', 'ipaddress', 'sip'),
    'dst_ip': ('dst_ip', 'destination_ip', 'dest_ip', 'dstip', 'server_ip', 'dst_addr', 'dst_address', 'destination_address', 'dest_address', 'destination_ip_address',
               'destination_ipaddress', 'target_ip', 'server_address', 'victim_ip', 'dip', 's_ip'),
    'src_port': ('src_port', 'source_port', 'sport', 'client_port'),
    'dst_port': ('dst_port', 'destination_port', 'dest_port', 'dport', 'target_port', 'server_port', 'service_port'),
    'user': ('user', 'username', 'user_id', 'userid', 'account', 'user_name', 'login', 'account_name', 'actor', 'principal', 'usr', 'user_information', 'cs_username'),
    'hostname': ('hostname', 'host', 'computer', 'device', 'host_name', 'device_name', 'machine', 'server', 'server_name', 'computer_name', 'node', 'workstation'),
    'process_name': ('process_name', 'process', 'image', 'process_path', 'processname', 'exe', 'executable', 'program'),
    'process_id': ('process_id', 'pid'),
    'ppid': ('ppid', 'parent_process_id'),
    'parent_process_name': ('parent_process_name', 'parent_process', 'parent_image', 'parent_process_path'),
    'command_line': ('command_line', 'cmdline', 'command', 'commandline', 'cmd', 'process_command_line'),
    'file_path': ('file_path', 'path_on_disk', 'file', 'filename', 'file_name', 'filepath'),
    'file_hash': ('file_hash', 'sha256', 'sha1', 'md5', 'hash', 'md5_hash', 'sha256_hash', 'file_md5', 'file_sha256', 'hash_value'),
    'registry_key': ('registry_key',),
    'domain': ('domain', 'dns_query', 'query', 'domain_name', 'dns_name', 'fqdn', 'qname', 'rrname'),
    'url': ('url', 'request_url', 'full_url'),
    'method': ('method', 'http_method', 'request_method', 'verb', 'cs_method'),
    'endpoint': ('endpoint', 'path', 'uri', 'request_path', 'resource', 'cs_uri_stem', 'uri_path'),
    'status_code': ('status_code', 'status', 'http_status', 'response_code', 'http_status_code', 'statuscode', 'sc_status', 'response_status', 'http_code'),
    'user_agent': ('user_agent', 'ua', 'useragent', 'http_user_agent'),
    'session_id': ('session_id', 'session', 'sessionid', 'session_key'),
    'auth_result': ('auth_result', 'login_result', 'authentication_result'),
    'protocol': ('protocol', 'proto', 'transport', 'protocol_name', 'ip_protocol', 'network_protocol'),
    'bytes': ('bytes', 'size', 'length', 'bytes_transferred', 'data_size', 'transfer_size', 'total_bytes', 'data_transferred', 'octets', 'byte_count', 'packet_length'),
    'bytes_in': ('bytes_in', 'bytes_received', 'received_bytes', 'rcvdbyte', 'resp_bytes', 'in_bytes', 'dst_bytes', 'dbytes', 'incoming_bytes', 'download_bytes'),
    'bytes_out': ('bytes_out', 'bytes_sent', 'sent_bytes', 'sentbyte', 'orig_bytes', 'out_bytes', 'src_bytes', 'sbytes', 'outgoing_bytes', 'upload_bytes', 'bytes_uploaded'),
    'payload_size': ('payload_size',),
    'packet_count': ('packet_count', 'packets', 'pkts'),
    'duration': ('duration', 'flow_duration', 'dur', 'time_taken'),
    'connection_status': ('connection_status', 'conn_state', 'connection_state', 'tcp_state'),
    'flags': ('flags', 'tcp_flags'),
    'geo_location': ('geo_location', 'geo_location_data'),
    'details': ('details', 'message', 'msg', 'content', 'log', 'text', 'event_message', 'log_message', 'description', 'summary', 'raw', '_raw', 'raw_log', 'info'),
    'event_id': ('event_id',),
}
SOURCE_KEYS = ('source', 'source_type')
_KNOWN_KEYS = {alias for aliases in FIELD_ALIASES.values() for alias in aliases} | set(SOURCE_KEYS)

EVENT_TYPE_ALIASES = {
    'failed_login': 'authentication_failure', 'login_failed': 'authentication_failure',
    'failed_logon': 'authentication_failure', 'auth_failure': 'authentication_failure',
    'login_failure': 'authentication_failure',
    'failed_password': 'authentication_failure', 'ssh_failed': 'authentication_failure', 'ssh_login_failed': 'authentication_failure',
    'authentication_failed': 'authentication_failure', 'auth_failed': 'authentication_failure', 'logon_failed': 'authentication_failure',
    'login_fail': 'authentication_failure', 'failedlogin': 'authentication_failure', 'invalid_login': 'authentication_failure', 'logon_failure': 'authentication_failure',
    'login': 'authentication_success', 'logon': 'authentication_success',
    'login_success': 'authentication_success', 'auth_success': 'authentication_success',
    'successful_login': 'authentication_success', 'login_successful': 'authentication_success', 'logon_success': 'authentication_success',
    'authentication_successful': 'authentication_success',
    'flow': 'network_connection', 'netflow': 'network_connection', 'conn': 'network_connection', 'connection': 'network_connection', 'network_flow': 'network_connection',
    'http': 'http_request', 'web_request': 'http_request', 'web_access': 'http_request', 'dns': 'dns_query',
}

# An event type that only says a login happened: the record's result says which way it went
_LOGIN_WORDS = {'login', 'logon', 'signin', 'sign_in', 'authentication', 'auth', 'ssh', 'ssh_login', 'user_login', 'login_attempt', 'logon_attempt', 'auth_attempt',
                'authentication_attempt', 'consolelogin', 'access_attempt', 'user.session.start'}
# A log that itself says an attack happened. ALLSAFE did not verify it, so a rule treats it as a report.
_REPORTED_THREAT = re.compile(r'^(alert|ids_alert|ips_alert|security_alert|threat|threat_detected|intrusion|intrusion_detected|signature_match|malware|malware_detected|virus|'
                              r'virus_detected|ransomware|trojan|worm|botnet|exploit|exploit_attempt|sql_injection|sqli|xss|cross_site_scripting|command_injection|rce|phishing|ddos|'
                              r'dos|dos_attack|ddos_attack|port_scan|portscan|network_scan|scan_detected|brute_force|bruteforce|brute_force_attack|credential_stuffing|password_spray|'
                              r'data_exfiltration|exfiltration|lateral_movement|c2|c2_communication|beacon|beaconing|suspicious|suspicious_activity|anomaly|attack|web_attack)$')

EVENT_CATEGORIES = {
    'authentication_failure': 'authentication', 'authentication_success': 'authentication',
    'logout': 'authentication', 'privilege_escalation': 'privilege',
    'privilege_granted': 'privilege', 'account_created': 'account',
    'process_start': 'process', 'process_stop': 'process', 'memory_access': 'process',
    'file_create': 'file', 'file_access': 'file', 'file_upload': 'file',
    'registry_access': 'registry',
    'high_cpu': 'system', 'high_memory': 'system', 'high_disk': 'system',
    'high_cpu_process': 'system', 'high_memory_process': 'system', 'high_cpu_system': 'system',
    'high_memory_system': 'system', 'high_disk_system': 'system', 'system_heartbeat': 'system',
    'ids_alert': 'alert', 'log_message': 'log', 'dns_query': 'network', 'firewall_block': 'network', 'firewall_allow': 'network',
}

_LOGIN_PATH = re.compile(r'(login|signin|sign-in|logon|/auth|/session)', re.IGNORECASE)
_HEX_HASH = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$')
_MAX_TEXT = 4096


class NormalizationError(ValueError):
    """Raised in strict mode when a record cannot become a valid event"""


@functools.lru_cache(maxsize=4096)
def normal_name(key):
    """A field name in one spelling: 'Source IP', 'source-ip' and 'sourceIp' are all source_ip"""
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', str(key).strip())
    return re.sub(r'[\s-]+', '_', text).lower()


# Day and month order cannot be told apart in 3/7/2017. Month first is tried first, as Windows exports write it.
_DATE_FORMATS = (
    '%d/%b/%Y:%H:%M:%S %z', '%Y-%m-%d %H:%M:%S,%f', '%Y/%m/%d %H:%M:%S', '%Y/%m/%d %H:%M:%S.%f',
    '%m/%d/%Y %I:%M:%S %p', '%m/%d/%Y, %I:%M:%S %p', '%m/%d/%Y %H:%M:%S', '%m/%d/%Y %H:%M', '%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M', '%d-%m-%Y %H:%M:%S', '%d-%b-%Y %H:%M:%S',
    '%d %b %Y %H:%M:%S', '%a %b %d %H:%M:%S %Y', '%a %b %d %H:%M:%S.%f %Y', '%a, %b %d %H:%M:%S %Y', '%b %d %Y %H:%M:%S', '%b %d, %Y %H:%M:%S', '%b %d %Y %I:%M:%S %p',
    '%y%m%d %H%M%S', '%Y%m%d %H%M%S', '%Y%m%dT%H%M%S', '%a, %d %b %Y %H:%M:%S %z', '%a, %d %b %Y %H:%M:%S %Z', '%Y-%m-%d %H:%M:%S %z', '%Y-%m-%d %H:%M:%S %Z',
)
# These carry no year, so the most recent occurrence is assumed
_YEARLESS_FORMATS = ('%b %d %H:%M:%S', '%m/%d-%H:%M:%S.%f', '%m/%d-%H:%M:%S', '%m-%d %H:%M:%S.%f')
_DIRECTIVE_SHAPES = {'Y': r'\d{4}', 'y': r'\d{2}', 'f': r'\d{1,6}', 'd': r'\s?\d{1,2}', 'm': r'\s?\d{1,2}',
                     'H': r'\d{1,2}', 'I': r'\d{1,2}', 'M': r'\d{1,2}', 'S': r'\d{1,2}',
                     'a': r'[a-z]+', 'A': r'[a-z]+', 'b': r'[a-z]+', 'B': r'[a-z]+', 'p': r'[a-z]+'}


def _quick_test(fmt):
    """A cheap check of whether text could fit a date format, and never stricter than strptime.

    strptime rebuilds its pattern for nearly every format it tries, so rejecting some thirty
    formats for each log was most of the time spent reading a file.
    """
    pieces = []
    for piece in re.split(r'(%.)', fmt):
        if piece.startswith('%'):
            pieces.append(_DIRECTIVE_SHAPES.get(piece[1], '.*?'))
        else:
            pieces.append(r'\s+'.join(re.escape(part) for part in re.split(r'\s+', piece)))
    return re.compile(''.join(pieces), re.IGNORECASE)


_DATE_TESTS = tuple((fmt, _quick_test(fmt)) for fmt in _DATE_FORMATS)


def parse_timestamp(value):
    """Parse the supported timestamp formats into an aware UTC datetime, or None.

    Naive values are treated as local time because that is what the collectors emit.
    """
    if value is None or value == '':
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        try:
            return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if re.fullmatch(r'\d{9,13}(\.\d+)?', text):
        return parse_timestamp(float(text))
    parsed = None
    try:
        parsed = datetime.datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        for fmt, could_fit in _DATE_TESTS:
            if not could_fit.fullmatch(text):
                continue
            try:
                parsed = datetime.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        # Syslog carries no year: assume the most recent occurrence
        now = datetime.datetime.now()
        for fmt in _YEARLESS_FORMATS:
            try:
                parsed = datetime.datetime.strptime(f'{now.year} {text}', f'%Y {fmt}')
            except ValueError:
                continue
            if parsed > now + datetime.timedelta(days=1):
                parsed = parsed.replace(year=now.year - 1)
            break
        if parsed is None:
            return None
    # Digits read as a date from the year 811 are not a date. Windows also cannot convert times before 1970.
    if parsed.year < 1971:
        return None
    try:
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def clean_ip(value):
    """Return the canonical text form of an IP address, or None if it is not one"""
    if value is None:
        return None
    text = str(value).strip()
    if text.startswith('[') and ']' in text:
        text = text[1:text.index(']')]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(address, 'ipv4_mapped', None)
    return str(mapped or address)


def is_internal_ip(value):
    """True for internal addresses, False for external ones, None if not an IP"""
    cleaned = clean_ip(value)
    if cleaned is None:
        return None
    address = ipaddress.ip_address(cleaned)
    return any(address.version == net.version and address in net for net in INTERNAL_NETWORKS)


def _first(raw, aliases):
    for key in aliases:
        value = raw.get(key)
        if value not in (None, ''):
            return value
    return None


def _as_int(value, minimum=0, maximum=None):
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    if number < minimum or (maximum is not None and number > maximum):
        return None
    return number


def _as_text(value):
    if value is None:
        return None
    return str(value)[:_MAX_TEXT]


def _resolve_source(raw, source, strict):
    candidate = _first(raw, SOURCE_KEYS) if source is None else source
    candidate = str(candidate or '').strip().lower()
    candidate = SOURCE_ALIASES.get(candidate, candidate)
    if candidate in VALID_SOURCES:
        return candidate
    if strict:
        raise NormalizationError(f"unknown or missing log source: {candidate or 'none'}")
    return 'application'


def _resolve_event_type(raw_type, source, method, endpoint, status_code, auth_result, outcome=None):
    event_type = str(raw_type or '').strip().lower().replace(' ', '_').replace('-', '_')
    if event_type in _LOGIN_WORDS and outcome in ('success', 'failure'):
        return 'authentication_success' if outcome == 'success' else 'authentication_failure'
    if _REPORTED_THREAT.match(event_type):
        return 'ids_alert'
    event_type = EVENT_TYPE_ALIASES.get(event_type, event_type)
    generic = event_type in ('', 'info', 'http_request', 'api_access', 'request')
    if generic and auth_result in ('success', 'failure'):
        return 'authentication_success' if auth_result == 'success' else 'authentication_failure'
    # A POST to a login path with an auth status is an authentication event in web logs
    if generic and method == 'POST' and endpoint and status_code and _LOGIN_PATH.search(endpoint):
        if status_code in (401, 403):
            return 'authentication_failure'
        if status_code in (200, 201, 204, 302):
            return 'authentication_success'
    if generic and source == 'network':
        return 'network_connection'
    if generic and source == 'application' and method:
        return 'http_request'
    return event_type or 'info'


def _categorize(event_type, source):
    if event_type in EVENT_CATEGORIES:
        return EVENT_CATEGORIES[event_type]
    return {'network': 'network', 'endpoint': 'host', 'application': 'web'}[source]


def normalize_log(raw_log, source=None, origin='live', ingest_batch=None, strict=False):
    """
    Normalize different log sources into a common schema.

    The original record is preserved in raw_event, and any field outside the schema is
    kept in normalized_fields. Invalid optional values become NULL with a note rather
    than being stored. strict=True (uploads) rejects a record without a usable timestamp.

    A source parser may pass the untouched record as _original, and _timestamp_optional for
    flow files that have no times: such an event is stored with no event time, because a
    time must never be made up. Its timestamp column then holds the ingestion time, with a note.
    """
    if not isinstance(raw_log, dict):
        raise NormalizationError('record is not an object')

    now = datetime.datetime.now(datetime.timezone.utc)
    notes = []
    resolved_source = _resolve_source(raw_log, source, strict)
    get = lambda field: _first(raw_log, FIELD_ALIASES[field])

    raw_timestamp = get('timestamp')
    parsed_time = parse_timestamp(raw_timestamp)
    has_event_time = True
    if parsed_time is None:
        if raw_log.get('_timestamp_optional') and not raw_timestamp:
            notes.append('timestamp_missing_in_source')
            has_event_time = False
        elif strict:
            raise NormalizationError(f'missing or unparseable timestamp: {raw_timestamp!r}')
        elif raw_timestamp:
            notes.append('timestamp_unparseable')
        parsed_time = now

    def checked_ip(field):
        value = get(field)
        cleaned = clean_ip(value)
        if value is not None and cleaned is None:
            notes.append(f'{field}_invalid')
        return cleaned

    def checked_int(field, maximum=None):
        value = get(field)
        number = _as_int(value, 0, maximum)
        if value is not None and number is None:
            notes.append(f'{field}_invalid')
        return number

    url = _as_text(get('url'))
    endpoint = _as_text(get('endpoint'))
    domain = _as_text(get('domain'))
    if url:
        parts = urlsplit(url if '//' in url else f'//{url}')
        endpoint = endpoint or parts.path or None
        domain = domain or parts.hostname
    domain = domain.lower().rstrip('.') if domain else None

    method = get('method')
    method = str(method).upper()[:16] if method else None
    status_code = checked_int('status_code', 999)
    auth_result = get('auth_result')
    auth_result = str(auth_result).lower() if auth_result else None

    event_type = _resolve_event_type(get('event_type'), resolved_source, method, endpoint, status_code, auth_result, raw_log.get('_outcome'))
    if event_type == 'authentication_failure':
        auth_result = 'failure'
    elif event_type == 'authentication_success':
        auth_result = 'success'

    file_hash = get('file_hash')
    if file_hash is not None:
        file_hash = str(file_hash).strip().lower()
        if not _HEX_HASH.match(file_hash):
            notes.append('file_hash_invalid')
            file_hash = None

    src_ip = checked_ip('src_ip')
    dst_ip = checked_ip('dst_ip')
    bytes_total = checked_int('bytes')
    bytes_out = checked_int('bytes_out')
    if bytes_out is None and resolved_source == 'network' and bytes_total:
        # Without an explicit direction, internal-to-external traffic counts as outbound
        if is_internal_ip(src_ip) and is_internal_ip(dst_ip) is False:
            bytes_out = bytes_total

    extras = {key: value for key, value in raw_log.items() if key not in _KNOWN_KEYS and not key.startswith('_')}
    if event_type == 'ids_alert' and get('event_type') and str(get('event_type')).lower() != 'ids_alert':
        extras['reported_as'] = str(get('event_type'))
    if notes:
        extras['validation_notes'] = notes

    event_id = get('event_id')
    return {
        'event_id': _as_text(event_id) if event_id else str(uuid.uuid4()),
        'source': resolved_source,
        'event_type': event_type,
        'event_category': _categorize(event_type, resolved_source),
        'timestamp': parsed_time.isoformat(),
        'ts_epoch': parsed_time.timestamp() if has_event_time else None,
        'ingestion_timestamp': now.isoformat(),
        'origin': origin,
        'ingest_batch': ingest_batch,
        'user': _as_text(get('user')),
        'hostname': _as_text(get('hostname')),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': checked_int('src_port', 65535),
        'dst_port': checked_int('dst_port', 65535),
        'protocol': _as_text(get('protocol')),
        'bytes': bytes_total,
        'bytes_in': checked_int('bytes_in'),
        'bytes_out': bytes_out,
        'packet_count': checked_int('packet_count'),
        'duration': _as_float(get('duration')),
        'connection_status': _as_text(get('connection_status')),
        'flags': _as_text(get('flags')),
        'process_name': _as_text(get('process_name')),
        'process_id': checked_int('process_id'),
        'ppid': checked_int('ppid'),
        'parent_process_name': _as_text(get('parent_process_name')),
        'command_line': _as_text(get('command_line')),
        'file_path': _as_text(get('file_path')),
        'file_hash': file_hash,
        'registry_key': _as_text(get('registry_key')),
        'domain': domain,
        'url': url,
        'method': method,
        'endpoint': endpoint,
        'status_code': status_code,
        'payload_size': checked_int('payload_size'),
        'user_agent': _as_text(get('user_agent')),
        'session_id': _as_text(get('session_id')),
        'auth_result': auth_result,
        'geo_location': _as_text(get('geo_location')),
        'details': _as_text(get('details')) or '',
        'raw_event': json.dumps(raw_log.get('_original', raw_log), default=str),
        'normalized_fields': json.dumps(extras, default=str) if extras else None,
    }


def _as_float(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 and number != float('inf') else None
