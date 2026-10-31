"""Reads the common log formats, so that a real log file gives a result rather than a refusal.

Each reader only reports what the line or record states. A field that is not there stays absent, and a
line with nothing but a time and a message is still kept as a text event, because a verdict that says
what could not be evaluated is more useful than a file that was turned away.
"""
import gzip
import io
import json
import re
import zipfile

from utils.normalizer import FIELD_ALIASES, clean_ip, normal_name, parse_timestamp

_ADDRESS = r'\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\]?'

_AUTH_FAILED = re.compile(r'failed password|failed publickey|failed keyboard|failed none|authentication failure|authentication failed|auth(?:entication)? fail|'
                          r'login failed|failed login|login failure|logon failure|failed logon|failed to log ?on|invalid user|invalid password|'
                          r'wrong password|incorrect password|bad password|access denied for user|unauthorized login|login incorrect', re.IGNORECASE)
_AUTH_OK = re.compile(r'accepted (?:password|publickey|keyboard)|login succeeded|login successful|successful login|successfully logged in|'
                      r'authentication succeeded|logged on successfully', re.IGNORECASE)
_SOURCE_AT = tuple(re.compile(pattern + _ADDRESS, re.IGNORECASE) for pattern in (
    r'\bfrom\s+', r'\brhost=', r'\bclient[:= ]+\s*', r'\bsource network address:\s*', r'\bsrc(?:ip)?[:= ]+\s*/?', r'\bremote(?: address| addr|_addr)?[:= ]+\s*',
    r'\bip address:\s*', r'\bfor \S+ '))
_TARGET_AT = tuple(re.compile(pattern + _ADDRESS, re.IGNORECASE) for pattern in (r'\bdest(?:ination)?[:= ]+\s*/?', r'\bdst(?:ip)?[:= ]+\s*/?'))
_USER_AT = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r'\bfor invalid user\s+([\w.@$\\-]+)', r'\binvalid user\s+([\w.@$\\-]+)', r'\bfor user\s+"?([\w.@$\\-]+)', r'\bfor\s+([\w.@$\\-]+)\s+from\b',
    r'(?<![a-z])user[= ]+"?([\w.@$\\-]+)', r'\baccount name:\s*([\w.@$\\-]+)', r'\busername[=: ]+"?([\w.@$\\-]+)'))
_NOT_USERS = {'invalid', 'user', 'from', 'unknown', 'root:', '-', 'for', 'name', 'by', 'is', 'was', 'not'}
_PORT_AT = re.compile(r'\bport[ =:]+(\d{1,5})', re.IGNORECASE)
_PAIRS = re.compile(r'([\w.-]+)=("[^"]*"|[^\s,;]+)')
_LEVEL = re.compile(r'^\W*(EMERG|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO|DEBUG|TRACE|FATAL|SEVERE)\b[\s:,\]\-|]*', re.IGNORECASE)

_BSD_SYSLOG = re.compile(r'^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^\s:\[(]+)(?:\(([^)]*)\))?(?:\[(\d+)\])?:? ?(.*)$')
_RFC5424 = re.compile(r'^<\d{1,3}>\d+ (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+) ?(.*)$')
_APACHE_ERROR = re.compile(r'^\[(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[([\w:]+)\](?: \[pid \d+(?::tid \d+)?\])?(?: \[client (\S+?)(?::\d+)?\])? ?(.*)$')
_NGINX_ERROR = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#\d+: (?:\*\d+ )?(.*)$')
_SNORT_FAST = re.compile(r'^(\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\[\*\*\]\s+\[[\d:]+\]\s+(.*?)\s+\[\*\*\]'
                         r'(?:\s+\[Classification: ([^\]]*)\])?(?:\s+\[Priority: (\d+)\])?\s+\{(\w+)\}\s+(\S+?)(?::(\d+))?\s+->\s+(\S+?)(?::(\d+))?\s*$')
_REQUEST = re.compile(r'request: "([A-Z]+) (\S+)', re.IGNORECASE)
_LEADING_TIMES = tuple(re.compile(pattern) for pattern in (
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s?(?:Z|UTC|[+-]\d{2}:?\d{2}))?)[,\s|:\-]+(.*)$',
    r'^(\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)[,\s|:\-]+(.*)$',
    r'^\[(\d{4}-\d{2}-\d{2}[T ][\d:.,]+(?:Z|[+-]\d{2}:?\d{2})?)\]\s*(.*)$',
    r'^\[?(\d{1,2}/\d{1,2}/\d{4},? \d{1,2}:\d{2}:\d{2}(?: ?[AP]M)?)\]?[,\s|:\-]+(.*)$',
    r'^(\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})\S*\s+(.*)$',
    r'^\[(\w{3},? \w{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s*(.*)$',
    r'^(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s+(.*)$',
    r'^(\d{6} \d{6})\s+(.*)$',
    r'^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(.*)$',
    r'^(\d{10}(?:\.\d+)?)\s+(.*)$',
))


def _first_address(text, patterns):
    for pattern in patterns:
        for match in pattern.finditer(text):
            address = clean_ip(match.group(1))
            if address:
                return address
    return None


def message_facts(message):
    """What a free-text message states: whether a login failed or worked, who, and from where"""
    text = str(message or '')
    facts = {}
    if _AUTH_FAILED.search(text):
        facts['event_type'] = 'authentication_failure'
    elif _AUTH_OK.search(text):
        facts['event_type'] = 'authentication_success'
    source = _first_address(text, _SOURCE_AT)
    if source:
        facts['src_ip'] = source
        port = _PORT_AT.search(text)
        if port:
            facts['src_port'] = port.group(1)
    target = _first_address(text, _TARGET_AT)
    if target:
        facts['dst_ip'] = target
    if 'event_type' in facts:
        for pattern in _USER_AT:
            match = pattern.search(text)
            if match and match.group(1).lower().strip('.,;:') not in _NOT_USERS:
                facts['user'] = match.group(1).strip('.,;:"')
                break
    return facts


def _key_values(text):
    pairs = {key: value.strip('"') for key, value in _PAIRS.findall(text)}
    return pairs if len(pairs) >= 3 else {}


def _text_event(timestamp, message, **known):
    """A record for a line that has a time and a message, with whatever else the message states"""
    record = {'timestamp': timestamp, 'details': message, **{key: value for key, value in known.items() if value not in (None, '', '-')}}
    facts = message_facts(message)
    for key, value in facts.items():
        record.setdefault(key, value)
    record.setdefault('event_type', 'log_message')
    return record


def _parse_cef(line):
    position = line.find('CEF:')
    if position < 0:
        return None
    parts = line[position:].split('|', 7)
    if len(parts) < 8:
        return None
    _, _, product, _, signature, name, severity, extension = parts
    fields = {key: value.strip() for key, value in re.findall(r'(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|\s*$)', extension)}
    prefix = re.match(r'^(?:<\d+>)?(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})', line)
    record = {'timestamp': fields.get('rt') or fields.get('receiptTime') or fields.get('start') or (prefix.group(1) if prefix else None),
              'src_ip': fields.get('src') or fields.get('sourceAddress'), 'dst_ip': fields.get('dst') or fields.get('destinationAddress'),
              'src_port': fields.get('spt') or fields.get('sourcePort'), 'dst_port': fields.get('dpt') or fields.get('destinationPort'),
              'protocol': fields.get('proto') or fields.get('transportProtocol'), 'user': fields.get('suser') or fields.get('sourceUserName') or fields.get('duser'),
              'hostname': fields.get('shost') or fields.get('sourceHostName') or fields.get('dvchost') or fields.get('dhost'),
              'bytes_in': fields.get('in') or fields.get('bytesIn'), 'bytes_out': fields.get('out') or fields.get('bytesOut'),
              'url': fields.get('request'), 'method': fields.get('requestMethod'), 'file_path': fields.get('fname'), 'file_hash': fields.get('fileHash'),
              'process_name': fields.get('sproc'), 'details': f"{name}: {fields['msg']}" if fields.get('msg') else name, 'device_product': product, 'signature_id': signature}
    return _security_record(record, name, severity, fields.get('act') or fields.get('deviceAction'))


def _parse_leef(line):
    position = line.find('LEEF:')
    if position < 0:
        return None
    parts = line[position:].split('|', 5)
    if len(parts) < 6:
        return None
    version, _, product, _, event_id, rest = parts
    delimiter = '\t'
    if version.startswith('LEEF:2') and '|' in rest and len(rest.split('|', 1)[0]) <= 2:
        given, rest = rest.split('|', 1)
        delimiter = {'x09': '\t', '^': '^'}.get(given.strip(), given.strip() or '\t')
    fields = dict(pair.split('=', 1) for pair in rest.split(delimiter) if '=' in pair) if delimiter in rest else {key: value.strip('"') for key, value in _PAIRS.findall(rest)}
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    record = {'timestamp': fields.get('devTime') or fields.get('devTimeEpoch'), 'src_ip': fields.get('src') or fields.get('identSrc'), 'dst_ip': fields.get('dst'),
              'src_port': fields.get('srcPort'), 'dst_port': fields.get('dstPort'), 'protocol': fields.get('proto'), 'user': fields.get('usrName') or fields.get('accountName'),
              'hostname': fields.get('identHostName') or fields.get('srcHostName'), 'bytes_out': fields.get('srcBytes'), 'bytes_in': fields.get('dstBytes'),
              'url': fields.get('url'), 'details': fields.get('msg') or fields.get('cat') or event_id, 'device_product': product, 'signature_id': event_id}
    if event_id in ('4625', '4771', '4776'):
        record['event_type'] = 'authentication_failure'
    elif event_id == '4624':
        record['event_type'] = 'authentication_success'
    return _security_record(record, fields.get('cat') or event_id, fields.get('sev'), fields.get('action'))


def _security_record(record, name, severity, action):
    """A security product's own event: a firewall decision, a login, or an alert it raised"""
    record = {key: value for key, value in record.items() if value not in (None, '')}
    if not record.get('timestamp'):
        return None
    if 'event_type' not in record:
        facts = message_facts(f"{name} {record.get('details', '')}")
        if 'event_type' in facts:
            record['event_type'] = facts['event_type']
    words = str(action or '').strip().lower()
    if 'event_type' not in record and words:
        record['action'] = words
    if 'event_type' not in record and 'action' not in record:
        try:
            level = float(severity)
        except (TypeError, ValueError):
            level = 0
        record['event_type'] = 'ids_alert' if level >= 4 else 'log_message'
    return record, 'network'


def parse_line(line):
    """One line of a text log that the exact parsers did not recognize. Returns (record, source) or None."""
    if 'CEF:' in line[:200]:
        parsed = _parse_cef(line)
        if parsed:
            return parsed
    if 'LEEF:' in line[:200]:
        parsed = _parse_leef(line)
        if parsed:
            return parsed
    match = _RFC5424.match(line)
    if match:
        timestamp, host, app, pid, _, _, message = match.groups()
        record = _text_event(timestamp, message, hostname=host, process_name=app, process_id=pid)
        return record, 'application' if record['event_type'].startswith('authentication') else 'endpoint'
    match = _BSD_SYSLOG.match(line)
    if match:
        timestamp, host, process, _, pid, message = match.groups()
        record = _text_event(timestamp, message or line, hostname=host, process_name=process, process_id=pid)
        record['details'] = line
        return record, 'application' if record['event_type'].startswith('authentication') else 'endpoint'
    match = _APACHE_ERROR.match(line)
    if match:
        timestamp, level, client, message = match.groups()
        return _text_event(timestamp, message or line, level=level, src_ip=clean_ip(client) if client else None), 'application'
    match = _NGINX_ERROR.match(line)
    if match:
        timestamp, level, pid, message = match.groups()
        record = _text_event(timestamp, message, level=level, process_id=pid)
        request = _REQUEST.search(message)
        if request:
            record.update(method=request.group(1).upper(), endpoint=request.group(2))
        return record, 'application'
    match = _SNORT_FAST.match(line)
    if match:
        timestamp, signature, classification, priority, protocol, src, spt, dst, dpt = match.groups()
        return {'timestamp': timestamp, 'event_type': 'ids_alert', 'details': signature, 'classification': classification, 'priority': priority, 'protocol': protocol,
                'src_ip': src, 'src_port': spt, 'dst_ip': dst, 'dst_port': dpt}, 'network'
    for pattern in _LEADING_TIMES:
        match = pattern.match(line)
        if not match or parse_timestamp(match.group(1)) is None:
            continue
        timestamp, message = match.group(1), match.group(2)
        level = _LEVEL.match(message)
        known = {}
        if level:
            known['level'] = level.group(1).upper()
            message = message[level.end():]
        record = _text_event(timestamp, message or line, **known)
        for key, value in _key_values(message).items():
            record.setdefault(key, value)
        return record, 'application'
    return None


# ---------- Zeek logs and IIS W3C logs: the header says what the columns are ----------

_ZEEK_NAMES = {'ts': 'timestamp', 'id.orig_h': 'src_ip', 'id.orig_p': 'src_port', 'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port', 'proto': 'protocol', 'orig_bytes': 'bytes_out',
               'resp_bytes': 'bytes_in', 'duration': 'duration', 'orig_pkts': 'packet_count', 'uri': 'endpoint', 'method': 'method', 'status_code': 'status_code', 'user_agent': 'user_agent',
               'query': 'domain', 'username': 'user', 'msg': 'details', 'md5': 'file_hash', 'sha256': 'file_hash', 'server_name': 'domain'}
_ZEEK_NO_REPLY = {'S0', 'REJ', 'RSTOS0', 'RSTRH', 'SH', 'SHR'}
_W3C_NAMES = {'c-ip': 'src_ip', 's-ip': 'dst_ip', 's-port': 'dst_port', 'cs-method': 'method', 'cs-uri-stem': 'endpoint', 'cs-uri-query': 'query_string', 'cs-username': 'user',
              'cs(user-agent)': 'user_agent', 'sc-status': 'status_code', 'sc-bytes': 'bytes_out', 'cs-bytes': 'bytes_in', 'time-taken': 'duration', 's-computername': 'hostname',
              'x-forwarded-for': 'forwarded_for'}
_ZEEK_TYPES = {'conn': 'network_connection', 'http': 'http_request', 'dns': 'dns_query', 'notice': 'ids_alert', 'files': 'file_access'}


def is_directive_log(text):
    head = text[:4000].splitlines()[:16]
    return any(line.startswith(('#fields', '#Fields:')) for line in head)


def read_directive_log(text):
    """Returns (records, errors), in the same form as the other readers"""
    records, errors = [], []
    names, separator, path, w3c = None, '\t', None, False
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith('#'):
            if line.startswith('#separator'):
                value = line.split(' ', 1)[-1].strip()
                separator = bytes(value, 'utf-8').decode('unicode_escape') if value.startswith('\\') else value
            elif line.startswith('#path'):
                path = re.split(r'\s+', line, 1)[-1].strip()
            elif line.startswith('#fields'):
                names = line.split(separator)[1:]
            elif line.startswith('#Fields:'):
                names, separator, w3c = line[len('#Fields:'):].split(), ' ', True
            continue
        if not names:
            errors.append({'line': number, 'error': 'a row came before the header that names the columns'})
            continue
        values = line.split(separator)
        if len(values) != len(names):
            errors.append({'line': number, 'error': f'row has {len(values)} columns, and the header names {len(names)}'})
            continue
        row = {name: value for name, value in zip(names, values) if value not in ('-', '(empty)', '')}
        records.append(_from_w3c(row) if w3c else _from_zeek(row, path))
    return records, errors


def _from_zeek(row, path):
    record = {_ZEEK_NAMES.get(name, name): value for name, value in row.items()}
    state = row.get('conn_state')
    if state:
        record['connection_status'] = 'attempted' if state in _ZEEK_NO_REPLY else 'established'
    if path == 'ssh' and row.get('auth_success') in ('T', 'F'):
        record['event_type'] = 'authentication_success' if row['auth_success'] == 'T' else 'authentication_failure'
    else:
        record['event_type'] = _ZEEK_TYPES.get(path, f'zeek_{path or "event"}')
    return record, 'application' if path in ('http', 'ssh') else 'network'


def _from_w3c(row):
    lowered = {name.lower(): value for name, value in row.items()}
    record = {_W3C_NAMES.get(name, name): value for name, value in lowered.items() if name not in ('date', 'time')}
    if 'date' in lowered and 'time' in lowered:
        record['timestamp'] = f"{lowered['date']} {lowered['time']}"
    record['event_type'] = 'http_request'
    return record, 'application'


# ---------- JSON exports ----------

_WRAPPER_KEYS = ('events', 'Records', 'records', 'logs', 'log', 'data', 'items', 'results', 'entries', 'hits', 'value', 'rows', 'messages', 'alerts')
_MAX_DEPTH = 8


def unwrap_json(document):
    """The list of records in an export such as CloudTrail's {"Records": [...]} or Elasticsearch's hits"""
    for _ in range(4):
        if not isinstance(document, dict):
            break
        inner = next((document[key] for key in _WRAPPER_KEYS if isinstance(document.get(key), (list, dict)) and document.get(key)), None)
        if inner is None or (isinstance(inner, dict) and not any(key in inner for key in _WRAPPER_KEYS)):
            break
        document = inner
    if isinstance(document, dict):
        document = [document]
    if not isinstance(document, list):
        return document
    return [item['_source'] if isinstance(item, dict) and isinstance(item.get('_source'), dict) else item for item in document]


def flatten_record(record):
    """Nested fields under dotted names: {"source": {"ip": ...}} becomes {"source.ip": ...}"""
    flat = {}

    def walk(prefix, value, depth):
        if isinstance(value, dict) and depth < _MAX_DEPTH:
            for key, inner in value.items():
                walk(f'{prefix}.{key}' if prefix else str(key), inner, depth + 1)
        else:
            flat[prefix] = value
    walk('', record, 0)
    return flat


# ---------- Giving any record the common names ----------

_PATHS = {
    'source.ip': 'src_ip', 'source.address': 'src_ip', 'client.ip': 'src_ip', 'client.address': 'src_ip', 'client.ipaddress': 'src_ip', 'destination.ip': 'dst_ip', 'destination.address': 'dst_ip', 'server.ip': 'dst_ip',
    'source.port': 'src_port', 'client.port': 'src_port', 'destination.port': 'dst_port', 'server.port': 'dst_port',
    'user.name': 'user', 'user.id': 'user', 'actor.alternateid': 'user', 'host.name': 'hostname', 'host.hostname': 'hostname', 'agent.hostname': 'hostname', 'agent.name': 'hostname',
    'process.name': 'process_name', 'process.pid': 'process_id', 'process.command_line': 'command_line', 'process.executable': 'file_path', 'process.parent.name': 'parent_process_name',
    'url.full': 'url', 'url.original': 'url', 'url.path': 'endpoint', 'http.request.method': 'method', 'http.response.status_code': 'status_code', 'user_agent.original': 'user_agent',
    'dns.question.name': 'domain', 'dns.rrname': 'domain', 'tls.sni': 'domain', 'http.hostname': 'domain', 'http.url': 'endpoint', 'http.http_method': 'method', 'http.status': 'status_code', 'http.http_user_agent': 'user_agent',
    'file.path': 'file_path', 'file.hash.sha256': 'file_hash', 'file.hash.sha1': 'file_hash', 'file.hash.md5': 'file_hash',
    'network.transport': 'protocol', 'network.protocol': 'protocol', 'network.bytes': 'bytes', 'source.bytes': 'bytes_out', 'destination.bytes': 'bytes_in',
    'flow.bytes_toserver': 'bytes_out', 'flow.bytes_toclient': 'bytes_in', 'flow.pkts_toserver': 'packet_count', 'flow.state': 'connection_status', 'alert.signature': 'details',
    'event.action': 'event_type', 'event.type': 'event_type', 'published': 'timestamp', 'displaymessage': 'details', 'log.message': 'details',
    'winlog.event_id': 'eventid', 'event.code': 'eventid', 'winlog.computer_name': 'computer', 'event.system.eventid': 'eventid', 'event.system.eventid.#text': 'eventid', 'event.system.computer': 'computer',
    'event.system.timecreated.@systemtime': 'systemtime', 'system.eventid': 'eventid', 'system.computer': 'computer', 'system.timecreated.systemtime': 'systemtime',
}
_NESTED_WINDOWS_DATA = ('winlog.event_data.', 'event.eventdata.', 'eventdata.', 'event_data.', 'winlog.user_data.', 'event.userdata.')
_OUTCOME_FIELDS = ('event.outcome', 'outcome.result', 'outcome', 'result', 'login_result', 'login_status', 'auth_status', 'authentication_status', 'responseelements.consolelogin', 'success', 'status')
_FAILED_WORDS = {'fail', 'failed', 'failure', 'denied', 'deny', 'invalid', 'unauthorized', 'unauthorised', 'rejected', 'false', 'error', 'unsuccessful', 'incorrect'}
_SUCCESS_WORDS = {'success', 'succeeded', 'successful', 'ok', 'allowed', 'accepted', 'true', 'passed', 'valid'}
_PLACEHOLDERS = {'-', '--', 'n/a', 'na', 'none', 'null', 'nan', 'unknown', 'undefined', '(null)', '(empty)'}
_TIME_COLUMN = re.compile(r'time|date|stamp|created|generated|received|occurred|published|logged|_at$|^ts$', re.IGNORECASE)
_TEXT_COLUMNS = ('message', 'msg', 'details', 'content', 'log', 'text', 'event_message', 'log_message', 'description', 'summary', 'raw', '_raw', 'raw_log', 'info', 'display_message', 'event_description')
_GENERIC_TYPES = {'', 'info', 'log', 'log_message', 'event', 'syslog', 'security', 'audit', 'message', 'error', 'warning', 'notice', 'debug'}
_ALERT_COLUMNS = ('alert', 'alerts', 'alert_name', 'alerts/warnings', 'ids/ips_alerts', 'ids_alert', 'ids_alerts', 'threat', 'threat_name', 'signature', 'signature_name', 'malware_indicators', 'detection', 'detection_name', 'virus', 'malware')
_NOT_AN_ALERT = {'false', 'no', '0', 'clean', 'benign', 'normal', 'pass', 'ok', 'info', 'informational'}
_CLOUD_PRIVILEGE = re.compile(r'^(Attach\w*Policy|Put\w*Policy|AddUserToGroup|CreateAccessKey|UpdateAssumeRolePolicy|CreateLoginProfile)$')
_CLOUD_ACCOUNT = re.compile(r'^(CreateUser|CreateRole)$')


def _by_name(record):
    return {normal_name(key): key for key in record}


def _value(record, names, lookup):
    for name in names:
        key = lookup.get(name)
        if key is not None and record.get(key) not in (None, ''):
            return record[key]
    return None


def _fill_timestamp(adopted, lookup):
    """Times in separate columns are joined, and a time column with an unusual name is found"""
    time_value, date_value = _value(adopted, ('time', 'clock'), lookup), _value(adopted, ('date', 'day'), lookup)
    month = _value(adopted, ('month',), lookup)
    if time_value is not None and date_value is not None and parse_timestamp(time_value) is None:
        joined = f'{month} {date_value} {time_value}' if month else f'{date_value} {time_value}'
        if parse_timestamp(joined) is not None:
            adopted['timestamp'] = joined
            return
    if _value(adopted, FIELD_ALIASES['timestamp'], lookup) is not None and parse_timestamp(_value(adopted, FIELD_ALIASES['timestamp'], lookup)) is not None:
        return
    for name, key in lookup.items():
        value = adopted.get(key)
        if _TIME_COLUMN.search(name) and value not in (None, '') and parse_timestamp(value) is not None:
            adopted['timestamp'] = value
            return


def _adopt_cloud_audit(record, adopted, lookup):
    """AWS CloudTrail: an API call, or a console login"""
    name = _value(record, ('event_name',), lookup)
    if not name or not (_value(record, ('event_source', 'source_ipaddress', 'source_ip_address'), lookup) or _value(record, ('aws_region',), lookup)):
        return
    adopted.setdefault('timestamp', _value(record, ('event_time',), lookup))
    address = clean_ip(_value(record, ('source_ipaddress', 'source_ip_address'), lookup))
    if address:
        adopted['src_ip'] = address
    for key in list(adopted):
        if normal_name(key) in ('source_ipaddress', 'source_ip_address') and not address:
            adopted.pop(key)
    who = next((record[key] for key in record if key.lower() in ('useridentity.username', 'useridentity.arn', 'useridentity.principalid', 'useridentity.sessioncontext.sessionissuer.username') and record[key]), None)
    if who:
        adopted['user'] = str(who).rsplit('/', 1)[-1]
    if _CLOUD_PRIVILEGE.match(str(name)):
        adopted['event_type'] = 'privilege_granted'
    elif _CLOUD_ACCOUNT.match(str(name)):
        adopted['event_type'] = 'account_created'
    elif str(name) == 'ConsoleLogin':
        adopted['event_type'] = 'consolelogin'
    else:
        adopted['event_type'] = f'cloud_{name}'
    adopted['_log_type'] = 'cloud'


def adapt_record(record):
    """Give a record the common field names, using only what it holds. Returns a new dict."""
    adopted = {}
    for key, value in record.items():
        if isinstance(value, str) and value.strip().lower() in _PLACEHOLDERS:
            continue
        adopted[key] = value
    lookup = _by_name(adopted)
    lowered = {str(key).lower(): key for key in adopted}
    for path, name in _PATHS.items():
        key = lowered.get(path)
        if key is not None and adopted.get(key) not in (None, '') and adopted.get(name) in (None, ''):
            adopted[name] = adopted[key]
    for key in list(adopted):
        text = str(key).lower()
        prefix = next((item for item in _NESTED_WINDOWS_DATA if text.startswith(item)), None)
        if prefix:
            adopted.setdefault(str(key)[len(prefix):], adopted[key])
    # A nested object once named "source" must not be read as the name of a log source
    if isinstance(adopted.get('source'), (dict, list)):
        adopted.pop('source')
    lookup = _by_name(adopted)
    _adopt_cloud_audit(record, adopted, lookup)
    lookup = _by_name(adopted)
    _fill_timestamp(adopted, lookup)
    lookup = _by_name(adopted)

    request = _value(adopted, ('request',), lookup)
    if isinstance(request, str):
        match = re.match(r'^([A-Z]{3,7}) (\S+)', request)
        if match:
            adopted.setdefault('method', match.group(1))
            adopted.setdefault('endpoint', match.group(2))
            adopted.pop(lookup['request'], None)

    outcome = None
    names = {str(key).lower().replace(' ', '_').replace('-', '_'): key for key in adopted}
    for field in _OUTCOME_FIELDS:
        key = names.get(field)
        if key is None or adopted.get(key) in (None, ''):
            continue
        word = str(adopted[key]).strip().lower()
        if word in _FAILED_WORDS:
            outcome = 'failure'
        elif word in _SUCCESS_WORDS:
            outcome = 'success'
        if outcome:
            break
    if outcome:
        adopted['_outcome'] = outcome

    event_type = str(_value(adopted, FIELD_ALIASES['event_type'], lookup) or '').strip().lower()
    text = _value(adopted, _TEXT_COLUMNS, lookup)
    if text is not None and isinstance(text, str):
        facts = message_facts(text)
        if event_type in _GENERIC_TYPES and 'event_type' in facts:
            for alias in FIELD_ALIASES['event_type']:
                adopted.pop(alias, None)
            adopted['event_type'] = facts['event_type']
            event_type = facts['event_type']
        for field in ('src_ip', 'dst_ip', 'src_port', 'user'):
            if field in facts and _value(adopted, FIELD_ALIASES[field], lookup) is None and adopted.get(field) in (None, ''):
                adopted[field] = facts[field]
        if adopted.get('details') in (None, ''):
            adopted['details'] = text

    if event_type in _GENERIC_TYPES:
        for column in _ALERT_COLUMNS:
            key = names.get(column)
            value = adopted.get(key) if key is not None else None
            if value in (None, '') or str(value).strip().lower() in _NOT_AN_ALERT:
                continue
            for alias in FIELD_ALIASES['event_type']:
                adopted.pop(alias, None)
            adopted['event_type'] = 'ids_alert'
            adopted.setdefault('details', f'{key}: {value}')
            break
    return adopted


# ---------- Compressed uploads ----------

class UnpackRefused(ValueError):
    """The archive cannot be used. The message is safe to show."""


def unpack_upload(filename, data, limit, blocked_extensions):
    """A .gz or .zip holding one log file becomes that file. Returns (filename, data)."""
    lower = filename.lower()
    if lower.endswith('.gz') or lower.endswith('.tgz'):
        inner = filename[:-3]
        if inner.lower().endswith('.tar') or lower.endswith('.tgz'):
            raise UnpackRefused('A .tar.gz archive can hold many files. Extract it, and upload the log file itself.')
        try:
            with gzip.open(io.BytesIO(data)) as handle:
                unpacked = handle.read(limit + 1)
        except (OSError, EOFError, ValueError):
            raise UnpackRefused('This .gz file could not be read.')
        name = inner
    elif lower.endswith('.zip'):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = [info for info in archive.infolist() if not info.is_dir() and not info.filename.startswith('__MACOSX')
                           and info.filename.rsplit('.', 1)[-1].lower() not in blocked_extensions]
                if len(members) != 1:
                    raise UnpackRefused(f'This .zip holds {len(members)} log files. ALLSAFE analyzes one at a time, so extract it and upload one.')
                with archive.open(members[0]) as handle:
                    unpacked = handle.read(limit + 1)
                name = members[0].filename.replace('\\', '/').rsplit('/', 1)[-1]
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError):
            raise UnpackRefused('This .zip file could not be read. It may be damaged or password protected.')
    else:
        return filename, data
    if len(unpacked) > limit:
        raise UnpackRefused(f'The file inside this archive is larger than the {limit // (1024 * 1024)} MB limit.')
    return name, unpacked


# ---------- Windows event logs and XML exports ----------

def _local_name(tag):
    return tag.rsplit('}', 1)[-1]


def _windows_event_fields(event):
    """One <Event> as flat fields, named as the Windows parser expects"""
    fields = {}
    for section in event:
        name = _local_name(section.tag)
        if name == 'System':
            for item in section:
                tag = _local_name(item.tag)
                if tag == 'TimeCreated':
                    fields['SystemTime'] = item.get('SystemTime')
                elif tag == 'Provider':
                    fields['ProviderName'] = item.get('Name')
                elif tag == 'Security':
                    fields['SecurityUserID'] = item.get('UserID')
                elif tag in ('EventID', 'Computer', 'Channel', 'Level', 'EventRecordID', 'Task', 'Keywords') and (item.text or '').strip():
                    fields[tag] = item.text.strip()
        elif name in ('EventData', 'UserData'):
            for item in section.iter():
                tag = _local_name(item.tag)
                key = item.get('Name') if tag == 'Data' else tag
                if key and tag != name and (item.text or '').strip():
                    fields.setdefault(key, item.text.strip())
    return {key: value for key, value in fields.items() if value not in (None, '')}


def _xml_root(text):
    import xml.etree.ElementTree as ElementTree
    from xml.parsers import expat

    def refuse(*_details):
        raise UnpackRefused('This XML file declares entities, so it was not read.')

    # Entities are how an XML file attacks its reader, and logs have no need of them. Asking the
    # parser finds a declaration wherever it is, and does not refuse a log that only quotes one.
    probe = expat.ParserCreate()
    probe.StartDoctypeDeclHandler = refuse
    probe.EntityDeclHandler = refuse
    try:
        probe.Parse(text, True)
        return ElementTree.fromstring(text)
    except (expat.ExpatError, ElementTree.ParseError):
        raise UnpackRefused('This XML file could not be read.')


def read_xml_log(text):
    """Windows Event Viewer's Save as XML, or any XML whose top element holds one element per record"""
    root = _xml_root(text)
    if _local_name(root.tag) == 'Event':
        return [(_windows_event_fields(root), None)], []
    events = [item for item in root if _local_name(item.tag) == 'Event']
    if events:
        return [(_windows_event_fields(item), None) for item in events], []
    records = []
    for item in root:
        fields = dict(item.attrib)
        for child in item.iter():
            if child is not item and (child.text or '').strip():
                fields.setdefault(_local_name(child.tag), child.text.strip())
            fields.update({key: value for key, value in child.attrib.items() if key not in fields})
        if fields:
            records.append((fields, None))
    return records, []


def read_evtx(data, limit):
    """A Windows .evtx file. Returns (records, errors). One damaged record does not stop the others."""
    try:
        from Evtx.Evtx import FileHeader
    except ImportError:
        raise UnpackRefused('Reading .evtx files needs the python-evtx package, which is not installed. Export the log to CSV or JSON, or run: pip install python-evtx')
    records, errors = [], []
    try:
        number = 0
        for chunk in FileHeader(data, 0x0).chunks():
            for entry in chunk.records():
                number += 1
                if len(records) >= limit:
                    return records, errors
                try:
                    records.append((_windows_event_fields(_xml_root(entry.xml())), None))
                except Exception:
                    errors.append({'line': number, 'error': 'this event record could not be read'})
    except Exception:
        if not records:
            raise UnpackRefused('This .evtx file could not be read. It may be damaged.')
        errors.append({'line': len(records) + 1, 'error': 'the rest of this .evtx file could not be read'})
    return records, errors
