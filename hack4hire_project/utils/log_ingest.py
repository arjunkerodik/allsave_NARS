import csv
import hashlib
import io
import json
import logging
import os
import re

from models import batch_insert_logs
from utils.log_formats import parse_line
from utils.normalizer import NormalizationError, normalize_log

logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = int(os.environ.get('ALLSAFE_MAX_UPLOAD_MB', '100')) * 1024 * 1024
MAX_EVENTS_PER_UPLOAD = 50000
MAX_PCAP_PACKETS = 500000
MAX_REPORTED_ERRORS = 20

TEXT_EXTENSIONS = {'log', 'txt', 'out', 'syslog', 'messages', 'tsv', 'cef', 'leef'}
ALLOWED_EXTENSIONS = {'json', 'jsonl', 'ndjson', 'csv', 'pcap'} | TEXT_EXTENSIONS

# Apache / Nginx common and combined formats
_ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
_SYSLOG_PREFIX = r'^(?P<time>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) '
_SYSLOG_PRIORITY = re.compile(r'^<\d{1,3}>(?!\d+ )')
_SSHD = re.compile(
    _SYSLOG_PREFIX + r'sshd\[(?P<pid>\d+)\]: (?P<result>Failed|Accepted) (?P<method>\S+) for '
    r'(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
_SUDO = re.compile(
    _SYSLOG_PREFIX + r'sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$'
)
_USERADD = re.compile(_SYSLOG_PREFIX + r'useradd\[(?P<pid>\d+)\]: new user: name=(?P<name>[^,\s]+)')
_SSHD_INVALID = re.compile(_SYSLOG_PREFIX + r'sshd\[(?P<pid>\d+)\]: Invalid user (?P<user>\S*) from (?P<ip>\S+)')
_PAM_FAILURE = re.compile(_SYSLOG_PREFIX + r'\S+?(?:: pam_unix\([^)]*\)|\(pam_unix\)\[\d+\]): authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?')
_KERNEL_FIREWALL = re.compile(_SYSLOG_PREFIX + r'.*?SRC=(?P<src>\S+) DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?: SPT=(?P<spt>\d+))?(?: DPT=(?P<dpt>\d+))?')
_FIREWALL_BLOCK_WORD = re.compile(r'\b(BLOCK|DROP|DROPPED|DENY|DENIED|REJECT|REJECTED)\b')


class UploadRejected(ValueError):
    """The file as a whole cannot be processed. The message is safe to show to the client."""


def _parse_text_line(line):
    """Parse one line of a supported text log. Returns (record, source) or None."""
    line = _SYSLOG_PRIORITY.sub('', line)
    match = _ACCESS_LOG.match(line)
    if match:
        size = match.group('size')
        return {
            'timestamp': match.group('time'),
            'src_ip': match.group('ip'),
            'user': None if match.group('user') == '-' else match.group('user'),
            'method': match.group('method'),
            'endpoint': match.group('path'),
            'status_code': match.group('status'),
            'bytes_out': None if size == '-' else size,
            'payload_size': None if size == '-' else size,
            'user_agent': match.group('agent'),
            'event_type': 'http_request',
            'details': line,
        }, 'application'
    match = _SSHD.match(line)
    if match:
        failed = match.group('result') == 'Failed'
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'process_name': 'sshd',
            'process_id': match.group('pid'),
            'user': match.group('user'),
            'src_ip': match.group('ip'),
            'src_port': match.group('port'),
            'dst_port': 22,
            'protocol': 'SSH',
            'event_type': 'authentication_failure' if failed else 'authentication_success',
            'details': line,
        }, 'application'
    match = _SUDO.match(line)
    if match:
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'user': match.group('user'),
            'process_name': 'sudo',
            'command_line': f"sudo -u {match.group('target')} {match.group('command')}",
            'event_type': 'process_start',
            'details': line,
        }, 'endpoint'
    match = _USERADD.match(line)
    if match:
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'process_name': 'useradd',
            'process_id': match.group('pid'),
            'event_type': 'account_created',
            'details': line,
            'created_account': match.group('name'),
        }, 'endpoint'
    match = _SSHD_INVALID.match(line)
    if match:
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'process_name': 'sshd',
            'process_id': match.group('pid'),
            'user': match.group('user') or None,
            'src_ip': match.group('ip'),
            'dst_port': 22,
            'protocol': 'SSH',
            'event_type': 'authentication_failure',
            'details': line,
        }, 'application'
    match = _PAM_FAILURE.match(line)
    if match:
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'process_name': 'pam_unix',
            'user': match.group('user'),
            'src_ip': match.group('ip') or None,
            'event_type': 'authentication_failure',
            'details': line,
        }, 'application'
    match = _KERNEL_FIREWALL.match(line)
    if match:
        blocked = bool(_FIREWALL_BLOCK_WORD.search(line))
        syn = ' SYN ' in line
        return {
            'timestamp': match.group('time'),
            'hostname': match.group('host'),
            'src_ip': match.group('src'),
            'dst_ip': match.group('dst'),
            'src_port': match.group('spt'),
            'dst_port': match.group('dpt'),
            'protocol': match.group('proto'),
            'flags': 'SYN' if syn else None,
            'connection_status': 'attempted' if blocked or syn else 'allowed',
            'event_type': 'firewall_block' if blocked else 'firewall_allow',
            'details': line,
        }, 'network'
    return parse_line(line)


def _parse_pcap(data):
    """Aggregate a capture file into per-flow network events. Payloads are not stored."""
    # Imported here so the application runs without touching the packet stack until needed
    from scapy.error import Scapy_Exception
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import PcapReader

    flows = {}
    try:
        with PcapReader(io.BytesIO(data)) as reader:
            for index, packet in enumerate(reader):
                if index >= MAX_PCAP_PACKETS:
                    raise UploadRejected(f'capture exceeds the {MAX_PCAP_PACKETS} packet limit')
                if IP not in packet:
                    continue
                ip_layer = packet[IP]
                transport = TCP if TCP in packet else UDP if UDP in packet else None
                sport = packet[transport].sport if transport else None
                dport = packet[transport].dport if transport else None
                proto = transport.__name__ if transport else 'IP'
                forward = (ip_layer.src, ip_layer.dst, sport, dport, proto)
                reverse = (ip_layer.dst, ip_layer.src, dport, sport, proto)
                key = reverse if reverse in flows else forward
                when = float(packet.time)
                flow = flows.setdefault(key, {'first': when, 'last': when, 'out': 0, 'in': 0,
                                              'packets': 0, 'flags': set()})
                flow['first'], flow['last'] = min(flow['first'], when), max(flow['last'], when)
                flow['out' if key == forward else 'in'] += len(packet)
                flow['packets'] += 1
                if transport is TCP:
                    flow['flags'].update(str(packet[TCP].flags))
    except UploadRejected:
        raise
    except (Scapy_Exception, ValueError, EOFError, OSError, IndexError, TypeError):
        raise UploadRejected('file is not a valid pcap capture')

    records = []
    for (src, dst, sport, dport, proto), flow in flows.items():
        if flow['flags'] & {'F', 'R'}:
            status = 'closed'
        elif 'S' in flow['flags'] and flow['in'] == 0:
            status = 'attempted'
        elif flow['flags']:
            status = 'established'
        else:
            status = None
        records.append(({
            'timestamp': flow['first'],
            'src_ip': src,
            'dst_ip': dst,
            'src_port': sport,
            'dst_port': dport,
            'protocol': proto,
            'bytes': flow['out'],
            'bytes_in': flow['in'],
            'packet_count': flow['packets'],
            'duration': flow['last'] - flow['first'],
            'connection_status': status,
            'flags': ''.join(sorted(flow['flags'])),
            'event_type': 'network_connection',
        }, 'network'))
    return records


def parse_upload(filename, data):
    """Parse an uploaded file. Returns (records, errors); records are (raw, source_hint) pairs."""
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if extension not in ALLOWED_EXTENSIONS:
        raise UploadRejected(f"unsupported file type; allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
    if not data:
        raise UploadRejected('file is empty')
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadRejected(f'file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit')
    if extension == 'pcap':
        return _parse_pcap(data), []

    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise UploadRejected('file is not valid UTF-8 text')

    records, errors = [], []
    if extension == 'json':
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            raise UploadRejected('file is not valid JSON')
        if isinstance(document, dict):
            document = document['events'] if isinstance(document.get('events'), list) else [document]
        if not isinstance(document, list):
            raise UploadRejected('JSON must be an object, an array of objects, or {"events": [...]}')
        records = [(item, None) for item in document]
    elif extension in ('jsonl', 'ndjson'):
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append((json.loads(line), None))
            except (ValueError, RecursionError):
                errors.append({'line': number, 'error': 'invalid JSON'})
    elif extension == 'csv':
        try:
            reader = csv.DictReader(io.StringIO(text, newline=''))
            if not reader.fieldnames:
                raise UploadRejected('CSV has no header row')
            for row in reader:
                row.pop(None, None)
                records.append(({k: v for k, v in row.items() if k and v not in (None, '')}, None))
        except csv.Error:
            raise UploadRejected('file is not valid CSV')
    else:
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            parsed = _parse_text_line(line)
            if parsed:
                records.append(parsed)
            else:
                errors.append({'line': number, 'error': 'unrecognized log format'})
    return records, errors


def ingest_records(records, default_source=None, origin='upload', batch_id=None, id_seed=None, parse_errors=None):
    """Normalize and store records. One bad record never stops the others.

    id_seed gives events deterministic identifiers, so the same file uploaded twice is not
    stored twice. Detection happens afterwards, driven by the stored events.
    """
    errors = list(parse_errors or [])
    rejected = len(errors)
    if len(records) > MAX_EVENTS_PER_UPLOAD:
        raise UploadRejected(f'more than {MAX_EVENTS_PER_UPLOAD} events in one request')

    normalized = []
    for index, (raw, source_hint) in enumerate(records):
        try:
            source = source_hint or default_source
            if isinstance(raw, dict) and raw.get('source') or isinstance(raw, dict) and raw.get('source_type'):
                source = None
            log = normalize_log(raw, source, origin=origin, ingest_batch=batch_id, strict=True)
        except NormalizationError as error:
            rejected += 1
            if len(errors) < MAX_REPORTED_ERRORS:
                errors.append({'record': index, 'error': str(error)})
            continue
        if id_seed and not (isinstance(raw, dict) and raw.get('event_id')):
            log['event_id'] = hashlib.sha256(f'{id_seed}:{index}'.encode()).hexdigest()[:32]
        normalized.append(log)

    row_ids = batch_insert_logs(normalized)
    stored = sum(1 for row_id in row_ids if row_id)
    return {
        'received': len(records) + len(parse_errors or []),
        'stored': stored,
        'duplicates': len(normalized) - stored,
        'rejected': rejected,
        'errors': errors[:MAX_REPORTED_ERRORS],
        'by_source': _count_by(normalized, 'source'),
    }


def ingest_upload(filename, data, default_source=None, batch_id=None):
    """Parse, validate and store an uploaded file. The file itself is never written to disk."""
    records, errors = parse_upload(filename, data)
    report = ingest_records(records, default_source, origin='upload', batch_id=batch_id,
                            id_seed=hashlib.sha256(data).hexdigest(), parse_errors=errors)
    if not report['stored'] and not report['duplicates']:
        raise UploadRejected('no valid events found in file')
    logger.info('Ingested upload: stored=%s rejected=%s', report['stored'], report['rejected'])
    return report


def _count_by(items, field):
    counts = {}
    for item in items:
        counts[item[field]] = counts.get(item[field], 0) + 1
    return counts
