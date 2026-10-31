import codecs
import csv
import hashlib
import io
import json
import os
import re

from utils.log_formats import (
    UnpackRefused, adapt_record, flatten_record, is_directive_log, message_facts, read_directive_log, read_evtx, read_xml_log, unwrap_json,
)
from utils.log_ingest import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES, TEXT_EXTENSIONS, UploadRejected, _parse_pcap, _parse_text_line
from utils.nids_engine import flow_key
from utils.normalizer import FIELD_ALIASES, SOURCE_KEYS, clean_ip, parse_timestamp
from utils.source_parsers import LOG_TYPE_NAMES, UnknownLogSource, has_valid_addresses, identify_and_map

LABEL_FIELDS = ('label', 'ground_truth', 'gt_label', 'is_attack', 'is_malicious', 'attack_label', 'binary_label')
ATTACK_FIELDS = ('attack_type', 'attack_category', 'attack_cat', 'attack_name', 'attack')
LABEL_VALUES = {
    'normal': 'normal', 'benign': 'normal', '0': 'normal', 'false': 'normal', 'no': 'normal', 'clean': 'normal',
    'malicious': 'malicious', 'attack': 'malicious', '1': 'malicious', 'true': 'malicious', 'yes': 'malicious', 'anomaly': 'malicious',
    'suspicious': 'suspicious',
}
_NOT_AN_ATTACK = {'', 'normal', 'benign', 'none', 'no', '0', 'false', '-', 'n/a', 'na', 'clean'}
# Parsing holds the file in memory, and detection takes longer than parsing, so a huge file is sampled
# from its start. The result says how much was left out.
MAX_DATASET_RECORDS = int(os.environ.get('ALLSAFE_MAX_DATASET_RECORDS', '100000'))
_TEXT_ONLY_WARNING_SHARE = 0.5
MAX_REPORTED_INVALID = 200
MAX_PROFILE_RECORDS = 5000
MAX_REPORTED_COLUMNS = 120
_MAPPABLE = {alias for aliases in FIELD_ALIASES.values() for alias in aliases} | set(SOURCE_KEYS) | set(LABEL_FIELDS) | set(ATTACK_FIELDS)
_WATCHED_FIELDS = ('timestamp', 'event_type', 'src_ip', 'dst_ip', 'user', 'hostname')
_TIME_NAME = re.compile(r'(^|[_\s@])(time|timestamp|date|datetime|ts)($|[_\s])|timecreated|timegenerated|systemtime|utctime', re.IGNORECASE)
_DELIMITERS = ',;\t|'
_KNOWN_FIELDS = {alias for aliases in FIELD_ALIASES.values() for alias in aliases} | set(SOURCE_KEYS)

# Other kinds of file that may arrive under a log's name. Their contents are never interpreted.
_BINARY_SIGNATURES = (
    (b'MZ', 'a Windows executable'), (b'\x7fELF', 'a Linux executable'), (b'PK\x03\x04', 'a ZIP archive'),
    (b'\x1f\x8b', 'a GZIP archive'), (b'%PDF', 'a PDF document'), (b'Rar!', 'a RAR archive'), (b'\xd0\xcf\x11\xe0', 'an Office document'),
)
_EVTX_SIGNATURE = b'ElfFile\x00'
# Any other file is accepted if its content is text. These are programs, not logs.
BLOCKED_EXTENSIONS = {'exe', 'dll', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1', 'vbs', 'jar', 'apk', 'iso', 'img', 'sys', 'so', 'dmg', 'deb', 'rpm'}
_XML_START = re.compile(r'^(<\?xml\b|<Events?\b|<[A-Za-z_][\w.-]*[\s>])')
_PCAP_SIGNATURES = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')


def parse_mapping(text):
    """Read a {"their_field": "our_field"} mapping. Only known target fields are accepted."""
    if not text:
        return {}
    try:
        mapping = json.loads(text) if isinstance(text, str) else text
    except ValueError:
        raise UploadRejected('The field mapping is not valid JSON')
    if not isinstance(mapping, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
        raise UploadRejected('The field mapping must be an object of field names, like {"event_time": "timestamp"}')
    unknown = sorted(set(mapping.values()) - _MAPPABLE)
    if unknown:
        raise UploadRejected(f"Unknown target field in the mapping: {', '.join(unknown)}")
    return mapping


def inspect_file(filename, data):
    """Check the file against its name and its actual content. Returns (extension, kind, warnings).
    kind is 'pcap' or 'text'. Nothing is executed or written to disk."""
    extension = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if extension in BLOCKED_EXTENSIONS:
        raise UploadRejected(f'unsupported file type: .{extension} is a program, not a log. Upload a text log, or a CSV, JSON, XML, EVTX or PCAP file.')
    if not data:
        raise UploadRejected('file is empty')
    if len(data) > MAX_UPLOAD_BYTES:
        raise UploadRejected(f'file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit')
    if data.startswith(_EVTX_SIGNATURE):
        return extension, 'evtx', []
    if extension == 'evtx':
        raise UploadRejected('file is named .evtx but is not a Windows event log')
    if data.startswith(_PCAP_SIGNATURES):
        if extension not in ('pcap', 'pcapng', 'cap'):
            raise UploadRejected(f'file is named .{extension} but its content is a packet capture. Rename it to .pcap.')
        return extension, 'pcap', []
    if extension in ('pcap', 'pcapng', 'cap'):
        raise UploadRejected('file is named .pcap but is not a packet capture')
    for signature, description in _BINARY_SIGNATURES:
        if data.startswith(signature):
            raise UploadRejected(f'file is named .{extension} but its content looks like {description}')
    return extension, 'text', []


def decode_text(data):
    """Returns (text, encoding, warnings). Windows tools often export UTF-16, so that is expected."""
    if data.startswith(codecs.BOM_UTF8):
        return data.decode('utf-8-sig', errors='strict'), 'UTF-8 with BOM', []
    for bom, encoding, name in ((codecs.BOM_UTF16_LE, 'utf-16-le', 'UTF-16 LE'), (codecs.BOM_UTF16_BE, 'utf-16-be', 'UTF-16 BE')):
        if data.startswith(bom):
            try:
                return data[len(bom):].decode(encoding), name, []
            except UnicodeDecodeError:
                raise UploadRejected(f'file says it is {name} but cannot be read as that')
    if b'\x00' in data:
        raise UploadRejected('file is not a text file: it contains binary data')
    try:
        return data.decode('utf-8'), 'UTF-8', []
    except UnicodeDecodeError:
        return data.decode('cp1252', errors='replace'), 'Windows-1252', ['The file is not UTF-8, so it was read as Windows-1252. Check any non-English text.']


def detect_structure(text, extension):
    """What the content really is, whatever the file is called"""
    stripped = text.lstrip()
    if not stripped:
        raise UploadRejected('file is empty')
    first_line = next((line for line in text.splitlines() if line.strip()), '')
    if is_directive_log(text):
        return 'directive'
    if extension == 'xml' or (stripped[0] == '<' and _XML_START.match(stripped[:200])):
        return 'xml'
    if stripped[0] in '[{':
        try:
            json.loads(stripped)
            return 'json'
        except (ValueError, RecursionError):
            if first_line.lstrip().startswith('{'):
                try:
                    json.loads(first_line)
                    return 'jsonl'
                except (ValueError, RecursionError):
                    pass
            if extension in ('json', 'jsonl', 'ndjson'):
                raise UploadRejected('file is not valid JSON')
    if extension in ('json',):
        try:
            json.loads(stripped)
        except (ValueError, RecursionError):
            raise UploadRejected('file is not valid JSON')
        return 'json'
    if extension in ('jsonl', 'ndjson'):
        return 'jsonl'
    if extension == 'csv':
        return 'csv'
    if _parse_text_line(first_line):
        return 'text'
    lines = [line for line in text.splitlines()[:6] if line.strip()]
    for delimiter in _DELIMITERS:
        counts = {line.count(delimiter) for line in lines}
        if len(lines) > 1 and len(counts) == 1 and counts.pop() >= 2:
            return 'csv'
    return 'text'


def _delimiter_of(text):
    header = next((line for line in text.splitlines() if line.strip()), '')
    return max(_DELIMITERS, key=header.count) if any(d in header for d in _DELIMITERS) else ','


def _parse_key_values(line):
    """Lines like: date=2026-01-02 time=03:04:05 action=deny src=1.2.3.4 dst=5.6.7.8 dport=22"""
    pairs = dict(re.findall(r'([\w.-]+)=("[^"]*"|\S+)', line))
    if len(pairs) < 3:
        return None
    record = {key: value.strip('"') for key, value in pairs.items()}
    if 'date' in record and 'time' in record:
        record['timestamp'] = f"{record.pop('date')} {record.pop('time')}"
    return record


def read_records(text, structure):
    """Returns (records, errors). A record is (fields, source_hint). Bad lines never stop the good ones."""
    records, errors = [], []
    if structure == 'json':
        try:
            document = json.loads(text.lstrip())
        except (ValueError, RecursionError):
            raise UploadRejected('file is not valid JSON')
        document = unwrap_json(document)
        if not isinstance(document, list):
            raise UploadRejected('JSON must be an object, an array of objects, or {"events": [...]}')
        records = [(item, None) for item in document]
    elif structure == 'directive':
        records, errors = read_directive_log(text)
    elif structure == 'xml':
        try:
            records, errors = read_xml_log(text)
        except UnpackRefused as error:
            raise UploadRejected(str(error))
    elif structure == 'jsonl':
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append((json.loads(line), None))
            except (ValueError, RecursionError):
                errors.append({'line': number, 'error': 'invalid JSON'})
    elif structure == 'csv':
        try:
            reader = csv.DictReader(io.StringIO(text, newline=''), delimiter=_delimiter_of(text))
            if not reader.fieldnames:
                raise UploadRejected('CSV has no header row')
            width = len(reader.fieldnames)
            for row in reader:
                if None in row:
                    errors.append({'line': reader.line_num, 'error': f'row has more columns than the header ({width})'})
                    continue
                if any(value is None for value in row.values()):
                    errors.append({'line': reader.line_num, 'error': f'row has fewer columns than the header ({width})'})
                    continue
                records.append(({key: value for key, value in row.items() if key and value != ''}, None))
        except csv.Error:
            raise UploadRejected('file is not valid CSV')
    else:
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            parsed = _parse_text_line(line)
            if parsed:
                records.append(parsed)
                continue
            fields = _parse_key_values(line)
            if fields:
                records.append((fields, None))
            else:
                errors.append({'line': number, 'error': 'unrecognized log format'})
        if not records and errors:
            # No line is in a format ALLSAFE knows. They are kept as text rather than turned away, with what
            # they state, and the result says that without times the rules could not measure them.
            errors = []
            for line in text.splitlines():
                if line.strip():
                    records.append(({'details': line[:4096], 'event_type': 'log_message', **message_facts(line)}, 'application'))
    return records, errors


def _inferred_type(values):
    samples = [value for value in values if value not in (None, '')][:200]
    if not samples:
        return 'empty'
    if all(clean_ip(value) for value in samples):
        return 'ip address'
    def is_number(value):
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False
    if all(is_number(value) for value in samples):
        return 'number'
    return 'text'


def _profile_columns(originals, total):
    """Which columns exist, what they hold, and which ones this platform has no field for"""
    columns = {}
    for record in originals[:MAX_PROFILE_RECORDS]:
        for key, value in record.items():
            columns.setdefault(key, []).append(value)
    sampled = min(total, MAX_PROFILE_RECORDS)
    profile, timestamps, unsupported = [], [], []
    for name, values in columns.items():
        kind = _inferred_type(values)
        named_time = bool(_TIME_NAME.search(str(name)))
        if named_time and kind != 'empty' and all(parse_timestamp(value) for value in values[:50] if value not in (None, '')):
            kind = 'timestamp'
            timestamps.append(name)
        elif named_time and kind != 'empty':
            timestamps.append(name)
        missing = sampled - sum(1 for value in values if value not in (None, ''))
        known = str(name).strip() in _KNOWN_FIELDS or re.sub(r'[\s-]+', '_', str(name).strip()).lower() in _KNOWN_FIELDS
        profile.append({'name': name, 'type': kind, 'missing': max(0, missing), 'mapped': known})
        if not known:
            unsupported.append(name)
    return profile[:MAX_REPORTED_COLUMNS], timestamps, unsupported


def _take_labels(record):
    """Take ground truth out of a record before anything else sees it. Column names are matched
    loosely, because CIC-IDS2017 writes ' Label'."""
    found_label = found_attack = None
    taken = []
    for key in list(record):
        name = str(key).strip().lower()
        if name in LABEL_FIELDS:
            found_label = record.pop(key)
            taken.append(key)
        elif name in ATTACK_FIELDS:
            found_attack = record.pop(key)
            taken.append(key)
    return found_label, found_attack, taken


def prepare_dataset(filename, data, mapping=None, default_source=None):
    """Validate a file without storing anything. Its contents are only parsed, never executed.

    One bad record never rejects the others. Returns {'rows': [...], 'summary': {...},
    'invalid': [...], 'sha256': ...}. Each row holds the mapped record for the pipeline, with the
    original beside it. Ground truth columns are taken out here, so they never reach detection.
    """
    mapping = mapping or {}
    extension, kind, warnings = inspect_file(filename, data)
    if kind == 'pcap':
        records, parse_errors = _parse_pcap(data), []
        encoding, structure = 'binary', 'pcap'
    elif kind == 'evtx':
        try:
            records, parse_errors = read_evtx(data, MAX_DATASET_RECORDS + 1)
        except UnpackRefused as error:
            raise UploadRejected(str(error))
        encoding, structure = 'binary', 'evtx'
    else:
        text, encoding, encoding_warnings = decode_text(data)
        warnings += encoding_warnings
        structure = detect_structure(text, extension)
        expected = {'csv': 'csv', 'json': 'json', 'jsonl': 'jsonl', 'ndjson': 'jsonl'}.get(extension)
        if expected and expected != structure:
            warnings.append(f'The file is named .{extension} but its content is {structure.upper()}. It was read as {structure.upper()}.')
        if extension in TEXT_EXTENSIONS and structure != 'text':
            warnings.append(f'The file is named .{extension} but its content is {structure.upper()}. It was read as {structure.upper()}.')
        records, parse_errors = read_records(text, structure)
    records_left_out = max(0, len(records) - MAX_DATASET_RECORDS)
    if records_left_out:
        warnings.append(f'This file has {len(records):,} records. The first {MAX_DATASET_RECORDS:,} were analyzed, and the last {records_left_out:,} were not.')
        records = records[:MAX_DATASET_RECORDS]

    invalid = [{'row': error.get('line') or error.get('record'), 'errors': [error['error']], 'record': None} for error in parse_errors]
    rows, seen = [], set()
    originals = []
    duplicates = invalid_timestamps = missing_timestamps = no_timestamp_flows = 0
    labels, log_types = {}, {}
    missing = {field: 0 for field in _WATCHED_FIELDS}
    flows_with_features = flows_without_features = 0
    source_assumed = text_only = 0
    timeless = []

    def accept(mapped, hint, label, attack, taken, original):
        """A record that passed validation. Duplicates are counted and left out."""
        nonlocal duplicates, flows_with_features, flows_without_features, source_assumed, text_only
        fingerprint = hashlib.sha256(json.dumps(mapped, sort_keys=True, default=str).encode()).hexdigest()
        if fingerprint in seen:
            duplicates += 1
            return
        seen.add(fingerprint)
        log_types[mapped['log_type']] = log_types.get(mapped['log_type'], 0) + 1
        if mapped.pop('_source_assumed', False):
            source_assumed += 1
        if not any(mapped.get(alias) not in (None, '') for field in ('src_ip', 'dst_ip', 'user', 'hostname', 'process_name', 'command_line', 'endpoint', 'url', 'domain') for alias in FIELD_ALIASES[field]):
            text_only += 1
        if mapped['log_type'] == 'network_flow' and 'model_features' in mapped:
            if mapped['model_features']:
                flows_with_features += 1
            else:
                flows_without_features += 1
        for field in _WATCHED_FIELDS:
            if not any(mapped.get(alias) not in (None, '') for alias in FIELD_ALIASES[field]):
                missing[field] += 1
        if label:
            labels[label] = labels.get(label, 0) + 1
        if taken:
            mapped['ground_truth_columns_removed'] = sorted(str(key).strip() for key in taken)
        mapped['_original'] = original
        mapped['source_file'] = filename
        rows.append({'raw': mapped, 'hint': hint, 'label': label, 'attack_type': attack, 'fingerprint': fingerprint})

    for index, (raw, hint) in enumerate(records, 1):
        if not isinstance(raw, dict):
            invalid.append({'row': index, 'errors': ['record is not an object'], 'record': str(raw)[:200]})
            continue
        original = dict(raw)
        originals.append(original)
        # Mapping sees the flattened names, so that a nested field can be mapped as source.ip
        record = {mapping.get(key, key): value for key, value in flatten_record(raw).items()}
        label_value, attack, taken = _take_labels(record)
        for key in list(original):
            if key in taken or mapping.get(key) in LABEL_FIELDS + ATTACK_FIELDS:
                original.pop(key)

        errors = []
        mapped = None
        try:
            mapped = identify_and_map(adapt_record(record), hint, default_source)
        except UnknownLogSource as error:
            errors.append(str(error))
        label = None
        if label_value not in (None, ''):
            label = LABEL_VALUES.get(str(label_value).strip().lower())
            if label is None:
                # Many files name the attack class rather than saying malicious, as CIC-IDS2017 does
                label, attack = 'malicious', attack or str(label_value).strip()
            elif label == 'normal':
                attack = None
        elif attack not in (None, ''):
            label = 'normal' if str(attack).strip().lower() in _NOT_AN_ATTACK else 'malicious'
            attack = None if label == 'normal' else attack

        if mapped:
            stamp = next((mapped[alias] for alias in FIELD_ALIASES['timestamp'] if mapped.get(alias) not in (None, '')), None)
            if stamp is None:
                if mapped.get('_timestamp_optional'):
                    no_timestamp_flows += 1
                else:
                    errors += has_valid_addresses(mapped)
                    if not errors:
                        # Whether this is a bad row or a file with no times is only known at the end
                        timeless.append((index, mapped, hint, label, attack, taken, original))
                        continue
                    missing_timestamps += 1
                    errors.insert(0, 'missing timestamp')
            elif parse_timestamp(stamp) is None:
                invalid_timestamps += 1
                errors.append(f'timestamp cannot be read: {str(stamp)[:60]}')
            if stamp is not None or mapped.get('_timestamp_optional'):
                errors += has_valid_addresses(mapped)
        if errors:
            invalid.append({'row': index, 'errors': errors, 'record': {str(k): str(v)[:200] for k, v in list(original.items())[:20]}})
            continue
        accept(mapped, hint, label, attack, taken, original)

    if timeless and not rows:
        # Nothing in this file has a time. It is still read as far as it can be. A time is never made up,
        # and the verdict says that the rules, which all work over a time window, could not evaluate it.
        for _, mapped, hint, label, attack, taken, original in timeless:
            mapped['_timestamp_optional'] = True
            no_time_records = True
            accept(mapped, hint, label, attack, taken, original)
        warnings.append('No record in this file has a time that could be read, so detection rules could not evaluate it. '
                        'If a column holds the time, name it in the field mapping, like {"logged": "timestamp"}, and analyze the file again.')
    else:
        for index, _, _, _, _, _, original in timeless:
            missing_timestamps += 1
            invalid.append({'row': index, 'errors': ['missing timestamp'], 'record': {str(k): str(v)[:200] for k, v in list(original.items())[:20]}})
    invalid.sort(key=lambda row: row['row'] or 0)

    if source_assumed:
        warnings.append(f'{source_assumed:,} record(s) did not show what kind of log they are, so they were kept as application logs.')
    if rows and text_only / len(rows) >= _TEXT_ONLY_WARNING_SHARE:
        warnings.append(f'{text_only:,} of {len(rows):,} record(s) hold only a time and a message, with no address, user, host or process. Most rules measure those fields, so they had little to work with here.')
    if no_timestamp_flows:
        warnings.append(f'{no_timestamp_flows} flow record(s) have no timestamp. They were kept, but time-based detection cannot evaluate them.')
    if flows_without_features:
        warnings.append(f'{flows_without_features} flow record(s) lack some of the features the saved network model needs, so it cannot classify them.')
    profile, timestamp_fields, unsupported = _profile_columns(originals, len(originals))
    if unsupported:
        warnings.append(f'{len(unsupported)} field(s) have no equivalent in the common schema. They are preserved with each event, but no detection reads them.')

    total_rows = len(records) + len(parse_errors)
    malformed = len(parse_errors)
    types_found = sorted(log_types, key=lambda name: -log_types[name])
    if not types_found:
        dataset_type = 'Not identified'
    elif len(types_found) == 1 or log_types[types_found[1]] < 0.1 * len(rows):
        dataset_type = LOG_TYPE_NAMES[types_found[0]]
    else:
        dataset_type = 'Mixed: ' + ', '.join(LOG_TYPE_NAMES[name] for name in types_found)

    summary = {
        'file': {'name': filename, 'size_bytes': len(data), 'extension': extension, 'encoding': encoding, 'structure': structure},
        'dataset_type': dataset_type,
        'log_types': {LOG_TYPE_NAMES[name]: count for name, count in log_types.items()},
        'total_rows': total_rows,
        'valid_records': len(rows),
        'invalid_records': len(invalid),
        'skipped_duplicates': duplicates,
        'malformed_records': malformed,
        'invalid_timestamps': invalid_timestamps,
        'missing_timestamps': missing_timestamps,
        'flows_without_timestamp': no_timestamp_flows,
        'flows_with_model_features': flows_with_features,
        'flows_without_model_features': flows_without_features,
        'records_left_out': records_left_out,
        'text_only_records': text_only,
        'missing_values': {field: count for field, count in missing.items() if count},
        'columns': profile,
        'timestamp_fields': timestamp_fields,
        'unsupported_fields': unsupported[:MAX_REPORTED_COLUMNS],
        'warnings': warnings,
        'labels': labels,
        'has_ground_truth': bool(labels),
    }
    return {'rows': rows, 'summary': summary, 'invalid': invalid[:MAX_REPORTED_INVALID], 'sha256': hashlib.sha256(data).hexdigest()}


def summarize_generated(built):
    """The same summary for a generated dataset, so both kinds of dataset read alike"""
    labels, log_types = {}, {}
    for raw, _, label, _ in built:
        labels[label] = labels.get(label, 0) + 1
        try:
            kind = identify_and_map(raw).get('log_type', 'other')
        except UnknownLogSource:
            kind = 'other'
        log_types[LOG_TYPE_NAMES[kind]] = log_types.get(LOG_TYPE_NAMES[kind], 0) + 1
    return {
        'file': {'name': 'generated', 'structure': 'generated'},
        'dataset_type': 'Mixed: ' + ', '.join(sorted(log_types)) if len(log_types) > 1 else next(iter(log_types), 'Not identified'),
        'log_types': log_types,
        'total_rows': len(built), 'valid_records': len(built), 'invalid_records': 0, 'skipped_duplicates': 0,
        'malformed_records': 0, 'invalid_timestamps': 0, 'missing_timestamps': 0, 'flows_without_timestamp': 0,
        'flows_with_model_features': 0, 'flows_without_model_features': 0, 'missing_values': {}, 'columns': [],
        'timestamp_fields': ['timestamp'], 'unsupported_fields': [], 'warnings': [], 'labels': labels, 'has_ground_truth': True,
    }
