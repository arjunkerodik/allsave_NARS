import ntpath
import re
from datetime import datetime

from utils.nids_engine import FLOW_FEATURE_SET, flow_key, missing_features
from utils.normalizer import FIELD_ALIASES, SOURCE_ALIASES, SOURCE_KEYS, VALID_SOURCES, clean_ip, normal_name

# Each parser turns one record into ALLSAFE's field names, and states what kind of log it is.
# Nothing is invented: a field that is not in the record stays absent. The original record is
# kept beside the result, untouched, and stored as the event's raw record.

LOG_TYPE_NAMES = {
    'network_flow': 'Network flow events',
    'windows_auth': 'Windows authentication events',
    'linux_auth': 'Linux authentication events',
    'endpoint_process': 'Endpoint and process events',
    'application': 'Application security events',
    'firewall': 'Firewall events',
    'ids_alerts': 'Alerts from other security tools',
    'cloud': 'Cloud audit events',
    'other': 'Other logs',
}

_KNOWN = {alias for aliases in FIELD_ALIASES.values() for alias in aliases} | set(SOURCE_KEYS)
_SHORT_NAMES = {'src': 'src_ip', 'dst': 'dst_ip', 'source_address': 'src_ip', 'destination_address': 'dst_ip',
                'srcport': 'src_port', 'dstport': 'dst_port', 'spt': 'src_port', 'dpt': 'dst_port', 'src_pt': 'src_port', 'dst_pt': 'dst_port'}
_FIREWALL_ACTION_FIELDS = ('action', 'fw_action', 'disposition', 'verdict', 'action_taken', 'act', 'decision', 'rule_action', 'policy_action')
_FIREWALL_SOURCE_FIELDS = ('src_ip', 'source_ip', 'src', 'srcip', 'src_addr', 'src_address', 'source_address', 'source_ip_address', 'client_ip', 'sip')
_FIREWALL_ACTIONS = {'allow': 'allow', 'allowed': 'allow', 'accept': 'allow', 'accepted': 'allow', 'permit': 'allow', 'permitted': 'allow',
                     'deny': 'block', 'denied': 'block', 'drop': 'block', 'dropped': 'block', 'block': 'block', 'blocked': 'block', 'reject': 'block', 'rejected': 'block'}
_LINUX_AUTH_PROCESSES = {'sshd', 'sudo', 'su', 'useradd', 'usermod', 'groupadd', 'passwd', 'login', 'pam_unix'}
_MIN_FLOW_FEATURES = 40

# Windows Security and Sysmon event IDs that have a meaning in this schema
_WINDOWS_EVENTS = {
    4624: ('authentication_success', 'windows_auth'),
    4625: ('authentication_failure', 'windows_auth'),
    4634: ('logout', 'windows_auth'),
    4647: ('logout', 'windows_auth'),
    4648: ('explicit_credential_logon', 'windows_auth'),
    # Special privileges are assigned at every administrator logon, so alone this means little
    4672: ('special_privileges_assigned', 'windows_auth'),
    4720: ('account_created', 'windows_auth'),
    4728: ('privilege_granted', 'windows_auth'),
    4732: ('privilege_granted', 'windows_auth'),
    4756: ('privilege_granted', 'windows_auth'),
    4740: ('account_locked_out', 'windows_auth'),
    4688: ('process_start', 'endpoint_process'),
    4689: ('process_stop', 'endpoint_process'),
    4771: ('authentication_failure', 'windows_auth'),
    4776: ('windows_credential_validation', 'windows_auth'),
    1: ('process_start', 'endpoint_process'),
    3: ('network_connection', 'endpoint_process'),
    5: ('process_stop', 'endpoint_process'),
    10: ('memory_access', 'endpoint_process'),
    11: ('file_create', 'endpoint_process'),
    22: ('dns_query', 'endpoint_process'),
}
# Sysmon event numbers overlap with other logs, so they only count with Sysmon's own fields
_SYSMON_FIELDS = {1: ('image', 'utctime'), 3: ('image', 'utctime'), 5: ('image', 'utctime'), 10: ('sourceimage', 'targetimage'), 11: ('targetfilename',), 22: ('queryname',)}
_WINDOWS_MARKERS = {'computer', 'computername', 'machinename', 'channel', 'providername', 'provider_name', 'logontype', 'logon_type',
                    'targetusername', 'subjectusername', 'newprocessname', 'image', 'utctime', 'timecreated', 'time_created'}
_WINDOWS_FIELDS = {
    'timestamp': ('timecreated', 'time_created', 'timegenerated', 'time_generated', 'systemtime', 'utctime', 'date_and_time', 'timestamp', '@timestamp', 'time', 'date'),
    'hostname': ('computer', 'computername', 'computer_name', 'machinename', 'machine_name', 'hostname', 'host', 'workstationname', 'workstation_name'),
    'user': ('targetusername', 'target_user_name', 'accountname', 'account_name', 'username', 'user', 'subjectusername', 'subject_user_name'),
    'src_ip': ('ipaddress', 'ip_address', 'source_network_address', 'sourceip', 'source_ip', 'src_ip'),
    'dst_ip': ('destinationip', 'destination_ip', 'dst_ip'),
    'src_port': ('ipport', 'ip_port', 'sourceport', 'source_port'),
    'dst_port': ('destinationport', 'destination_port'),
    'command_line': ('commandline', 'command_line', 'process_command_line'),
    'parent_process_name': ('parentprocessname', 'parent_process_name', 'parentimage', 'parent_image'),
    'details': ('message', 'details', 'description'),
}
_WINDOWS_PROCESS = ('newprocessname', 'new_process_name', 'processname', 'process_name', 'image')


class UnknownLogSource(ValueError):
    """The record does not look like any supported log. The message says why."""


def _flat(record):
    return {re.sub(r'[\s-]+', '_', str(key).strip()).lower(): value for key, value in record.items()}


def _first(flat, names):
    for name in names:
        value = flat.get(name)
        if value not in (None, '', '-'):
            return value
    return None


def _flow_time(value):
    """CIC-IDS2017 writes day-first timestamps with no zone, like 3/7/2017 8:55"""
    if value in (None, ''):
        return None
    for fmt in ('%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M'):
        try:
            return datetime.strptime(str(value).strip(), fmt).isoformat()
        except ValueError:
            continue
    return value


def _parse_flow(record):
    flat = {flow_key(key): value for key, value in record.items()}
    if len(FLOW_FEATURE_SET & set(flat)) < _MIN_FLOW_FEATURES:
        return None
    missing = missing_features(record)
    fwd, bwd = flat.get('Total_Fwd_Packets'), flat.get('Total_Backward_Packets')
    try:
        packets = int(float(fwd)) + int(float(bwd))
    except (TypeError, ValueError):
        packets = None
    mapped = {
        'source': 'network',
        'timestamp': _flow_time(flat.get('Timestamp')),
        'src_ip': flat.get('Source_IP') or flat.get('Src_IP'),
        'dst_ip': flat.get('Destination_IP') or flat.get('Dst_IP'),
        'src_port': flat.get('Source_Port') or flat.get('Src_Port'),
        'dst_port': flat.get('Destination_Port') or flat.get('Dst_Port'),
        'protocol': flat.get('Protocol'),
        'bytes': flat.get('Total_Length_of_Fwd_Packets'),
        'bytes_in': flat.get('Total_Length_of_Bwd_Packets'),
        'packet_count': packets,
        'duration': flat.get('Flow_Duration'),
        'log_type': 'network_flow',
        'model_features': not missing,
        # Published flow files often carry no time at all. Time-window rules then cannot run,
        # which is reported. A time is never made up for them.
        '_timestamp_optional': True,
    }
    if missing:
        mapped['missing_model_features'] = len(missing)
    return {key: value for key, value in mapped.items() if value not in (None, '')}


def _parse_windows(record):
    flat = _flat(record)
    raw_id = _first(flat, ('eventid', 'eventcode', 'event_code', 'event_id', 'id'))
    try:
        event_number = int(str(raw_id).strip())
    except (TypeError, ValueError):
        return None
    named_as_event = any(name in flat for name in ('eventid', 'eventcode', 'event_code'))
    if not named_as_event and not (_WINDOWS_MARKERS & set(flat)):
        return None
    if event_number in _SYSMON_FIELDS and not any(name in flat for name in _SYSMON_FIELDS[event_number]):
        return None
    # An event ID this schema has no meaning for is kept and named, not guessed at
    event_type, log_type = _WINDOWS_EVENTS.get(event_number, (f'windows_event_{event_number}', 'other'))

    mapped = {'source': 'endpoint', 'event_type': event_type, 'log_type': log_type, 'windows_event_id': event_number}
    for field, names in _WINDOWS_FIELDS.items():
        value = _first(flat, names)
        if value is not None:
            mapped[field] = value
    process = _first(flat, _WINDOWS_PROCESS)
    if process is not None:
        mapped['process_name'] = ntpath.basename(str(process))
        mapped['file_path'] = str(process)
    parent = mapped.get('parent_process_name')
    if parent:
        mapped['parent_process_name'] = ntpath.basename(str(parent))
    # What a Sysmon event is about, in the fields the rules read
    if event_number == 10 and flat.get('sourceimage'):
        mapped['process_name'] = ntpath.basename(str(flat['sourceimage']))
        mapped['details'] = f"{flat['sourceimage']} accessed the memory of {flat.get('targetimage')}"
    if event_number == 11 and flat.get('targetfilename'):
        mapped['file_path'] = str(flat['targetfilename'])
    if event_number == 22 and flat.get('queryname'):
        mapped['domain'] = str(flat['queryname'])
    # 4625 records the attempt's source and account in its event data
    if 'src_ip' in mapped and clean_ip(mapped['src_ip']) is None:
        mapped.pop('src_ip')
    if 'dst_ip' in mapped and clean_ip(mapped['dst_ip']) is None:
        mapped.pop('dst_ip')
    return mapped


def _parse_firewall(record, flat):
    # A record that already reports an alert is an alert, whatever the firewall did with the traffic
    if flat.get('event_type') == 'ids_alert':
        return None
    action_field = next((name for name in _FIREWALL_ACTION_FIELDS if flat.get(name)), None)
    action = _FIREWALL_ACTIONS.get(str(flat.get(action_field) or '').strip().lower())
    if not action or not any(flat.get(name) for name in _FIREWALL_SOURCE_FIELDS):
        return None
    mapped = _named_fields(record)
    for key in list(mapped):
        if str(key).strip().lower().replace(' ', '_') == action_field:
            mapped.pop(key)
    mapped.update(source='network', event_type=f'firewall_{action}', log_type='firewall',
                  connection_status='blocked' if action == 'block' else 'allowed')
    return mapped


def _named_fields(record):
    """Keep the record's fields, renaming those that differ from a known name only in spacing,
    case or a common short form, such as 'Source IP' or 'src'"""
    mapped = {}
    for key, value in record.items():
        text = str(key).strip()
        normal = normal_name(text)
        if text in _KNOWN:
            mapped[text] = value
        elif normal in _SHORT_NAMES:
            mapped[_SHORT_NAMES[normal]] = value
        elif normal in _KNOWN:
            mapped[normal] = value
        else:
            mapped[text] = value
    return mapped


def _explicit_source(mapped):
    """The source the record itself names. Many logs use this column for something else, such as a
    file path or a product name. That is kept as source_name, and the source is worked out from the rest."""
    for key in SOURCE_KEYS:
        value = mapped.get(key)
        if value not in (None, ''):
            name = SOURCE_ALIASES.get(str(value).strip().lower(), str(value).strip().lower())
            if name in VALID_SOURCES:
                return name
            mapped['source_name'] = str(value)[:200]
            mapped.pop(key, None)
    return None


def _has(mapped, field):
    return any(mapped.get(alias) not in (None, '') for alias in FIELD_ALIASES[field])


def identify_and_map(record, hint=None, default_source=None):
    """Work out what kind of log a record is, and map it to the common schema.

    Returns the mapped record, with its log_type. Raises UnknownLogSource if nothing identifies it.
    """
    mapped = _parse_flow(record)
    if mapped:
        return mapped
    mapped = _parse_windows(record)
    if mapped:
        return mapped

    flat = _flat(record)
    mapped = _parse_firewall(record, flat)
    if mapped:
        return mapped

    mapped = _named_fields(record)
    explicit = _explicit_source(mapped)
    event_type = str(next((mapped[alias] for alias in FIELD_ALIASES['event_type'] if mapped.get(alias)), '')).lower()
    process = str(next((mapped[alias] for alias in FIELD_ALIASES['process_name'] if mapped.get(alias)), '')).lower()
    if event_type.startswith('firewall_'):
        log_type, source = 'firewall', 'network'
    elif event_type == 'ids_alert':
        log_type, source = 'ids_alerts', 'network' if _has(mapped, 'src_ip') or _has(mapped, 'dst_ip') else 'application'
    elif process in _LINUX_AUTH_PROCESSES:
        log_type, source = 'linux_auth', hint or ('endpoint' if process != 'sshd' else 'application')
    elif _has(mapped, 'process_name') or _has(mapped, 'command_line') or event_type.startswith('process_') or event_type == 'memory_access':
        log_type, source = 'endpoint_process', 'endpoint'
    elif _has(mapped, 'method') or _has(mapped, 'endpoint') or _has(mapped, 'url') or _has(mapped, 'status_code') or event_type.startswith('authentication_') or event_type in ('file_upload', 'http_request'):
        log_type, source = 'application', 'application'
    elif _has(mapped, 'dst_ip') or _has(mapped, 'dst_port') or _has(mapped, 'bytes') or _has(mapped, 'protocol') or event_type == 'network_connection':
        log_type, source = 'network_flow', 'network'
    elif explicit or hint or default_source:
        log_type, source = 'other', explicit or hint or default_source
    else:
        # Nothing shows what kind of log this is. It is kept, and the file's result says so.
        log_type, source = 'other', 'application'
        mapped['_source_assumed'] = True

    mapped['source'] = explicit or hint or source
    mapped['log_type'] = mapped.pop('_log_type', log_type)
    for key in SOURCE_KEYS[1:]:
        mapped.pop(key, None)
    return mapped


def has_valid_addresses(mapped):
    """The address fields that are present but are not IP addresses"""
    problems = []
    for field in ('src_ip', 'dst_ip'):
        value = next((mapped[alias] for alias in FIELD_ALIASES[field] if mapped.get(alias) not in (None, '')), None)
        if value is not None and clean_ip(value) is None:
            problems.append(f'{field} is not an IP address: {str(value)[:60]}')
    return problems
