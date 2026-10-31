"""Threat intelligence feeds uploaded as files.

A feed lists indicators, not events, so it has no event times and cannot go through the log
pipeline. It is recognised by its columns, imported into the indicator table, and the stored events
are searched for matches. That search only reads: it creates no alerts. Events that arrive
afterwards are matched by the normal IOC engine.
"""
import collections
import ipaddress
import json
import re

from models import (
    bulk_upsert_iocs, delete_iocs_by_source, find_log_matches, get_all_iocs, get_distinct_log_values, get_engine_state,
    get_ioc_match_counts, get_total_log_count, set_engine_state,
)
from utils.dataset_engine import _TIME_NAME, decode_text, detect_structure, inspect_file, read_records
from utils.ioc_engine import MAX_IOC_CONFIDENCE, validate_ioc
from utils.log_ingest import UploadRejected

MAX_FEED_INDICATORS = 20000
BUNDLED_FEED = 'allsafe-synthetic-demo-feed'
MAX_REPORTED_MATCHES = 25
_SAMPLE_CHARS = 65536
_DOCUMENTATION_RANGES = tuple(ipaddress.ip_network(net) for net in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))

_VALUE_COLUMNS = ('value', 'indicator', 'ioc', 'ioc_value', 'observable')
_NAMED_VALUE_COLUMNS = _VALUE_COLUMNS[1:]
_TYPE_COLUMNS = ('type', 'ioc_type', 'indicator_type', 'observable_type')
_REASON_COLUMNS = ('reason', 'description', 'comment', 'threat', 'malware', 'tags')
_EVENT_COLUMNS = {'src_ip', 'dst_ip', 'source_ip', 'destination_ip', 'hostname', 'user', 'username', 'event_type', 'eventid'}
_CONFIDENCE_WORDS = {'very high': 90, 'high': 80, 'medium': 60, 'moderate': 60, 'low': 40, 'very low': 20}
_LOW_SEVERITY_BELOW = 50

_TYPE_NAMES = {
    **dict.fromkeys(('ip', 'ipv4', 'ipv6', 'ipv4-addr', 'ipv6-addr', 'ip-src', 'ip-dst', 'ip_address', 'ip address'), 'ip'),
    **dict.fromkeys(('domain', 'domain-name', 'domain_name', 'hostname', 'fqdn'), 'domain'),
    **dict.fromkeys(('url', 'uri', 'link'), 'url'),
    **dict.fromkeys(('md5', 'sha1', 'sha-1', 'sha256', 'sha-256', 'hash', 'file_hash', 'filehash-md5', 'filehash-sha1', 'filehash-sha256'), 'file_hash'),
}
_HASH = re.compile(r'^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$')


# Matched against the feed's own text, so these say what the feed claims, not what ALLSAFE has verified
_THEMES = {
    'Command and control': r'\bc2\b|command.and.control|beacon',
    'Phishing or fake sites': r'phish|lure|fake|spoof|impersonat|credential',
    'Malware delivery': r'malware|payload|dropper|loader|download|deliver|stealer|ransom|trojan',
    'Fraud': r'fraud|scam',
    'Exploitation': r'exploit|\bcve\b|vulnerab',
    'Scanning or botnet': r'\bscan|botnet|brute',
}
_TOP_ITEMS = 8


def _json_list(value):
    text = str(value or '').strip()
    if not text.startswith('['):
        return None
    try:
        items = json.loads(text)
    except ValueError:
        return None
    return items if isinstance(items, list) else None


def _source_names(fields):
    """The sources column, either JSON objects or name:date values separated by |"""
    value = fields.get('sources') or fields.get('reference')
    items = _json_list(value)
    if items is not None:
        return [str(item.get('source') if isinstance(item, dict) else item).strip() for item in items if item]
    return [name.split(':')[0].strip() for name in str(value or '').split('|') if name.strip()]


def _tags_of(fields, kind):
    return [str(item['value']) for item in (_json_list(fields.get('tags')) or []) if isinstance(item, dict) and item.get('type') == kind and item.get('value')]


def _ranked(counter, total=None):
    return [{'name': name, 'count': count, **({'percent': round(count * 100 / total, 1)} if total else {})} for name, count in counter.most_common(_TOP_ITEMS)]


def analyze_feed(rows):
    """What a feed contains, computed from its rows: [(indicator, its original fields)]"""
    total = len(rows)
    types, bands, reporters, tlds, themes, days, corroboration, malware, campaigns = (collections.Counter() for _ in range(9))
    corroborated = []
    for indicator, fields in rows:
        types[indicator['ioc_type']] += 1
        confidence = indicator['confidence']
        bands['High (70 or more)' if confidence >= 70 else 'Medium (40 to 69)' if confidence >= 40 else 'Low (under 40)'] += 1
        names = set(_source_names(fields))
        reporters.update(names)
        malware.update(set(_tags_of(fields, 'malware')))
        campaigns.update(set(_tags_of(fields, 'campaign')))
        try:
            count = int(fields.get('source_count') or len(names) or 1)
        except (TypeError, ValueError):
            count = len(names) or 1
        corroboration['Reported by 1 source' if count <= 1 else 'Reported by 2 or 3 sources' if count <= 3 else 'Reported by 4 or more sources'] += 1
        if count > 1:
            corroborated.append({'value': indicator['value'], 'ioc_type': indicator['ioc_type'], 'sources': count, 'reason': str(_first(fields, _REASON_COLUMNS) or '')[:160]})
        if indicator['ioc_type'] == 'domain':
            tlds['.' + indicator['value'].rsplit('.', 1)[-1]] += 1
        text = str(_first(fields, _REASON_COLUMNS) or '').lower()
        matched = [name for name, pattern in _THEMES.items() if re.search(pattern, text)]
        themes.update(matched or ['Other or not stated'])
        if str(fields.get('first_seen') or '')[:10]:
            days[str(fields['first_seen'])[:10]] += 1
    corroborated.sort(key=lambda item: (-item['sources'], item['value']))
    timeline = sorted(days.items())
    named_themes = [item for item in themes.most_common() if item[0] != 'Other or not stated']
    multi = sum(1 for item in corroborated)
    parts = [f"{total:,} indicator{'' if total == 1 else 's'}"]
    if types:
        kind, kind_count = types.most_common(1)[0]
        parts.append(f"{round(kind_count * 100 / total)}% are {kind.replace('_', ' ')}s")
    if named_themes:
        parts.append(f"the most common claim is {named_themes[0][0].lower()} ({named_themes[0][1]:,})")
    parts.append(f"{multi:,} {'was' if multi == 1 else 'were'} reported by more than one source")
    return {
        'headline': ', '.join(parts) + '.',
        'total': total,
        'by_type': _ranked(types, total),
        'confidence': _ranked(bands, total),
        'corroboration': _ranked(corroboration, total),
        'themes': _ranked(themes, total),
        'top_malware': _ranked(malware),
        'top_campaigns': _ranked(campaigns),
        'top_reporters': _ranked(reporters),
        'reporters_total': len(reporters),
        'top_domain_endings': _ranked(tlds),
        'most_corroborated': corroborated[:_TOP_ITEMS],
        'first_seen_from': timeline[0][0] if timeline else None,
        'first_seen_to': timeline[-1][0] if timeline else None,
        'first_seen_by_day': [{'day': day, 'count': count} for day, count in timeline[-14:]],
        'note': 'Computed from the feed\'s own contents. Themes match words in its text, so they show what the feed claims. ALLSAFE has not verified these indicators.',
    }


def _named(fields):
    return {str(key).strip().lower(): value for key, value in fields.items()}


def _first(fields, names):
    return next((fields[name] for name in names if fields.get(name) not in (None, '')), None)


def _refang(value):
    """Feeds often write hxxp://evil[.]com so that nobody clicks it by accident"""
    value = str(value).strip().replace('[.]', '.').replace('(.)', '.').replace('[:]', ':')
    return re.sub(r'^hxxp', 'http', value, flags=re.IGNORECASE)


def _infer_type(value):
    if value.lower().startswith(('http://', 'https://')):
        return 'url'
    if _HASH.match(value):
        return 'file_hash'
    try:
        ipaddress.ip_address(value)
        return 'ip'
    except ValueError:
        return 'domain'


def _confidence(value):
    """A word, 0 to 1, or 0 to 100. Absent means the same default as a hand-entered indicator."""
    if value in (None, ''):
        return 60
    text = str(value).strip().lower()
    if text in _CONFIDENCE_WORDS:
        return _CONFIDENCE_WORDS[text]
    try:
        number = float(text)
    except ValueError:
        return 60
    if 0 < number <= 1:
        number *= 100
    return int(max(0, min(number, 100)))


def _description(fields):
    reason = str(_first(fields, _REASON_COLUMNS) or '').strip()
    parts = [reason + ('.' if reason and reason[-1] not in '.!?' else '')]
    sources = _source_names(fields)
    if sources:
        parts.append(f"Reported by: {', '.join(sources[:3])}{' and others' if len(sources) > 3 else ''}.")
    if fields.get('first_seen'):
        parts.append(f"First seen {fields['first_seen']}.")
    return ' '.join(part for part in parts if part)


def _indicator(fields, feed_name):
    """A clean indicator, or (None, why it was left out)"""
    raw = _first(fields, _VALUE_COLUMNS)
    if raw is None:
        return None, 'no value'
    value = _refang(raw)
    named_type = str(_first(fields, _TYPE_COLUMNS) or '').strip().lower()
    ioc_type = _TYPE_NAMES.get(named_type) if named_type else _infer_type(value)
    if ioc_type is None:
        return None, f'unsupported type: {named_type[:40]}'
    if ioc_type == 'ip':
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None, 'invalid value'
        # An internal address in a feed would flag this organization's own traffic. Documentation
        # ranges cannot be internal, and synthetic data uses them.
        if not address.is_global and not any(address in network for network in _DOCUMENTATION_RANGES if network.version == address.version):
            return None, 'private or reserved address'
    confidence = _confidence(fields.get('confidence'))
    severity = str(fields.get('severity') or '').upper() or ('LOW' if confidence < _LOW_SEVERITY_BELOW else 'MEDIUM')
    try:
        return validate_ioc({'ioc_type': ioc_type, 'value': value, 'source': feed_name, 'severity': severity,
                             'confidence': min(confidence, MAX_IOC_CONFIDENCE), 'description': _description(fields)}), None
    except ValueError:
        return None, 'invalid value'


def _looks_like_feed(records):
    names = {str(key).strip().lower() for fields, _ in records[:50] for key in fields}
    if not names or names & _EVENT_COLUMNS or any(_TIME_NAME.search(name) for name in names):
        return False
    has_value = any(name in names for name in _VALUE_COLUMNS)
    has_type = any(name in names for name in _TYPE_COLUMNS)
    return (has_value and has_type) or any(name in names for name in _NAMED_VALUE_COLUMNS)


def parse_feed(filename, data):
    """Returns the parsed feed, or None when this file is not one. Nothing is stored."""
    try:
        extension, kind, _ = inspect_file(filename, data)
        if kind != 'text':
            return None
        text, _, _ = decode_text(data)
        structure = detect_structure(text, extension)
        if structure not in ('csv', 'json', 'jsonl'):
            return None
        # Most uploads are logs, so look at the start of a large file before parsing all of it
        if structure != 'json' and len(text) > _SAMPLE_CHARS:
            sample, _ = read_records(text[:text.rfind('\n', 0, _SAMPLE_CHARS) + 1], structure)
            if not _looks_like_feed(sample):
                return None
        records, _ = read_records(text, structure)
    except UploadRejected:
        return None  # The dataset validator reports what is wrong with the file
    if not _looks_like_feed(records):
        return None

    feed_name = (filename.rsplit('.', 1)[0] or filename)[:200]
    usable, seen, skipped, by_type, analysed = [], set(), {}, {}, []
    for fields, _ in records:
        fields = _named(fields)
        indicator, problem = _indicator(fields, feed_name)
        if not indicator:
            skipped[problem] = skipped.get(problem, 0) + 1
            continue
        key = (indicator['ioc_type'], indicator['value'])
        if key in seen:
            skipped['repeated in this file'] = skipped.get('repeated in this file', 0) + 1
            continue
        seen.add(key)
        usable.append(indicator)
        analysed.append((indicator, fields))
        by_type[indicator['ioc_type']] = by_type.get(indicator['ioc_type'], 0) + 1
    over_limit = max(0, len(usable) - MAX_FEED_INDICATORS)
    if over_limit:
        skipped[f'over the {MAX_FEED_INDICATORS} indicator limit'] = over_limit
    return {'name': feed_name, 'total_rows': len(records), 'indicators': usable[:MAX_FEED_INDICATORS],
            'by_type': by_type, 'skipped': skipped, 'analysis': analyze_feed(analysed[:MAX_FEED_INDICATORS])}


def preview(feed):
    """The feed without its full indicator list, for showing to an analyst"""
    return {**{key: value for key, value in feed.items() if key != 'indicators'},
            'usable': len(feed['indicators']),
            'examples': [{key: item[key] for key in ('ioc_type', 'value', 'confidence', 'description')} for item in feed['indicators'][:5]]}


def retro_hunt(indicators):
    """Which stored events contain these indicators. This only reads: no alert is created."""
    by_type = {}
    for item in indicators:
        by_type.setdefault(item['ioc_type'], set()).add(item['value'])
    found = {}

    def note(item_type, indicator, field, row):
        match = found.setdefault((item_type, indicator, field), {
            'indicator': indicator, 'ioc_type': item_type, 'field': field, 'events': 0, 'origins': {},
            'first_seen': row['first_seen'], 'last_seen': row['last_seen']})
        match['events'] += row['events']
        match['origins'][row['origin']] = match['origins'].get(row['origin'], 0) + row['events']
        match['first_seen'] = min(match['first_seen'], row['first_seen'])
        match['last_seen'] = max(match['last_seen'], row['last_seen'])

    for field in ('src_ip', 'dst_ip'):
        for row in find_log_matches(field, by_type.get('ip', ())):
            note('ip', row['value'], field, row)
    for item_type, field in (('url', 'url'), ('file_hash', 'file_hash')):
        for row in find_log_matches(field, by_type.get(item_type, ())):
            note(item_type, row['value'], field, row)
    domains = by_type.get('domain', set())
    if domains:
        # A domain indicator covers its subdomains, as it does in the IOC engine
        owners = {}
        for observed in get_distinct_log_values('domain'):
            parts = str(observed).lower().split('.')
            owner = next(('.'.join(parts[i:]) for i in range(len(parts) - 1) if '.'.join(parts[i:]) in domains), None)
            if owner:
                owners[observed] = owner
        for row in find_log_matches('domain', owners):
            note('domain', owners[row['value']], 'domain', row)

    matches = sorted(found.values(), key=lambda item: (-item['events'], item['indicator']))
    return {
        'events_searched': get_total_log_count(),
        'matching_events': sum(item['events'] for item in matches),
        'matched_indicators': len({item['indicator'] for item in matches}),
        'matches': matches[:MAX_REPORTED_MATCHES],
    }


def import_feed(feed):
    """Store the feed's indicators and search stored events for them"""
    added, updated = bulk_upsert_iocs(feed['indicators'])
    set_engine_state(_analysis_key(feed['name']), json.dumps(feed['analysis']))
    return {**preview(feed), 'added': added, 'updated': updated, 'retro_hunt': retro_hunt(feed['indicators'])}


def _analysis_key(source):
    return f'feed_analysis:{source}'


def get_feed_analysis(source):
    stored = get_engine_state(_analysis_key(source))
    return json.loads(stored) if stored else None


def indicators_of(source):
    return [ioc for ioc in get_all_iocs() if ioc['source'] == source]


def list_feeds():
    """Each feed in the indicator table, and how many alerts its indicators have produced"""
    matches = get_ioc_match_counts()
    feeds = {}
    for ioc in get_all_iocs():
        feed = feeds.setdefault(ioc['source'], {'source': ioc['source'], 'indicators': 0, 'by_type': {}, 'alerts': 0,
                                                'added_at': ioc['added_at'], 'removable': ioc['source'] != BUNDLED_FEED})
        feed['indicators'] += 1
        feed['by_type'][ioc['ioc_type']] = feed['by_type'].get(ioc['ioc_type'], 0) + 1
        feed['alerts'] += matches.get(ioc['value'], 0)
        feed['added_at'] = max(feed['added_at'] or '', ioc['added_at'] or '') or None
        feed['has_analysis'] = bool(get_engine_state(_analysis_key(ioc['source'])))
    return sorted(feeds.values(), key=lambda feed: feed['added_at'] or '', reverse=True)


def remove_feed(source):
    if source == BUNDLED_FEED:
        raise ValueError('The bundled demonstration feed is loaded again at every start, so it cannot be removed')
    set_engine_state(_analysis_key(source), '')
    return delete_iocs_by_source(source)
