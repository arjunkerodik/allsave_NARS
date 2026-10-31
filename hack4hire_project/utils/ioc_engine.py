import json
import logging
import os
import re
from urllib.parse import urlsplit

from models import get_all_iocs, upsert_ioc
from utils.detection_engine import simulation_run_of
from utils.normalizer import clean_ip

logger = logging.getLogger(__name__)

SYNTHETIC_FEED_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                   'data', 'ioc_feed_synthetic.json')

IOC_TYPES = ('ip', 'domain', 'url', 'file_hash')
# An indicator match is evidence, not proof of compromise, so on its own it can never be CRITICAL.
IOC_SEVERITIES = ('LOW', 'MEDIUM', 'HIGH')
MAX_IOC_CONFIDENCE = 95
MAX_IMPORT = 10000
ALERT_WINDOW_SECONDS = 3600

_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$')
_HASH = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$')

# Which event fields each indicator type is compared against
_MATCH_FIELDS = {'ip': ('src_ip', 'dst_ip'), 'domain': ('domain',), 'url': ('url',), 'file_hash': ('file_hash',)}


def validate_ioc(item, default_source='manual-import'):
    """Return a clean indicator, or raise ValueError saying why it is not usable"""
    if not isinstance(item, dict):
        raise ValueError('indicator is not an object')
    ioc_type = str(item.get('ioc_type') or item.get('type') or '').strip().lower()
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"ioc_type must be one of {', '.join(IOC_TYPES)}")
    value = str(item.get('value') or '').strip()
    if ioc_type == 'ip':
        value = clean_ip(value)
        if not value:
            raise ValueError('value is not a valid IP address')
    elif ioc_type == 'domain':
        value = value.lower().rstrip('.')
        if not _DOMAIN.match(value):
            raise ValueError('value is not a valid domain')
    elif ioc_type == 'file_hash':
        value = value.lower()
        if not _HASH.match(value):
            raise ValueError('value is not an MD5, SHA-1 or SHA-256 hash')
    else:
        if len(value) > 2048 or urlsplit(value).scheme not in ('http', 'https'):
            raise ValueError('value is not a valid http(s) URL')
    severity = str(item.get('severity') or 'MEDIUM').upper()
    if severity == 'CRITICAL':
        severity = 'HIGH'
    if severity not in IOC_SEVERITIES:
        raise ValueError(f"severity must be one of {', '.join(IOC_SEVERITIES)}")
    try:
        confidence = int(item.get('confidence', 60))
    except (TypeError, ValueError):
        raise ValueError('confidence must be a number')
    if not 0 <= confidence <= 100:
        raise ValueError('confidence must be between 0 and 100')
    return {
        'ioc_type': ioc_type,
        'value': value,
        'source': str(item.get('source') or default_source)[:200],
        'severity': severity,
        'confidence': min(confidence, MAX_IOC_CONFIDENCE),
        'description': str(item.get('description') or '')[:1000],
    }


def import_iocs(items, default_source='manual-import'):
    """Validate and store indicators. Bad entries are reported and do not block good ones."""
    if not isinstance(items, list):
        raise ValueError('expected a list of indicators')
    if len(items) > MAX_IMPORT:
        raise ValueError(f'more than {MAX_IMPORT} indicators in one import')
    added, updated, errors = 0, 0, []
    for index, item in enumerate(items):
        try:
            if upsert_ioc(validate_ioc(item, default_source)):
                added += 1
            else:
                updated += 1
        except ValueError as error:
            errors.append({'index': index, 'error': str(error)})
    return {'added': added, 'updated': updated, 'rejected': len(errors), 'errors': errors[:20]}


def load_synthetic_feed(path=SYNTHETIC_FEED_PATH):
    """Load the bundled demonstration feed"""
    try:
        with open(path, encoding='utf-8') as handle:
            feed = json.load(handle)
        return import_iocs(feed['indicators'], default_source=feed.get('feed', 'synthetic'))
    except (OSError, ValueError, KeyError) as error:
        logger.error('Could not load IOC feed %s: %s', path, error)
        return {'added': 0, 'updated': 0, 'rejected': 0, 'errors': [{'error': 'feed could not be loaded'}]}


def _rule_for(ioc):
    label = ioc['ioc_type'].replace('_', ' ').upper()
    return {
        'id': f"IOC-{ioc['ioc_type'].upper().replace('FILE_', '')}",
        'name': f'Threat Intelligence Match: {label}',
        'description': 'An event contains an indicator from the local threat intelligence database.',
        'detection_type': 'IOC',
        'type': 'ioc',
        'severity': ioc['severity'],
        'confidence': ioc['confidence'],
        'window_seconds': ALERT_WINDOW_SECONDS,
        'mitre': [],
        'recommendations': [
            'Verify the indicator is still current. Threat intelligence can be stale or wrong.',
            'Look for other activity that confirms or rules out compromise.',
        ],
    }


class IocEngine:
    """Matches events against the local threat intelligence database"""

    def evaluate(self, new_events):
        indicators = {(ioc['ioc_type'], ioc['value']): ioc for ioc in get_all_iocs()}
        if not indicators:
            return []
        grouped = {}
        for event in new_events:
            if event.get('ts_epoch') is None:
                continue
            for ioc, field in self._matches_for(event, indicators):
                key = (ioc['id'], field, event.get('src_ip'), event.get('hostname'), simulation_run_of(event))
                grouped.setdefault(key, {'ioc': ioc, 'field': field, 'events': []})['events'].append(event)

        findings = []
        for match in grouped.values():
            ioc, field, events = match['ioc'], match['field'], match['events']
            events.sort(key=lambda e: (e['ts_epoch'], e['id']))
            findings.append({
                'rule': dict(_rule_for(ioc), explanation=(
                    f"{field} matched {ioc['ioc_type']} indicator {ioc['value']} from feed "
                    f"'{ioc['source']}'. {ioc['description']} This is evidence to investigate, "
                    'not proof of compromise.')),
                'group': {'indicator': ioc['value'], 'src_ip': events[0].get('src_ip'),
                          'hostname': events[0].get('hostname'), 'simulation_run': simulation_run_of(events[0])},
                'events': events,
                'observed': len(events),
                'first_ts': events[0]['ts_epoch'],
                'last_ts': events[-1]['ts_epoch'],
                'metrics': {},
                'extra_evidence': {
                    'matched_indicator': ioc['value'],
                    'indicator_type': ioc['ioc_type'],
                    'matched_field': field,
                    'feed_source': ioc['source'],
                    'feed_description': ioc['description'],
                    'feed_confidence': ioc['confidence'],
                },
            })
        return findings

    @staticmethod
    def _matches_for(event, indicators):
        for ioc_type, fields in _MATCH_FIELDS.items():
            for field in fields:
                value = event.get(field)
                if not value:
                    continue
                ioc = indicators.get((ioc_type, str(value).lower() if ioc_type != 'ip' else value))
                if ioc is None and ioc_type == 'domain':
                    # Indicators cover their subdomains
                    parts = str(value).lower().split('.')
                    for i in range(1, len(parts) - 1):
                        ioc = indicators.get(('domain', '.'.join(parts[i:])))
                        if ioc:
                            break
                if ioc:
                    yield ioc, field
