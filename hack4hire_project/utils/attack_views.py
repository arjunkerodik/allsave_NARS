"""Two views computed from stored data: an incident's attack graph, and rule coverage on ATT&CK."""
from models import get_all_iocs

MAX_GRAPH_NODES = 24
MAX_RANK = 6
_FAILED_RESULTS = ('failure', 'failed', 'fail', 'denied')

# The enterprise tactics in attack order. Tactics without a rule stay on the page, so the gaps show.
ATTACK_TACTICS = (
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
    'Exfiltration', 'Impact',
)


def _links_of(event):
    """What one event says is connected to what: (from, to, relation)"""
    src = ('ip', event['src_ip']) if event.get('src_ip') else None
    dst = ('ip', event['dst_ip']) if event.get('dst_ip') else None
    user = ('user', event['user']) if event.get('user') else None
    host = ('host', event['hostname']) if event.get('hostname') else None
    process = ('process', event['process_name']) if event.get('process_name') else None
    domain = ('domain', event['domain']) if event.get('domain') else None

    links = []
    if src and user:
        links.append((src, user, 'authenticated as'))
    if user and host:
        links.append((user, host, 'active on'))
    elif src and host and not user:
        links.append((src, host, 'reached'))
    if src and dst:
        links.append((src, dst, 'connected to'))
    elif host and dst:
        links.append((host, dst, 'connected to'))
    if process:
        owner = user or host or src
        if owner:
            links.append((owner, process, 'ran'))
    if domain:
        owner = src or host
        if owner:
            links.append((owner, domain, 'contacted'))
    return [link for link in links if link[0] != link[1]]


def _ranks(nodes, edges):
    """Each node's column: how many hops it sits from where the activity starts. Loops are cut."""
    incoming, outgoing = {key: 0 for key in nodes}, {key: [] for key in nodes}
    for edge in edges:
        incoming[edge['to']] += 1
        outgoing[edge['from']].append(edge['to'])
    ranks = {}
    frontier = sorted((key for key, count in incoming.items() if not count), key=lambda key: -nodes[key]['events'])
    if not frontier and nodes:
        frontier = [max(nodes, key=lambda key: nodes[key]['events'])]
    current = 0
    while frontier:
        following = []
        for key in frontier:
            if key not in ranks:
                ranks[key] = min(current, MAX_RANK)
                following.extend(outgoing[key])
        frontier = [key for key in following if key not in ranks]
        current += 1
    # Whatever is only reachable inside a loop goes after the rest
    for key in nodes:
        ranks.setdefault(key, min(current, MAX_RANK))
    return ranks


def build_attack_graph(detail):
    """Who and what connects to what in an incident, read from the events behind its alerts"""
    indicators = {ioc['value'] for ioc in get_all_iocs()}
    nodes, edges = {}, {}

    def node(item, event):
        key = f'{item[0]}:{item[1]}'
        entry = nodes.setdefault(key, {'id': key, 'type': item[0], 'label': str(item[1]), 'events': 0, 'rules': set(),
                                       'is_indicator': str(item[1]) in indicators, '_seen': set()})
        if event['id'] not in entry['_seen']:
            entry['_seen'].add(event['id'])
            entry['events'] += 1
        entry['rules'].update(event.get('rule_ids') or [])
        return key

    for event in detail['related_events']:
        for start, end, relation in _links_of(event):
            first, second = node(start, event), node(end, event)
            edge = edges.setdefault((first, second, relation), {
                'from': first, 'to': second, 'relation': relation, 'events': 0, 'failed': 0, 'rules': set(),
                'ports': set(), 'first_seen': event.get('timestamp'), 'last_seen': event.get('timestamp')})
            edge['events'] += 1
            if str(event.get('auth_result') or '').lower() in _FAILED_RESULTS:
                edge['failed'] += 1
            edge['rules'].update(event.get('rule_ids') or [])
            if event.get('dst_port') and relation == 'connected to':
                edge['ports'].add(event['dst_port'])
            edge['last_seen'] = event.get('timestamp') or edge['last_seen']

    hidden = 0
    if len(nodes) > MAX_GRAPH_NODES:
        kept = set(sorted(nodes, key=lambda key: -nodes[key]['events'])[:MAX_GRAPH_NODES])
        hidden = len(nodes) - len(kept)
        nodes = {key: value for key, value in nodes.items() if key in kept}
        edges = {key: value for key, value in edges.items() if value['from'] in kept and value['to'] in kept}

    edge_list = list(edges.values())
    ranks = _ranks(nodes, edge_list)
    return {
        'nodes': [{**{key: value for key, value in entry.items() if key != '_seen'}, 'rules': sorted(entry['rules']), 'rank': ranks[key]}
                  for key, entry in nodes.items()],
        'edges': [{**edge, 'rules': sorted(edge['rules']), 'ports': sorted(edge['ports'])} for edge in edge_list],
        'hidden_nodes': hidden,
        'events_read': len(detail['related_events']),
        'events_total': detail['related_events_total'],
    }


def build_attack_matrix(rules, scenarios):
    """Every technique a rule maps to, under its tactic, with what has fired and what tests it.

    Coverage here means a rule exists and a synthetic scenario exercises it. It does not measure how
    well the rule detects real attacks, and techniques no rule maps to are simply not listed.
    """
    tested_by = {}
    for scenario in scenarios:
        for rule_id in scenario['expected_rules']:
            tested_by.setdefault(rule_id, []).append(scenario['name'])

    tactics = {name: {} for name in ATTACK_TACTICS}
    for rule in rules:
        for mapping in rule.get('mitre') or []:
            techniques = tactics.setdefault(mapping.get('tactic') or 'Unmapped', {})
            technique = techniques.setdefault(mapping['id'], {'id': mapping['id'], 'name': mapping.get('name') or mapping['id'],
                                                              'alerts': 0, 'rules': [], 'scenarios': set()})
            technique['alerts'] += rule.get('alerts') or 0
            technique['rules'].append({'id': rule['id'], 'name': rule['name'], 'alerts': rule.get('alerts') or 0,
                                       'last_fired': rule.get('last_fired')})
            technique['scenarios'].update(tested_by.get(rule['id'], []))

    columns = []
    for name, techniques in tactics.items():
        items = sorted(techniques.values(), key=lambda item: (-item['alerts'], item['id']))
        columns.append({'name': name, 'alerts': sum(item['alerts'] for item in items),
                        'techniques': [{**item, 'scenarios': sorted(item['scenarios'])} for item in items]})
    all_techniques = [item for column in columns for item in column['techniques']]
    return {
        'tactics': columns,
        'totals': {
            'tactics': len(columns),
            'tactics_with_rules': sum(1 for column in columns if column['techniques']),
            'techniques': len(all_techniques),
            'techniques_tested': sum(1 for item in all_techniques if item['scenarios']),
            'techniques_with_alerts': sum(1 for item in all_techniques if item['alerts']),
            'rules': len(rules),
        },
    }


FLOW_VERDICTS = {-1: ('normal', 'No detection'), 0: ('suspicious', 'Suspicious'), 1: ('threat', 'Threat evidence')}
FLOW_OUTCOMES = {'stored': 'Stored', 'alert': 'Alert raised', 'incident': 'In an incident'}


def build_flow(rows, minimum_confidence):
    """How stored logs moved through detection, as nodes and links. Every number is a count of logs."""
    nodes, links = {}, {}

    def link(source, target, logs, verdict):
        nodes[source]['logs_out'] = nodes[source].get('logs_out', 0) + logs
        nodes[target]['logs_in'] = nodes[target].get('logs_in', 0) + logs
        key = (source, target, verdict)
        links[key] = links.get(key, 0) + logs

    for row in rows:
        verdict, verdict_label = FLOW_VERDICTS[row['strength']]
        outcome = 'stored' if verdict == 'normal' else 'incident' if row['in_incident'] else 'alert'
        category, verdict_id, outcome_id = f"type:{row['category']}", f'verdict:{verdict}', f'outcome:{outcome}'
        nodes.setdefault(category, {'id': category, 'column': 0, 'label': str(row['category']).replace('_', ' ').capitalize(), 'key': row['category']})
        nodes.setdefault(verdict_id, {'id': verdict_id, 'column': 1, 'label': verdict_label, 'key': verdict})
        nodes.setdefault(outcome_id, {'id': outcome_id, 'column': 2, 'label': FLOW_OUTCOMES[outcome], 'key': outcome})
        link(category, verdict_id, row['logs'], verdict)
        link(verdict_id, outcome_id, row['logs'], verdict)
    return {
        'nodes': list(nodes.values()),
        'links': [{'source': source, 'target': target, 'verdict': verdict, 'logs': logs} for (source, target, verdict), logs in links.items()],
        'total': sum(row['logs'] for row in rows),
        'confirmed_min_confidence': minimum_confidence,
    }
