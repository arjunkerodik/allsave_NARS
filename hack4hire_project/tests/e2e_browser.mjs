// Drives the real dashboard in headless Edge or Chrome against a real server with a throwaway
// database. Clicks real elements and compares what the page shows with what the API returns.
//     node tests/e2e_browser.mjs [screenshot-dir]
// Exit code is the number of failed checks.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const shots = process.argv[2] || null;
if (shots) mkdirSync(shots, { recursive: true });
const work = mkdtempSync(join(tmpdir(), 'allsafe-browser-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const results = [];
const check = (name, passed, detail = '') => {
    results.push({ name, passed: !!passed, detail });
    console.log(`  [${passed ? 'PASS' : 'FAIL'}] ${name}${!passed && detail !== '' ? `  -> ${String(detail).slice(0, 220)}` : ''}`);
};
const section = title => console.log(`\n[${title}]`);

const freePort = () => new Promise(res => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => res(port)); });
});

const port = await freePort();
const base = `http://127.0.0.1:${port}`;
const env = { ...process.env, ALLSAFE_DB_PATH: join(work, 'b.db'), ALLSAFE_PORT: String(port), PYTHONIOENCODING: 'utf-8', ALLSAFE_LOAD_ML: '0', ALLSAFE_NO_ENV_FILE: '1' };
const server = spawn(process.env.PYTHON || 'python', ['-B', join(project, 'app.py')], { cwd: work, env, stdio: 'ignore' });

const apiGet = async path => (await fetch(base + path)).json();
for (let i = 0; i < 120; i++) {
    try { if ((await fetch(base + '/api/health')).ok) break; } catch { await sleep(500); }
}

const candidates = ['C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe',
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/microsoft-edge'];
const browserPath = candidates.find(existsSync);
const debugPort = await freePort();
const browser = spawn(browserPath, ['--headless=new', `--remote-debugging-port=${debugPort}`, `--user-data-dir=${join(work, 'profile')}`,
    '--window-size=1440,1000', '--no-first-run', 'about:blank'], { stdio: 'ignore' });

let target;
for (let i = 0; i < 40 && !target; i++) {
    await sleep(500);
    try { target = (await (await fetch(`http://127.0.0.1:${debugPort}/json`)).json()).find(t => t.type === 'page'); } catch { /* still starting */ }
}
// Requests this test makes on purpose, to see them refused. Any other failed request is a real problem.
const REFUSALS = [['/api/simulations', '409'], ['/api/datasets/upload', '400'], ['/api/risk/settings', '400']];
const expectedRefusal = entry => entry.url?.includes('favicon')
    || REFUSALS.some(([path, status]) => entry.url?.includes(path) && entry.text.includes(`status of ${status}`));
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => { ws.onopen = r; });
let nextId = 1;
const pending = new Map();
const problems = [];
const external = [];
ws.onmessage = ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id) { pending.get(msg.id)?.(msg); pending.delete(msg.id); return; }
    if (msg.method === 'Runtime.exceptionThrown') problems.push('exception: ' + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') problems.push('console.error: ' + msg.params.args.map(a => a.value ?? a.description).join(' '));
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error' && !expectedRefusal(msg.params.entry)) problems.push('log: ' + msg.params.entry.text + ' ' + (msg.params.entry.url || ''));
    if (msg.method === 'Network.requestWillBeSent') {
        const url = msg.params.request.url;
        if (/^https?:/.test(url) && !url.startsWith(base)) external.push(url);
    }
};
const send = (method, params = {}) => new Promise(r => { const id = nextId++; pending.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) return `EVAL ERROR: ${r.result.exceptionDetails.exception?.description}`;
    return r.result.result.value;
};
const q = s => JSON.stringify(s);
const click = selector => ev(`(() => { const e = document.querySelector(${q(selector)}); if (!e) return 'missing'; e.click(); return 'ok'; })()`);
const text = selector => ev(`document.querySelector(${q(selector)})?.innerText ?? null`);
const count = selector => ev(`document.querySelectorAll(${q(selector)}).length`);
const setValue = (selector, value) => ev(`(() => { const e = document.querySelector(${q(selector)}); e.value = ${q(value)}; e.dispatchEvent(new Event('input', {bubbles:true})); e.dispatchEvent(new Event('change', {bubbles:true})); })()`);
const waitFor = async (expr, timeout = 8000) => {
    const end = Date.now() + timeout;
    while (Date.now() < end) { if (await ev(expr)) return true; await sleep(150); }
    return false;
};
const shot = async name => {
    if (!shots) return;
    const r = await send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(shots, `${name}.png`), Buffer.from(r.result.data, 'base64'));
};
const go = async view => { await click(`.nav-item[data-view="${view}"]`); await sleep(500); };
const tile = key => ev(`document.getElementById('tile-${key}').textContent.replace(/,/g,'')`);

await send('Page.enable'); await send('Runtime.enable'); await send('Log.enable'); await send('Network.enable');
await send('Page.navigate', { url: base + '/dashboard' });
await sleep(3000);

const VIEWS = ['overview', 'events', 'detection', 'investigations', 'approvals', 'risk', 'parameters', 'attack', 'simulation', 'intel', 'upload', 'reports', 'audit'];

async function assertControlsWired(where) {
    const actions = await ev(`[...new Set([...document.querySelectorAll('[data-action]')].map(e => e.dataset.action))]`);
    const known = await ev(`Object.keys(ACTIONS)`);
    const unknown = actions.filter(a => !known.includes(a));
    check(`${where}: every data-action has a handler`, unknown.length === 0, unknown);
    const dead = await ev(`[...document.querySelectorAll('.view:not([hidden]) button, .sidebar button')]
        .filter(b => !b.dataset.action && b.type !== 'submit').map(b => b.innerText)`);
    check(`${where}: no button without a behavior`, dead.length === 0, dead);
}

section('Empty database');
check('page loads with its title', (await ev('document.title')).includes('ALLSAFE'));
check('live updates connect', await waitFor(`document.getElementById('conn-status').classList.contains('online')`));
check('tiles show real zeros for detections', (await tile('alerts')) === '0' && (await tile('responses_pending')) === '0');
check('empty charts say so', await ev(`!document.getElementById('empty-severity').hidden && !document.getElementById('empty-rules').hidden`));
check('empty incident panel says so', (await text('#overview-incidents')).includes('No open incidents'));
check('with no log analyzed yet, the overview says so', (await text('#latest-log')).includes('No log file has been analyzed yet'));
for (const view of VIEWS) {
    await go(view);
    check(`${view}: opens`, await ev(`!document.getElementById('view-${view}').hidden && document.querySelector('.nav-item.active').dataset.view === ${q(view)}`));
    await assertControlsWired(view);
}
await go('investigations');
check('no incidents gives guidance', (await text('#incidents-body')).includes('Simulation Lab'));
await go('audit');
check('empty audit log says so', (await text('#audit-body')).includes('No audit entries'));

section('Simulation lab');
await go('simulation');
const scenarios = await apiGet('/api/simulate');
check('every scenario from the API has a card', (await count('#scenarios .scenario')) === scenarios.scenarios.length);
check('run history starts empty', (await text('#runs-body')).includes('No scenarios'));
check('the multi-stage demo is first', (await text('#scenarios .scenario h3')) === 'Multi-Stage Attack');
check('intensity options come from the API', (await count('#sim-controls [name="intensity"] option')) === Object.keys((await apiGet('/api/simulations')).intensities).length);
await setValue('#sim-controls [name="speed"]', 'instant');
await click('[data-action="run-scenario"][data-id="benign"]');
check('benign run reports no detections', await waitFor(`document.getElementById('sim-result').innerText.includes('none fired')`));
await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`);
await setValue('#sim-controls [name="speed"]', 'normal');
await click('[data-action="run-scenario"][data-id="multi_stage"]');
check('a running scenario shows its progress', await waitFor(`!document.getElementById('sim-progress').hidden && document.getElementById('sim-progress').innerText.includes('RUNNING')`));
check('run buttons are disabled during a run', await waitFor(`[...document.querySelectorAll('[data-action="run-scenario"]')].every(b => b.disabled)`));
const refused = await ev(`fetch('/api/simulations', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({scenario:'benign'})}).then(r => r.status)`);
check('a second start is refused by the backend', refused === 409, refused);
await click('[data-action="sim-control"][data-control="pause"]');
check('pause holds the run', await waitFor(`document.getElementById('sim-progress').innerText.includes('PAUSED')`));
const pausedAt = (await apiGet('/api/simulate')).recent_runs[0].processed_count;
await sleep(1500);
check('nothing is processed while paused', (await apiGet('/api/simulate')).recent_runs[0].processed_count === pausedAt);
await click('[data-action="sim-control"][data-control="resume"]');
check('resume continues the run', await waitFor(`document.getElementById('sim-progress').innerText.includes('RUNNING')`));
await click('[data-action="sim-control"][data-control="stop"]');
check('stop ends the run and says so', await waitFor(`document.getElementById('sim-result').innerText.includes('ended as STOPPED')`, 15000));
const stoppedRun = (await apiGet('/api/simulate')).recent_runs[0];
check('the stopped run is recorded as stopped', stoppedRun.status === 'STOPPED' && stoppedRun.processed_count < stoppedRun.event_count, stoppedRun.status);
await click('[data-action="clear-sim-result"]');
check('a result can be cleared', (await text('#sim-result')) === '');
await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`);
await setValue('#sim-controls [name="speed"]', 'fast');
await click('[data-action="run-scenario"][data-id="multi_stage"]');
check('multi-stage run matches ground truth', await waitFor(`document.getElementById('sim-result').innerText.includes('matched its ground truth') && document.getElementById('sim-result').innerText.includes('IOA-007')`, 15000));
const sim = await apiGet('/api/simulate');
await waitFor(`document.querySelectorAll('#runs-body tr').length === 3`);
const resultText = await text('#sim-result');
for (const part of ['events generated', 'processed', 'failed', 'alerts', 'incidents', 'detections missed', 'unexpected detections', 'detection latency', 'Alert risk', 'Measured against ground truth', 'Triggered alerts', 'Generated events'])
    check(`the result shows "${part}"`, resultText.includes(part));
check('the result offers the report in each format', (await count('#sim-result .report-links a')) === 4);
check('run history matches the API', (await count('#runs-body tr')) === sim.recent_runs.length);
check('validation tiles match the API', (await text('#validation-tiles')).replace(/\s+/g, ' ').includes(`Expected detections ${sim.validation.expected_detections}`));
check('validation says how many runs it covers', (await text('#validation-scope')).includes(`latest ${sim.validation.runs} of ${sim.validation.total_runs} runs`));
check('run history shows the scenario name and its result', (await text('#runs-body')).includes('Multi-Stage Attack') && (await text('#runs-body')).includes('Matched'));
check('a scenario card shows its last result', (await text('#scenarios .scenario .scenario-last')).includes('matched its ground truth'));
check('a card that has not run says so', (await ev(`[...document.querySelectorAll('#scenarios .scenario')].find(c => c.innerText.includes('Brute Force')).innerText.includes('Not run recently')`)));
await click('#sim-result [data-action="open-simulated-stream"]');
check('the lab opens the stream filtered to simulated events', await waitFor(`window.dashboard.view === 'events' && document.querySelector('#events-filter [name=origin]').value === 'simulation' && document.querySelectorAll('#events-body tr.clickable').length > 0`));
check('that stream holds only simulated events', await ev(`[...document.querySelectorAll('#events-body tr.clickable')].every(row => row.lastElementChild.innerText === 'simulation')`));
await ev(`document.getElementById('events-filter').reset(); window.history.back();`);
await waitFor(`window.dashboard.view === 'simulation' && !!document.querySelector('#scenarios .scenario')`);
await click('[data-action="run-scenario"][data-id="multi_stage"]');
await waitFor(`document.getElementById('sim-result').innerText.includes('matched its ground truth')`, 15000);
await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`);
await shot('simulation');
await click('#sim-result [data-action="open-incident"]');
await sleep(800);

section('Investigation');
const incident = (await apiGet('/api/incidents?limit=1'))[0];
check('the second run of a scenario opens its own incident', await ev(`window.location.hash === '#investigations/${incident.id}'`), await ev('location.hash'));
const detail = await apiGet(`/api/incidents/${incident.id}`);
check('the button opens the investigation', await ev(`window.location.hash === '#investigations/${incident.id}'`));
const page = await text('#incident-detail');
for (const part of ['Attack timeline', 'How this was scored', 'Detections and evidence', 'Automatic handling', 'Recommended response', 'Potential impact', 'Who and what was involved', 'Related events', 'Audit trail', 'Expected impact', 'not the probability'])
    check(`shows "${part}"`, page.includes(part));
check('shows the same title as the API', page.includes(incident.title));
check('shows the risk score from the API', page.includes(`${incident.risk_score}/100`));
check('shows the same number of detections', (await count('#incident-detail details.block summary .chip')) === detail.alerts.length);
check('timeline has one row per API entry', (await count('#incident-detail .timeline li')) === detail.timeline.length);
check('shows every recommended action', (await count('#incident-actions .action-row')) === detail.response_actions.length);
check('attack progression is shown', (await text('#incident-detail .chain')).includes('Exfiltration'));
check('the multi-stage incident is critical risk with priority P1', incident.risk_level === 'CRITICAL' && incident.priority === 'P1', `${incident.risk_level} ${incident.priority}`);
check('automatic steps match the API', (await count('#incident-detail .card ul li')) >= detail.automation_log.length && detail.automation_log.length >= 5);
check('entity names are readable', page.includes('Source IP') && !page.includes('src_ip'));
check('the data origin is shown and flagged as synthetic', page.includes('Data origin') && page.includes('Built from synthetic events'));
check('the count awaiting a decision matches the API', await ev(`[...document.querySelectorAll('.metric')].find(m => m.innerText.includes('Awaiting decision')).querySelector('strong').innerText === '${detail.response_actions.filter(a => a.status === 'PENDING').length}'`));
const reportResponse = await ev(`fetch(document.getElementById('incident-report').href).then(async r => ({ status: r.status, name: r.headers.get('Content-Disposition'), body: await r.text() }))`);
check('the report button downloads a real report', reportResponse.status === 200 && reportResponse.name.includes(`${incident.incident_uid}-report.md`), reportResponse.status);
check('the report holds the title, timeline and scoring', reportResponse.body.includes(incident.title) && reportResponse.body.includes('## Attack timeline') && reportResponse.body.includes('## How this was scored'));
check('the report says the data is synthetic', reportResponse.body.includes('Built from synthetic events'));
check('changing a target starts collapsed', await ev(`[...document.querySelectorAll('#incident-actions details.change-target')].every(d => !d.open)`));
check('the severity chip in the header keeps its shape', await ev(`getComputedStyle(document.querySelector('.metric .chip')).display === 'inline-flex'`));
check('a single event is not written as "1 events"', !(await text('#incident-detail')).includes('1 events'));
await ev(`window.scrollTo(0, 3000)`);
await sleep(100);
check('navigation stays on screen when the page scrolls', await ev(`window.scrollY > 0 && document.querySelector('.sidebar').getBoundingClientRect().top === 0`), await ev(`document.querySelector('.sidebar').getBoundingClientRect().top`));
await ev(`window.scrollTo(0, 0)`);
await shot('investigation');
await ev(`document.querySelector('#incident-detail .timeline').scrollIntoView()`);
await sleep(200);
await shot('investigation-timeline');

section('Analyst approval through the interface');
await setValue('#analyst-name', '');
const blockAction = detail.response_actions.find(a => a.action_type === 'block_test_ip');
const approveSel = `[data-action="decide"][data-decision="approve"][data-id="${blockAction.id}"]`;
await click(approveSel);
check('no analyst name means no decision', await waitFor(`document.getElementById('toasts').innerText.includes('analyst name')`));
check('the action is still pending', (await apiGet(`/api/incidents/${incident.id}/response-actions`)).find(a => a.id === blockAction.id).status === 'PENDING');
await setValue('#analyst-name', 'Browser Analyst');
await click(approveSel);
check('approving shows the run button', await waitFor(`!!document.querySelector('[data-action="execute"][data-id="${blockAction.id}"]')`));
check('the approval reached the backend', (await apiGet(`/api/incidents/${incident.id}/response-actions`)).find(a => a.id === blockAction.id).decided_by === 'Browser Analyst');
await click(`[data-action="execute"][data-id="${blockAction.id}"]`);
check('the simulated result is displayed', await waitFor(`document.getElementById('incident-actions').innerText.includes('No real system was changed')`));
const executed = (await apiGet(`/api/incidents/${incident.id}/response-actions`)).find(a => a.id === blockAction.id);
check('backend recorded it as executed and verified', executed.status === 'EXECUTED' && executed.verification.verified);
check('the real blocklist is untouched', (await apiGet('/api/blocklist')).length === 0);
const rejectTarget = detail.response_actions.find(a => a.action_type === 'disable_test_account');
await click(`[data-action="decide"][data-decision="reject"][data-id="${rejectTarget.id}"]`);
await waitFor(`document.getElementById('incident-actions').innerText.includes('Rejected by Browser Analyst')`);
check('rejecting works', (await apiGet(`/api/incidents/${incident.id}/response-actions`)).find(a => a.id === rejectTarget.id).status === 'REJECTED');
// An attack starts small, so a safe step may have run on its own before the risk rose. Choose ones still open.
const investigateTarget = detail.response_actions.find(a => a.action_type === 'collect_additional_logs' && a.status === 'PENDING');
await click(`[data-action="decide"][data-decision="investigate"][data-id="${investigateTarget.id}"]`);
check('an action can be marked for investigation', await waitFor(`document.getElementById('incident-actions').innerText.includes('Marked for investigation by Browser Analyst')`));
check('it stays open for a later decision', await waitFor(`!!document.querySelector('[data-action="decide"][data-decision="approve"][data-id="${investigateTarget.id}"]')`));
const modifyTarget = detail.response_actions.find(a => a.action_type === 'investigate_source_ip' && a.status === 'PENDING');
// A person opens the box and types in it, and a live refresh leaves a focused box alone
const modifyRow = `.action-row:has([data-decision="modify"][data-id="${modifyTarget.id}"])`;
await ev(`(() => { document.querySelector(${q(`${modifyRow} details`)}).open = true; document.querySelector(${q(`${modifyRow} [data-field="target"]`)}).focus(); })()`);
await setValue(`${modifyRow} [data-field="target"]`, '203.0.113.55');
await click(`[data-action="decide"][data-decision="modify"][data-id="${modifyTarget.id}"]`);
await waitFor(`document.getElementById('incident-actions').innerText.includes('Target changed from')`);
check('modifying the target works', (await apiGet(`/api/incidents/${incident.id}/response-actions`)).find(a => a.id === modifyTarget.id).target === '203.0.113.55');
await shot('response');

section('Metrics match the API');
await go('overview');
await sleep(800);
const stats = await apiGet('/api/stats');
for (const key of ['alerts', 'responses_pending', 'responses_automated'])
    check(`tile ${key} equals /api/stats`, (await tile(key)) === String(stats[key]), `${await tile(key)} vs ${stats[key]}`);
check('total events tile is live', Number(await tile('total')) >= 38);
check('the four tiles sit in one even row', (await count('#tiles .tile')) === 4 && await ev(`getComputedStyle(document.getElementById('tiles')).gridTemplateColumns.split(' ').length === 4`));
check('the triage list comes before the charts', await ev(`!!(document.getElementById('overview-incidents').compareDocumentPosition(document.getElementById('chart-volume')) & Node.DOCUMENT_POSITION_FOLLOWING)`));
const topIncidents = await apiGet('/api/incidents?status=OPEN&sort=risk&limit=5');
check('the triage list matches the API', (await count('#overview-incidents tr.clickable')) === topIncidents.length && (await text('#overview-incidents')).includes(topIncidents[0].title));
const ruleData = await apiGet('/api/rules');
check('every required attack type has coverage', ['Credential Access', 'Privilege Escalation', 'Lateral Movement', 'Exfiltration'].every(t => ruleData.rules.some(r => (r.mitre || []).some(m => m.tactic === t))));
check('the sidebar says responses are simulated', !(await text('.sidebar-note')).includes('Synthetic and public data only') && (await text('.sidebar-note')).includes('No real system is changed'));
check('sidebar badge matches pending actions', (await text('#badge-pending')) === String(stats.responses_pending));
check('sidebar badge matches open incidents', (await text('#badge-open')) === String(stats.incidents_open));
const overview = await apiGet('/api/overview?minutes=60');
check('charts are drawn', await ev(`!document.getElementById('chart-severity').parentElement.hidden && !!Chart.getChart('chart-rules')`));
const chartData = await ev(`Chart.getChart('chart-severity').data.datasets[0].data`);
const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
check('severity chart equals the API', JSON.stringify(chartData) === JSON.stringify(severityOrder.map(name => overview.alerts_by_severity[name])), chartData);
check('severity chart runs from most to least severe', JSON.stringify(await ev(`Chart.getChart('chart-severity').data.labels`)) === JSON.stringify(severityOrder));
const ruleChart = await ev(`Chart.getChart('chart-rules').data.labels`);
check('rules chart equals the API', JSON.stringify(ruleChart) === JSON.stringify(overview.top_rules.map(r => r.rule_id)), ruleChart);
// The chart and its note come from the same response, while live telemetry keeps arriving
const volume = await ev(`[Chart.getChart('chart-volume').data.datasets.reduce((sum, d) => sum + d.data.reduce((a, b) => a + b, 0), 0),
    Number(document.getElementById('overview-range-note').textContent.split(' ')[0].replace(/,/g, ''))]`);
check('volume chart total equals the events in range', volume[0] === volume[1], volume);
check('volume chart covers the simulated events', volume[0] >= 25, volume);
await click('[data-action="toggle-table"][data-chart="severity"]');
check('the table view replaces the chart', await ev(`!document.getElementById('table-severity').hidden && document.getElementById('chart-severity').parentElement.hidden`));
check('the table view shows the same values', (await text('#table-severity')).includes(String(overview.alerts_by_severity.CRITICAL)));
await click('[data-action="toggle-table"][data-chart="severity"]');
check('the chart view returns', await ev(`document.getElementById('table-severity').hidden && !document.getElementById('chart-severity').parentElement.hidden`));
await setValue('#overview-range', '15');
await sleep(600);
check('changing the time range reloads the charts', (await text('#overview-range-note')).includes('arrived in this range'));
await setValue('#overview-range', '60');
await sleep(400);
await shot('overview');
await click('[data-action="open-tile"][data-key="alerts"]');
const alertTileOk = await waitFor(`document.querySelectorAll('#alerts-body tr.clickable').length === ${stats.alerts}`);
check('the alerts tile opens the same number of alerts', alertTileOk, `${await count('#alerts-body tr')} vs ${stats.alerts}`);
await go('overview');
await click('[data-action="open-tile"][data-key="responses_pending"]');
const pendingNowApi = (await apiGet('/api/stats')).responses_pending;
const pendingOk = await waitFor(`document.querySelectorAll('#approvals-body .action-row').length === ${pendingNowApi}`);
const pendingShown = await count('#approvals-body .action-row');
check('the pending tile opens the same number of actions', pendingOk,
    `${pendingShown} vs ${pendingNowApi}; hash=${await ev('location.hash')} view=${await ev('window.dashboard.view')} status=${await ev(`document.querySelector('#approvals-filter [name=status]').value`)} body=${(await text('#approvals-body')).slice(0, 120)}`);
await go('overview');
await click('[data-action="open-tile"][data-key="responses_automated"]');
check('the automatic tile opens that filter', await waitFor(`document.querySelector('#approvals-filter [name=status]').value === 'AUTOMATED'`));

section('Incident status');
await go('overview');
await sleep(300);
const resolvedBefore = (await apiGet('/api/stats')).incidents_resolved;
await ev(`window.location.hash = '#investigations/${incident.id}'`);
await waitFor(`!!document.querySelector('[data-action="set-status"][data-status="INVESTIGATING"]')`);
await click('[data-action="set-status"][data-status="INVESTIGATING"]');
await waitFor(`document.querySelector('[data-action="set-status"][data-status="ACTIVE"]') !== null`);
check('status change reaches the backend', (await apiGet(`/api/incidents/${incident.id}`)).incident.status === 'INVESTIGATING');
await click('[data-action="set-status"][data-status="RESOLVED"]');
await waitFor(`!document.querySelector('[data-action="set-status"][data-status="RESOLVED"]')`);
await go('overview');
await sleep(400);
check('the resolved count goes up', (await apiGet('/api/stats')).incidents_resolved === resolvedBefore + 1);
await ev(`window.location.hash = '#investigations/${incident.id}'`);
await waitFor(`!!document.querySelector('[data-action="set-status"][data-status="ACTIVE"]')`);
await click('[data-action="set-status"][data-status="ACTIVE"]');
await sleep(500);

section('Live event stream');
await go('events');
await sleep(800);
const logs = await apiGet('/api/logs?limit=100&exclude_system=1');
check('rows come from the API', (await count('#events-body tr')) >= Math.min(logs.length, 1));
check('long summaries are clamped in the table', await ev(`getComputedStyle(document.querySelector('#events-body .clamp')).webkitLineClamp === '2'`));
check('the stream says what it is showing', await waitFor(`/^Showing \\d+, \\d+ with detections\\. .*received in the last minute/.test(document.getElementById('stream-stats').textContent)`));
check('source filter options come from the data', (await text('#events-filter [name="source"]')).includes('network'));
await waitFor(`document.querySelectorAll('#events-body tr.detected').length > 0`);
check('detected events are marked', (await count('#events-body tr.detected')) > 0,
    `rows=${await count('#events-body tr')} apiDetected=${logs.filter(l => l.detections.length).length}/${logs.length} source=${await ev(`document.querySelector('#events-filter [name=source]').value`)} first=${(await text('#events-body')).slice(0, 160)}`);
const polling = logs.filter(l => /GET \/(api|socket\.io)/.test(`${l.method} ${l.endpoint} ${l.details}`));
check('the dashboard polling itself does not fill the stream', polling.length === 0, `${polling.length} of ${logs.length}: ${polling[0]?.details}`);
check('each request is recorded once', logs.filter(l => (l.details || '').includes('HTTP/1.1')).length === 0);
await setValue('#events-filter [name="q"]', 'psexec');
await sleep(700);
check('search filters the stream', (await count('#events-body tr')) >= 1 && await ev(`[...document.querySelectorAll('#events-body tr')].every(row => row.innerText.includes('psexec'))`));
await click('#events-body tr[data-action="open-event"]');
check('clicking an event opens its details', await waitFor(`!document.getElementById('drawer').hidden && document.getElementById('drawer-body').innerText.includes('Original record')`));
check('the details show the original record', (await text('#drawer-body')).includes('psexec.exe'));
await shot('event-drawer');
await click('[data-action="close-drawer"]');
check('the drawer closes', await ev(`document.getElementById('drawer').hidden`));
await setValue('#events-filter [name="q"]', '');
await sleep(600);
const beforeLive = await count('#events-body tr');
const streamed = await ev(`fetch('/api/simulate/port_scan', {method:'POST'}).then(r => r.json()).then(() => 1)`);
check('a new scenario streams in without a reload', streamed === 1 && await waitFor(`document.getElementById('events-body').innerText.includes('10.20.0.50')`, 6000));
check('the received counter counts streamed events', await ev(`window.dashboard.receivedAt.length >= 20 && document.getElementById('stream-stats').textContent.includes(window.dashboard.receivedAt.length + ' logs received')`), await text('#stream-stats'));
check('the stream grew', (await count('#events-body tr')) > beforeLive);
await click('[data-action="toggle-pause"]');
check('pause changes the button', (await text('#events-pause')).includes('Resume'));
await ev(`fetch('/api/simulate/webshell', {method:'POST'})`);
check('new events are counted while paused', await waitFor(`document.getElementById('events-pause').innerText.includes('new')`, 6000));
check('the table does not change while paused', !(await text('#events-body')).includes('shell.php'));
await click('[data-action="toggle-pause"]');
check('resume catches up', await waitFor(`document.getElementById('events-body').innerText.includes('shell.php')`));
await shot('events');

section('Threat detection');
await go('detection');
await ev(`document.getElementById('alerts-filter').reset()`);
await setValue('#alerts-filter [name="q"]', '');
await sleep(800);
const alerts = await apiGet('/api/alerts?limit=200');
const alertsOk = await waitFor(`document.querySelectorAll('#alerts-body tr.clickable').length === ${alerts.length}`);
check('alert rows match the API', alertsOk, `${await count('#alerts-body tr')} vs ${alerts.length}`);
const rules = await apiGet('/api/rules');
check('rule rows match the API, including behavioral rules', (await count('#rules-body tr')) === rules.rules.length + rules.behavioral_rules.length);
check('behavioral rules show their logic', (await text('#rules-body')).includes('UEBA-001') && (await text('#rules-body')).includes('earlier transfers'));
await setValue('#alerts-filter [name="detection_type"]', 'IOC');
check('method filter works', await waitFor(`document.getElementById('alerts-body').innerText.includes('IOC-IP') && !document.getElementById('alerts-body').innerText.includes('IOA-001')`));
await setValue('#alerts-filter [name="detection_type"]', '');
await waitFor(`document.getElementById('alerts-body').innerText.includes('IOA-001')`);
await click('[data-action="filter-rule"][data-rule="IOA-005"]');
await waitFor(`document.querySelectorAll('#alerts-body tr.clickable').length === 1 && document.getElementById('alerts-body').innerText.includes('IOA-005')`);
check('a rule button filters alerts to that rule', (await count('#alerts-body tr')) === 1 && (await text('#alerts-body')).includes('IOA-005'),
    `rows=${await count('#alerts-body tr')} rule=${await ev(`document.querySelector('#alerts-filter [name=rule_id]').value`)} body=${(await text('#alerts-body')).slice(0, 160)}`);
await click('#alerts-body tr[data-action="open-alert"]');
check('an alert opens its evidence', await waitFor(`document.getElementById('drawer-body').innerText.includes('Matched evidence')`));
await click('[data-action="close-drawer"]');
await shot('detection');

section('A slow old response cannot overwrite newer results');
await ev(`(() => {
    window.__realFetch = window.fetch;
    window.fetch = (url, options) => String(url).includes('/api/alerts') && !String(url).includes('rule_id=IOA-005')
        ? new Promise(resolve => setTimeout(() => resolve(window.__realFetch(url, options)), 1200))
        : window.__realFetch(url, options);
})()`);
// Both requests start in the same tick. Not awaiting is the point: the old one must still be in flight.
const raceScript = `(() => {
    const form = document.getElementById('alerts-filter');
    form.reset();
    void window.dashboard.loadAlerts();
    form.querySelector('[name=rule_id]').value = 'IOA-005';
    void window.dashboard.loadAlerts();
})()`;
const showsOnlyRule = `document.querySelectorAll('#alerts-body tr.clickable').length === 1 && document.getElementById('alerts-body').innerText.includes('IOA-005')`;
// Control: with the guard switched off, the same steps must show the bug, or this test proves nothing
await ev(`window.__guard = window.dashboard.latest; window.dashboard.latest = () => () => true;`);
await ev(raceScript);
await sleep(1800);
check('control: without the guard, the old response does overwrite', !(await ev(showsOnlyRule)), await count('#alerts-body tr.clickable'));
await ev(`window.dashboard.latest = window.__guard;`);
await ev(raceScript);
await sleep(1800);
check('with the guard, the latest filter stays on screen', await ev(showsOnlyRule), await count('#alerts-body tr.clickable'));
await ev(`window.fetch = window.__realFetch`);
await ev(`document.getElementById('alerts-filter').reset(); void window.dashboard.loadAlerts();`);
await waitFor(`document.getElementById('alerts-body').innerText.includes('IOA-001')`);

section('Threat intelligence');
await go('intel');
await sleep(600);
const iocsBefore = (await apiGet('/api/iocs')).length;
check('indicator rows match the API', (await count('#ioc-body tr')) === iocsBefore);
check('match counts are shown', (await text('#ioc-body')).includes('198.51.100.77'));
await setValue('#ioc-form [name="value"]', '198.51.100.222');
await ev(`document.getElementById('ioc-form').requestSubmit()`);
check('adding an indicator updates the table', await waitFor(`document.getElementById('ioc-body').innerText.includes('198.51.100.222')`));
check('the indicator reached the backend', (await apiGet('/api/iocs')).length === iocsBefore + 1);
await setValue('#ioc-form [name="value"]', 'not-an-ip');
await ev(`document.getElementById('ioc-form').requestSubmit()`);
check('an invalid indicator is reported', await waitFor(`document.getElementById('toasts').innerText.includes('1 rejected')`));
await setValue('#ioc-import [name="json"]', '{broken');
await ev(`document.getElementById('ioc-import').requestSubmit()`);
check('broken import JSON is reported', await waitFor(`document.getElementById('ioc-result').innerText.includes('not valid JSON')`));
await setValue('#ioc-import [name="json"]', JSON.stringify([{ ioc_type: 'domain', value: 'bad.malware-demo.example' }]));
await ev(`document.getElementById('ioc-import').requestSubmit()`);
check('a feed import works', await waitFor(`document.getElementById('ioc-body').innerText.includes('bad.malware-demo.example')`));
await setValue('#ioc-search', 'bad.malware');
await sleep(200);
check('indicator search works', (await count('#ioc-body tr')) === 1);
await setValue('#ioc-search', '');
await shot('intel');

section('Dataset analysis');
await go('upload');
check('profiles come from the API', (await count('#generate-form [name="profile"] option')) === (await apiGet('/api/datasets')).profiles.length);
check('an empty list says so', (await text('#datasets-body')).includes('No logs analyzed yet'));
check('the page is named Log Analysis', (await text('.topbar h1')) === 'Log Analysis' && (await text('.nav-item[data-view="upload"]')).includes('Log Analysis'));
check('any file can be chosen', !(await ev(`document.getElementById('upload-file').hasAttribute('accept')`)));
await setValue('#generate-form [name="count"]', '300');
await setValue('#generate-form [name="seed"]', '42');
await ev(`document.getElementById('generate-form').requestSubmit()`);
check('a generated dataset finishes with results', await waitFor(`document.getElementById('upload-result').innerText.includes('Measured against ground truth')`, 40000));
const generated = (await apiGet('/api/datasets')).datasets[0];
const generatedDetail = await apiGet(`/api/datasets/${generated.dataset_id}`);
check('it completed with no missed or unexpected rules', generated.status === 'COMPLETED' && generated.metrics.missed_rules.length === 0 && generated.metrics.unexpected_rules.length === 0, JSON.stringify(generated.metrics).slice(0, 200));
check('the page shows the same alert count as the API', (await text('#upload-result')).replace(/\s+/g, ' ').includes(`${generated.metrics.alerts} alerts`));
check('its incidents are listed', (await count('#upload-result [data-action="open-incident"]')) === generatedDetail.incidents.length && generatedDetail.incidents.length > 0);
check('it has a report to download', await ev(`!!document.querySelector('#upload-result .report-links a[href*="format=pdf"]')`));
check('the dataset is in the history', await waitFor(`document.getElementById('datasets-body').innerText.includes('Mixed benign')`));
const logPath = join(work, 'attack.log');
const nowLine = (i) => { const d = new Date(Date.now() - (30 - i) * 1000); const m = d.toLocaleString('en-US', { month: 'short' }); return `${m} ${String(d.getDate()).padStart(2, ' ')} ${d.toTimeString().slice(0, 8)}`; };
writeFileSync(logPath, Array.from({ length: 6 }, (_, i) => `${nowLine(i)} files-07 sshd[9]: Failed password for root from 203.0.113.90 port ${4000 + i} ssh2`).join('\n') + '\nnot a recognized line\n');
const doc = await send('DOM.getDocument');
const node = await send('DOM.querySelector', { nodeId: doc.result.root.nodeId, selector: '#upload-file' });
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [logPath] });
await click('[data-action="validate-dataset"]');
check('validation reports without storing', await waitFor(`document.getElementById('upload-result').innerText.includes('Nothing has been stored') && document.getElementById('upload-result').innerText.includes('unrecognized')`));
const beforeUpload = (await apiGet('/api/datasets')).datasets.length;
check('validation created no dataset', beforeUpload === 1);
await ev(`document.getElementById('upload-form').requestSubmit()`);
check('upload reports results', await waitFor(`document.getElementById('upload-result').innerText.includes('events stored')`, 20000));
const uploaded = await text('#upload-result');
check('upload reports the rejected line', uploaded.includes('unrecognized'));
check('upload links to the incident', await ev(`!!document.querySelector('#upload-result [data-action="open-incident"]')`));
await shot('upload');
await ev(`document.getElementById('upload-form').requestSubmit()`);
check('the same file is not processed twice', await waitFor(`document.getElementById('upload-result').innerText.includes('already analyzed')`));
check('no second dataset was created', (await apiGet('/api/datasets')).datasets.length === beforeUpload + 1);
const badPath = join(work, 'evil.exe');
writeFileSync(badPath, 'MZ');
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [badPath] });
await ev(`document.getElementById('upload-form').requestSubmit()`);
check('a refused file shows the reason', await waitFor(`document.getElementById('upload-result').innerText.includes('unsupported file type')`));
const noColumn = join(work, 'bad.csv');
writeFileSync(noColumn, 'a,b\n1,2\n');
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [noColumn] });
await ev(`document.getElementById('upload-form').requestSubmit()`);
check('a file with no times is analyzed, and never called clean', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'ANALYSIS INCOMPLETE'`, 30000));
await waitFor(`document.getElementById('datasets-body').innerText.includes('bad.csv') && !document.getElementById('dataset-progress').offsetParent`, 10000);

section('Dataset verdicts');
const samplePath = name => join(project, 'data', 'samples', name);
const uploadSample = async name => {
    await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [samplePath(name)] });
    await ev(`document.getElementById('upload-result').innerHTML = ''; document.getElementById('upload-form').requestSubmit()`);
};
await uploadSample('clean_activity.csv');
check('a clean dataset shows NO THREATS DETECTED', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'NO THREATS DETECTED'`, 30000), await text('#upload-result .verdict-headline'));
check('with the exact statement that it is no guarantee', (await text('#upload-result .verdict')).includes('This does not guarantee that the environment is completely free of threats.'));
for (const part of ['What was read', 'Detection engine status', 'Analysis overview', 'Threat detection results', 'Attack investigation and risk', 'Recommended response', 'Security report'])
    check(`the analysis page shows "${part}"`, (await text('#upload-result')).includes(part));
const pageText = await text('#upload-result');
check('the engine table lists all five engines', ['IOC enrichment', 'IOA behavior rules', 'Supervised ML', 'UEBA baselines', 'Anomaly model'].every(name => pageText.includes(name)));
await shot('dataset-clean');
await uploadSample('brute_force_windows.csv');
check('a Windows export shows THREATS DETECTED', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'THREATS DETECTED'`, 30000), await text('#upload-result .verdict-headline'));
check('its log type was identified', (await text('#upload-result')).includes('Windows authentication events'));
await click('#upload-result tr[data-action="open-alert"]');
check('a finding opens its record-level evidence', await waitFor(`document.getElementById('drawer-body').innerText.includes('Supporting events')`));
await click('#drawer-body [data-action="open-event"]');
check('an event opens with its original record', await waitFor(`document.getElementById('drawer-body').innerText.includes('Original record') && document.getElementById('drawer-body').innerText.includes('TimeCreated')`));
await shot('dataset-evidence');
await click('[data-action="close-drawer"]');
await shot('dataset-threats');
await uploadSample('suspicious_network.csv');
check('weak signals show SUSPICIOUS ACTIVITY FOUND', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'SUSPICIOUS ACTIVITY FOUND'`, 30000), await text('#upload-result .verdict-headline'));
await uploadSample('network_flows_cicids.csv');
check('flow data no engine can read shows ANALYSIS INCOMPLETE', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'ANALYSIS INCOMPLETE'`, 30000), await text('#upload-result .verdict-headline'));
check('and never the clean statement', !(await text('#upload-result')).includes('No suspicious activity was detected'));
await shot('dataset-incomplete');
await uploadSample('malformed_records.csv');
check('malformed rows are reported without rejecting the rest', await waitFor(`document.getElementById('upload-result').innerText.includes('Invalid records') && document.getElementById('upload-result').innerText.includes('fewer columns')`, 30000));
const evtxPath = join(work, 'security.evtx');
writeFileSync(evtxPath, 'ElfFile\0rest');
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [evtxPath] });
await ev(`document.getElementById('upload-form').requestSubmit()`);
check('a damaged EVTX fails validation with a reason', await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText === 'VALIDATION FAILED'`));
check('the history shows each result', await waitFor(`['NO THREATS DETECTED', 'THREATS DETECTED', 'ANALYSIS INCOMPLETE', 'VALIDATION FAILED'].every(name => document.getElementById('datasets-body').innerText.includes(name))`));

section('Risk management');
await go('risk');
await sleep(600);
const riskData = await apiGet('/api/risk');
check('risk tiles match the API', (await text('#risk-tiles')).replace(/\s+/g, ' ').includes(`CRITICAL risk incidents ${riskData.incident_distribution.CRITICAL || 0}`));
check('the policy table has one row per level', (await count('#risk-policy tr')) === 4);
check('the policy shows the score ranges', (await text('#risk-policy')).includes('90 to 100') && (await text('#risk-policy')).includes('70 to 89'));
check('actions needing approval are listed', (await text('#risk-approval')).includes('Block test IP'));
check('notifications match the API', (await count('#risk-notifications tr')) === (await apiGet('/api/notifications')).length);
check('recent automatic steps are shown', (await count('#risk-automation tr')) === riskData.recent_automation.length && riskData.recent_automation.length > 0);
const modelData = await apiGet('/api/ml');
await go('parameters');
await waitFor(`document.getElementById('risk-models').innerText.includes('Not claimed')`);
check('the anomaly model shows its measured numbers', (await text('#risk-models')).includes(`${modelData.anomaly_model.evaluation.held_out_false_alarms} of ${modelData.anomaly_model.evaluation.held_out_normal_windows.toLocaleString()}`), (await text('#risk-models')).slice(0, 300));
check('the network model says no accuracy is claimed', (await text('#risk-models')).includes('Not claimed'));
await go('risk');
await sleep(300);
const unreadBefore = Number(await text('#badge-notifications'));
check('the sidebar counts unread notifications', unreadBefore === (await apiGet('/api/stats')).notifications_unread && unreadBefore > 0, unreadBefore);
await click('[data-action="read-notifications"]');
check('marking as read clears the badge', await waitFor(`document.getElementById('badge-notifications').hidden`));
await setValue('#risk-form [name="weight.severity"]', '60');
await ev(`document.getElementById('risk-form').requestSubmit()`);
check('weights that do not add up are refused', await waitFor(`document.getElementById('toasts').innerText.includes('add up to 100')`));
check('refused settings changed nothing', (await apiGet('/api/risk')).weights.severity === 25);
await setValue('#risk-form [name="weight.severity"]', '25');
await setValue('#risk-form [name="level.CRITICAL"]', '95');
await ev(`document.getElementById('risk-form').requestSubmit()`);
check('valid settings are saved', await waitFor(`document.getElementById('toasts').innerText.includes('scored again')`));
check('the backend has the new threshold', (await apiGet('/api/risk')).levels.CRITICAL === 95);
check('the change is in the audit log', (await apiGet('/api/audit?action=risk_settings_changed')).length === 1);
await setValue('#risk-form [name="level.CRITICAL"]', '90');
await ev(`document.getElementById('risk-form').requestSubmit()`);
await waitFor(`document.querySelector('#risk-form [name="level.CRITICAL"]').value === '90'`);
check('the threshold can be restored', await waitFor(`fetch('/api/risk').then(r => r.json()).then(r => r.levels.CRITICAL === 90)`));
await shot('risk');

section('Reports');
await go('reports');
await sleep(600);
const reportList = await apiGet('/api/reports');
check('report rows match the API', (await count('#reports-body tr')) === reportList.length && reportList.length > 0, `${await count('#reports-body tr')} vs ${reportList.length}`);
for (const format of ['pdf', 'json', 'md', 'csv']) {
    const downloaded = await ev(`fetch(document.querySelector('#reports-body a[href*="format=${format}"]').href).then(async r => [r.status, (await r.text()).slice(0, 8)])`);
    check(`the ${format} download works`, downloaded[0] === 200 && (format !== 'pdf' || downloaded[1].startsWith('%PDF')), downloaded);
}
await click('#reports-body [data-action="view-report"]');
check('a report opens with every section', await waitFor(`['Overall security assessment', 'Executive summary', 'Detection engines', 'Model performance', 'Known limitations'].every(part => document.getElementById('drawer-body').innerText.includes(part))`));
await shot('report');
await click('[data-action="close-drawer"]');
await click('#reports-body [data-action="new-report"]');
check('a new version can be generated', await waitFor(`document.querySelectorAll('#reports-body tr').length === ${reportList.length + 1}`));

section('Audit log');
await go('audit');
await sleep(800);
const rowsBeforeLowAlert = await count('#audit-body tr');
await fetch(base + '/api/ingest/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify([
    { timestamp: new Date().toISOString(), source: 'endpoint', event_type: 'process_start', hostname: 'wks-77', user: 'lowrisk', process_name: '7z.exe', command_line: '7z.exe a /tmp/x.7z /reports' },
]) });
check('a low-risk alert with no incident still updates an open page', await waitFor(`document.querySelectorAll('#audit-body tr').length > ${rowsBeforeLowAlert}`));
// Automatic steps can still be arriving, so the page and the API are read until they agree
let audit = [];
let auditAgrees = false;
for (let i = 0; i < 20 && !auditAgrees; i++) {
    audit = await apiGet('/api/audit?limit=300');
    auditAgrees = (await count('#audit-body tr')) === audit.length;
    if (!auditAgrees) await sleep(300);
}
check('audit rows match the API', auditAgrees, `${await count('#audit-body tr')} vs ${audit.length}`);
check('the approval and its analyst are visible', (await text('#audit-body')).includes('response_approved') && (await text('#audit-body')).includes('Browser Analyst'));
await setValue('#audit-filter [name="action"]', 'response_executed');
await sleep(600);
const executedEntries = await apiGet('/api/audit?action=response_executed&limit=500');
check('audit filter works', executedEntries.length > 0 && (await count('#audit-body tr')) === executedEntries.length && (await ev(`[...document.querySelectorAll('#audit-body tr')].every(row => row.innerText.includes('response_executed'))`)));
await setValue('#audit-filter [name="action"]', '');
await sleep(400);
await shot('audit');

section('Approvals queue');
await go('approvals');
await setValue('#approvals-filter [name="status"]', 'PENDING');
await sleep(600);
const pendingNow = (await apiGet('/api/response-actions?status=PENDING&limit=200')).length;
check('the queue matches the API', (await count('#approvals-body .action-row')) === pendingNow);
const pendingActions = await apiGet('/api/response-actions?status=PENDING&limit=200');
check('the queue has one group per incident', (await count('#approvals-body .action-group')) === new Set(pendingActions.map(a => a.incident_id)).size);
const riskById = Object.fromEntries((await apiGet('/api/incidents?limit=1000')).map(i => [i.id, i.risk_score || 0]));
const groupRisks = (await ev(`[...document.querySelectorAll('#approvals-body .action-group')].map(g => Number(g.dataset.incident))`)).map(id => riskById[id]);
check('the highest-risk incident comes first', groupRisks.every((risk, i) => i === 0 || groupRisks[i - 1] >= risk), groupRisks);
await setValue('#approvals-filter [name="status"]', 'EXECUTED');
const executedOk = await waitFor(`document.getElementById('approvals-body').innerText.includes('No real system was changed')`);
check('filtering by state works', executedOk, (await text('#approvals-body')).slice(0, 200));
await setValue('#approvals-filter [name="status"]', 'PENDING');
await sleep(300);
await shot('approvals');
check('the page states the policy', (await text('.policy-strip')).includes('Critical and high risk') && (await text('.policy-strip')).includes('handled automatically'));
check('with real mode off, the page says responses are simulated', (await text('#mode-note-response')).includes('only in simulation') && (await text('#mode-note-sidebar')).includes('No real system is changed'));
check('each action offers the real commands', (await count('#approvals-body .manual-commands')) > 0 && await ev(`document.getElementById('approvals-body').textContent.includes('netsh advfirewall firewall add rule')`));
check('with real mode off, nothing offers a real block', !(await ev(`document.getElementById('approvals-body').textContent.includes('Block for real')`)));
await fetch(base + '/api/simulate/suspicious_process', { method: 'POST' });
await sleep(600);
const responseStats = await apiGet('/api/stats');
await setValue('#approvals-filter [name="status"]', 'AUTOMATED');
await sleep(600);
check('the response tiles match the API', (await text('#approvals-tiles')).replace(/\s+/g, ' ').includes(`Handled automatically ${responseStats.responses_automated}`) && (await text('#approvals-tiles')).replace(/\s+/g, ' ').includes(`Held at small risk ${responseStats.responses_held}`));
check('a small risk was handled automatically, and the page says so', responseStats.responses_automated > 0 && (await text('#approvals-body')).includes('Handled automatically'));
await setValue('#approvals-filter [name="status"]', 'HELD');
await sleep(600);
const heldActions = await apiGet('/api/response-actions?status=HELD&limit=200');
check('held actions are listed, and a person can still decide them', heldActions.length > 0 && (await count('#approvals-body .action-row')) === heldActions.length && (await count('#approvals-body [data-action="decide"]')) > 0);
await setValue('#approvals-filter [name="status"]', 'PENDING');
await sleep(300);

section('A failed API request');
await go('simulation');
await waitFor(`!!document.querySelector('[data-action="run-scenario"][data-id="benign"]') && !document.querySelector('[data-action="run-scenario"][data-id="benign"]').disabled`);
await ev(`window.__savedFetch = window.fetch; window.fetch = () => Promise.reject(new Error('network down'))`);
await click('[data-action="run-scenario"][data-id="benign"]');
check('a failed start shows the reason', await waitFor(`document.getElementById('sim-result').innerText.includes('Could not start') && document.getElementById('sim-result').innerText.includes('network down')`));
check('the run buttons work again afterwards', await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`));
await ev(`window.fetch = window.__savedFetch`);

section('Hostile data is inert');
await fetch(base + '/%3Cimg%20src%3Dx%20onerror%3D%22window.__pwned%3D1%22%3E');
await fetch(base + '/api/ingest/events', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify([
    { timestamp: new Date().toISOString(), source: 'endpoint', event_type: 'process_start', hostname: '<img src=x onerror="window.__pwned=2">', user: '"><script>window.__pwned=3</script>', process_name: 'mimikatz.exe', command_line: '<svg onload="window.__pwned=4">' },
]) });
await sleep(2500);
await go('events');
await sleep(800);
await go('detection');
await sleep(800);
const hostile = (await apiGet('/api/incidents?limit=1'))[0];
await ev(`window.location.hash = '#investigations/${hostile.id}'`);
await sleep(1200);
await go('approvals');
await sleep(600);
await go('audit');
await sleep(600);
await go('overview');
await sleep(500);
check('no injected script ran in any view', (await ev(`String(window.__pwned)`)) === 'undefined');
await ev(`window.location.hash = '#investigations/${hostile.id}'`);
await sleep(1000);
check('the hostile text is displayed as text', (await text('#incident-detail')).includes('onerror'));
check('no markup was injected', (await count('#incident-detail img, #incident-detail svg:not(.attack-graph)')) === 0);

section('NARS assistant');
const askNars = async question => {
    const before = await count('#nars-log .nars-bot');
    await setValue('#nars-input', question);
    await click('#nars-send');
    await waitFor(`document.querySelectorAll('#nars-log .nars-bot').length === ${before + 1} && !document.querySelector('#nars-log .fa-spin')`, 15000);
    return text('#nars-log .nars-bot:last-child');
};
await go('overview');
check('the launcher is on every page', (await ev(`getComputedStyle(document.getElementById('nars-launcher')).display`)) !== 'none');
await click('#nars-launcher');
check('the panel opens', (await ev(`document.getElementById('nars-panel').hidden`)) === false);
check('it says it is in local mode and nothing leaves the machine', (await text('#nars-mode')) === 'Local mode' && (await text('#nars-note')).includes('nothing leaves this machine'));
check('suggestions are offered', (await count('#nars-suggestions .nars-chip')) >= 2);
const expectedTop = (await apiGet('/api/incidents?status=OPEN&sort=risk&limit=1'))[0];
const triage = await askNars('What should I look at first?');
check('triage names the highest-risk open incident from the API', triage.includes(`Start with ${expectedTop.incident_uid}`), triage.slice(0, 200));
check('the answer shows what it read', triage.includes('Read: list incidents') && triage.includes('Built directly from stored data'));
await click(`#nars-log .nars-bot:last-child .nars-source[data-action="open-incident"]`);
await waitFor(`window.dashboard.view === 'investigations' && !!document.querySelector('#incident-detail .incident-head')`);
await waitFor(`document.querySelector('#incident-detail .incident-head h2')?.innerText.includes(${JSON.stringify(expectedTop.incident_uid)}) && document.querySelectorAll('#attack-graph-card .graph-node').length > 0`);
check('a source link opens the incident, with its attack graph', (await count('#attack-graph-card .graph-node')) > 0);
const apiGraph = (await apiGet(`/api/incidents/${expectedTop.id}`)).attack_graph;
check('the graph draws what the API returned', (await count('#attack-graph-card .graph-node')) === apiGraph.nodes.length && (await count('#attack-graph-card .graph-edge')) === apiGraph.edges.length);
check('the graph has a table version', (await text('#attack-graph-card details summary')).includes(`(${apiGraph.edges.length})`));
check('the open panel does not cover the page', await ev(`document.querySelector('#incident-detail .incident-head').getBoundingClientRect().right <= document.getElementById('nars-panel').getBoundingClientRect().left + 1`));
await ev(`document.getElementById('attack-graph-card').scrollIntoView()`);
await sleep(200);
await shot('attack_graph');
await ev(`window.scrollTo(0, 0)`);
const beforeNode = await count('#nars-log .nars-bot');
await ev(`document.querySelector('#attack-graph-card .graph-node').dispatchEvent(new MouseEvent('click', {bubbles:true}))`);
await waitFor(`document.querySelectorAll('#nars-log .nars-bot').length === ${beforeNode + 1} && !document.querySelector('#nars-log .fa-spin')`, 15000);
check('selecting a graph node asks NARS about it', (await text('#nars-log .nars-bot:last-child')).includes('What is stored about'));
const explained = await askNars(`Explain ${expectedTop.incident_uid}`);
check('NARS explains the incident with its real scores', explained.includes(`risk ${expectedTop.risk_score}/100`) && explained.includes('Why it was flagged'));
await shot('nars');
const pendingBefore = (await apiGet('/api/stats')).responses_pending;
const narsRefusal = await askNars('Approve all pending actions');
check('NARS refuses to act', narsRefusal.includes('I cannot do that'));
check('and nothing changed', (await apiGet('/api/stats')).responses_pending === pendingBefore);
const hostileAnswer = await askNars(`Explain ${hostile.incident_uid}`);
check('hostile log text stays text in an answer', (await count('#nars-log img, #nars-log script')) === 0 && (await ev(`String(window.__pwned)`)) === 'undefined', hostileAnswer.slice(0, 100));
const audited = await apiGet('/api/audit?action=nars_question&limit=50');
check('questions are in the audit log', audited.length >= 5);
await click('[data-action="nars-clear"]');
check('clear empties the conversation', (await count('#nars-log .nars-message')) === 0);
await click('#nars-panel [data-action="nars-toggle"]');
check('the panel closes and the launcher returns', (await ev(`document.getElementById('nars-panel').hidden`)) === true && (await ev(`getComputedStyle(document.getElementById('nars-launcher')).display`)) !== 'none');

section('ATT&CK coverage');
await go('attack');
await waitFor(`document.querySelectorAll('#attack-grid .attack-column').length > 0`);
const matrix = await apiGet('/api/attack-matrix');
check('every tactic has a column, gaps included', (await count('#attack-grid .attack-column')) === matrix.tactics.length && (await count('#attack-grid .attack-gap')) === matrix.tactics.filter(t => !t.techniques.length).length);
check('every technique from the API is drawn', (await count('#attack-grid .attack-cell')) === matrix.totals.techniques);
check('the tiles match the API', (await text('#attack-tiles')).includes(`${matrix.totals.tactics_with_rules} of ${matrix.totals.tactics}`));
const fired = matrix.tactics.flatMap(t => t.techniques).find(t => t.alerts > 0);
await click(`#attack-grid .attack-cell[data-id="${fired.id}"]`);
await sleep(200);
check('a technique opens its rules and tests', (await text('#drawer-title')).includes(fired.id) && (await text('#drawer-body')).includes(fired.rules[0].id));
await click('[data-action="close-drawer"]');
await assertControlsWired('attack');
await shot('attack');

section('Threat intelligence feed upload');
await setValue('#analyst-name', 'E2E Analyst');
await go('upload');
const feedFile = samplePath('threat_feed.csv');
const feedIocsBefore = (await apiGet('/api/iocs?limit=10000')).length;
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [feedFile] });
await click('[data-action="validate-dataset"]');
await waitFor(`!!document.querySelector('#feed-result')`);
check('validate only recognises the feed and stores nothing', (await text('#feed-result')).includes('RECOGNISED') && (await apiGet('/api/iocs?limit=10000')).length === feedIocsBefore);
await click('#upload-form button[type="submit"]');
await waitFor(`document.querySelector('#feed-result')?.innerText.includes('IMPORTED')`);
const feedText = await text('#feed-result');
check('the feed imports and reports what it left out', feedText.includes('private or reserved address') && feedText.includes('unsupported type: cve'), feedText.slice(0, 300));
check('the retro-hunt result is shown', feedText.includes('Retro-hunt of stored events'));
check('the feed itself is analyzed', feedText.includes('What this feed contains') && feedText.includes('Command and control') && feedText.includes('Indicator types'), feedText.slice(0, 300));
await click('#feed-result [data-action="test-feed"]');
await waitFor(`document.querySelector('#upload-result .verdict-headline')?.innerText.includes('THREATS DETECTED')`, 30000);
const feedTestText = await text('#upload-result');
check('testing the feed gives a real verdict from the pipeline', feedTestText.includes('THREATS DETECTED') && feedTestText.includes('IOC'), feedTestText.slice(0, 300));
await shot('feed_test');
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [feedFile] });
await click('#upload-form button[type="submit"]');
await waitFor(`document.querySelector('#feed-result')?.innerText.includes('added nothing new')`);
check('uploading the same feed again says that nothing changed', true);
await shot('feed_analysis');
await shot('feed_import');
await assertControlsWired('feed result');
await go('intel');
await waitFor(`document.getElementById('ioc-feeds').innerText.includes('threat_feed')`);
check('the feed is listed in Threat Intelligence', (await text('#ioc-feeds')).includes('threat_feed'));
await click('#ioc-feeds [data-action="remove-feed"][data-source="threat_feed"]');
await waitFor(`!document.getElementById('ioc-feeds').innerText.includes('threat_feed')`);
check('the feed can be removed', !(await text('#ioc-feeds')).includes('threat_feed'));
check('the import and removal are audited', (await apiGet('/api/audit?action=ioc_feed_imported&limit=5')).length === 2 && (await apiGet('/api/audit?action=ioc_feed_removed&limit=5')).length === 1);

section('Menu');
await go('overview');
const mainMenu = await ev(`[...document.querySelectorAll('nav > .nav-item')].map(item => item.dataset.view).join(',')`);
check('the main menu follows the workflow', mainMenu === 'overview,events,upload,detection,parameters,simulation,investigations,approvals,reports', mainMenu);
check('supporting pages are under More', (await ev(`[...document.querySelectorAll('#nav-more .nav-item')].map(item => item.dataset.view).join(',')`)) === 'intel,risk,attack,audit');
await ev(`document.getElementById('nav-more').open = false`);
await ev(`window.location.hash = '#risk'`);
await sleep(300);
check('More opens when one of its pages is showing', await ev(`document.getElementById('nav-more').open`));
await go('overview');

section('Live data flow');
await go('events');
await waitFor(`document.querySelectorAll('#live-flow .flow-band').length > 0`);
await setValue('#flow-range', '0');
await sleep(800);
const flowData = await apiGet('/api/flow?minutes=0');
check('the flow draws every link from the API', (await count('#live-flow .flow-band')) === flowData.links.length, await count('#live-flow .flow-band'));
check('the flow labels show true counts', (await text('#live-flow svg').catch(() => null)) !== undefined && (await ev(`document.querySelector('#live-flow svg').textContent`)).includes(flowData.nodes.find(n => n.id === 'verdict:threat').logs_in.toLocaleString()));
await ev(`window.__dots = 0; const original = window.dashboard.flow.addEvent.bind(window.dashboard.flow); window.dashboard.flow.addEvent = log => { window.__dots += 1; original(log); };`);
await fetch(base + '/api/simulate/brute_force', { method: 'POST' });
await waitFor(`window.__dots > 0`, 8000);
check('a real log reaching the socket reaches the flow', (await ev(`window.__dots`)) > 0);
check('the rate of arriving logs is shown', (await text('#flow-rate')).includes('arrived in the last minute'));
await sleep(600);
check('the flow has a table version', (await ev(`document.getElementById('flow-table').querySelectorAll('tbody tr').length`)) === flowData.links.length || (await ev(`document.getElementById('flow-table').querySelectorAll('tbody tr').length`)) > 0);
await shot('live_flow');
await setValue('#flow-origin', 'simulation');
await sleep(600);
check('the origin filter changes the flow', (await ev(`window.dashboard.flow.origin`)) === 'simulation');
await setValue('#flow-origin', '');
await setValue('#flow-range', '60');

section('Threat parameters');
await go('parameters');
await waitFor(`document.querySelectorAll('#parameters-rules tr').length > 0`);
const threatParameters = await apiGet('/api/threat-parameters');
check('every rule is listed with its limit', (await count('#parameters-rules tr')) === threatParameters.rules.length && (await text('#parameters-rules')).includes('IOA-001'));
check('normal, suspicious and threat are defined', (await text('#parameters-classes')).includes('THREAT') && (await text('#parameters-classes')).includes('NORMAL'));
await shot('parameters');
const threatLog = (await apiGet('/api/logs?limit=200&detected=1'))[0];
await go('events');
await ev(`window.dashboard.openEventDrawer(${threatLog.id})`);
await waitFor(`!!document.querySelector('#event-verdict .log-verdict')`);
const apiVerdict = await apiGet(`/api/logs/${threatLog.id}/verdict`);
check('a log shows its verdict and the parameters behind it', (await text('#event-verdict')).includes(apiVerdict.verdict));
await shot('log_verdict');
await click('[data-action="close-drawer"]');

section('Simulation impact');
await go('simulation');
await setValue('#sim-controls [name="speed"]', 'instant');
await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`, 15000);
await click('[data-action="run-scenario"][data-id="multi_stage"]');
await waitFor(`!!document.querySelector('#impact-panel')`, 20000);
const impactText = await text('#impact-panel');
check('the impact says what the threat affected', impactText.includes('The threat affected') && impactText.includes('before and after'), impactText.slice(0, 200));
check('it shows the parameters that crossed their limits', impactText.includes('IOA-007') && impactText.includes('90.0 MB') && impactText.includes('50.0 MB'));
check('it shows how the logs changed', impactText.includes('How the logs changed') && impactText.includes('Failed logins'));
await ev(`document.getElementById('impact-panel').scrollIntoView()`);
await sleep(200);
await shot('impact');
await assertControlsWired('impact');
check('each threat in the run shows its solution', await waitFor(`document.querySelectorAll('#sim-solutions .solution').length > 0`, 8000));
const solutionRun = await ev(`window.dashboard.solutionRun.view.run_id`);
const solutionRules = new Set((await apiGet(`/api/simulations/${solutionRun}/alerts`)).map(alert => alert.rule_id));
check('there is one solution for each detection', (await count('#sim-solutions .solution')) === solutionRules.size, `${await count('#sim-solutions .solution')} vs ${solutionRules.size}`);
const solutionText = await text('#sim-solutions');
check('it gives the real fix steps', solutionText.includes('reset the account') && solutionText.includes('SOC approval'), solutionText.slice(0, 200));
check('the actions and real commands are there', await ev(`document.getElementById('sim-solutions').textContent.includes('netsh advfirewall firewall add rule')`));
const solutionBlock = `#sim-solutions .action-row:has([data-action="decide"][data-decision="approve"])`;
await ev(`(() => { const row = document.querySelector(${q(solutionBlock)}); row.closest('details').open = true; row.querySelector('[data-decision="approve"]').click(); })()`);
check('an action can be approved from the results', await waitFor(`!!document.querySelector('#sim-solutions [data-action="execute"]')`));
check('the open section stays open after the decision', await ev(`!!document.querySelector('#sim-solutions .solution-actions[open] [data-action="execute"]')`));
await ev(`document.getElementById('sim-solutions').scrollIntoView()`);
await sleep(200);
await shot('solutions');
await assertControlsWired('solutions');
section('Solution Portal');
const portalData = await apiGet('/api/solutions');
check('the last run is chosen and marked', (await ev(`document.querySelector('#solution-filter [name=scenario]').value`)) === 'last-run' && (await text('#solution-run-note')).includes('Your last run') && (await text('#solution-list')).includes('In your last run'));
check('it lists only that run now', (await count('#solution-list .portal-item')) === solutionRules.size, `${await count('#solution-list .portal-item')} vs ${solutionRules.size}`);
await setValue('#solution-filter [name="scenario"]', '');
check('all threats are listed', await waitFor(`document.querySelectorAll('#solution-list .portal-item').length === ${portalData.threats.length}`));
check('a threat from the run comes first', [...solutionRules].includes(await ev(`document.querySelector('#solution-list .portal-item').dataset.rule`)));
await setValue('#solution-filter [name="q"]', 'password spraying');
check('search narrows the list', await waitFor(`document.querySelectorAll('#solution-list .portal-item').length === 1 && document.querySelector('#solution-list .portal-item').dataset.rule === 'IOA-015'`));
check('a single match opens by itself, with its solution', await ev(`document.querySelector('#solution-list .portal-item').open`) && (await text('#solution-list')).includes('How to fix it') && (await text('#solution-list')).includes('Who decides'));
check('it offers the real commands', await ev(`document.getElementById('solution-list').textContent.includes('netsh advfirewall firewall add rule')`));
await ev(`document.getElementById('solution-portal').scrollIntoView()`);
await sleep(200);
await shot('solution_portal');
await assertControlsWired('portal');
await setValue('#solution-filter [name="q"]', '');
await click('[data-action="open-scenario-solution"][data-id="exfil"]');
check('a scenario card opens its own solutions', await waitFor(`document.querySelector('#solution-filter [name=scenario]').value === 'exfil' && document.querySelector('#solution-list').innerText.includes('IOA-007')`));
await click('[data-action="open-scenario-solution"][data-id="benign"]');
check('normal activity says it has no threat to fix', await waitFor(`document.getElementById('solution-list').innerText.includes('no threat to fix')`));
await setValue('#solution-filter [name="scenario"]', '');
await ev(`window.scrollTo(0, 0)`);
await waitFor(`!document.querySelector('[data-action="run-scenario"]').disabled`, 15000);
await click('[data-action="run-scenario"][data-id="benign"]');
await waitFor(`document.querySelector('#impact-panel')?.innerText.includes('No asset was affected')`, 20000);
check('normal activity affects nothing', true);
check('and has nothing to fix', await waitFor(`document.getElementById('sim-solutions')?.innerText.includes('nothing to fix')`));
check('the portal is still there, and says the run raised nothing', (await text('#solution-run-note')).includes('raised no alert') && (await count('#solution-list .portal-item')) > 0);
await click('[data-action="open-portal"]');

section('Alert emails');
await go('risk');
await waitFor(`!!document.querySelector('#email-card h2')`);
check('the health panel is filled from the API', (await text('#overview-health')).includes('Rules loaded') && (await text('#overview-health')).includes('simulation'));
check('it says email is not set up, and how to set it up', (await text('#email-card')).includes('.env.example') && (await ev(`document.querySelector('[data-action="email-test"]').disabled`)) === true);

section('Landing page');
await send('Page.navigate', { url: base + '/' });
await sleep(2500);
check('the landing page loads', (await text('h1') || '').includes('genuine threats'));
const landingStats = await apiGet('/api/stats');
await waitFor(`document.querySelectorAll('#landing-tiles .tile').length === 4`);
check('its totals come from the API', (await text('#landing-tiles')).includes('Alerts raised') && (await text('#landing-tiles')).includes(landingStats.alerts.toLocaleString()));
await waitFor(`document.querySelectorAll('#landing-flow .flow-band').length > 0`);
check('it shows the live flow', (await count('#landing-flow .flow-band')) > 0);
check('its rule table shows real limits', (await text('#landing-rules')).includes('50.0 MB'));
check('no horizontal scroll', !(await ev(`document.documentElement.scrollWidth > window.innerWidth + 1`)));
await shot('landing');
await send('Page.navigate', { url: base + '/#upload' });
await sleep(2000);
check('an old dashboard link still works', (await ev(`location.pathname + location.hash`)) === '/dashboard#upload');
await send('Page.navigate', { url: base + '/dashboard' });
await sleep(2500);

section('Whole page');
const slowest = await ev(`performance.getEntriesByType('resource').filter(e => e.name.includes('/api/')).sort((a, b) => b.duration - a.duration).slice(0, 6)
    .map(e => ({ path: e.name.replace(location.origin, '').slice(0, 60), ms: Math.round(e.duration), queued: Math.round(e.requestStart - e.startTime), waiting: Math.round(e.responseStart - e.requestStart) }))`);
console.log(`  (slowest: ${JSON.stringify(slowest)})`);
const timings = await ev(`performance.getEntriesByType('resource').filter(e => e.name.includes('/api/') && !e.name.includes('/simulate/') && !e.name.includes('/ingest/')).map(e => Math.round(e.duration)).sort((a, b) => a - b)`);
console.log(`  (browser-measured API reads: ${timings.length} requests, median ${timings[Math.floor(timings.length / 2)]} ms, 95th percentile ${timings[Math.floor(timings.length * 0.95)]} ms, max ${timings[timings.length - 1]} ms)`);
check('all assets are served locally', external.length === 0, [...new Set(external)].slice(0, 5));
check('toasts never pile up over the page', (await count('#toasts .toast')) <= 3);
check('no console errors or exceptions', problems.length === 0, [...new Set(problems)].slice(0, 5).join(' | '));
for (const view of VIEWS) {
    await go(view);
    await assertControlsWired(`${view} with data`);
    const overflow = await ev(`document.documentElement.scrollWidth > window.innerWidth + 1`);
    check(`${view}: no horizontal page scroll at 1440px`, !overflow);
}
await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
await sleep(400);
for (const view of VIEWS) {
    await go(view);
    const overflow = await ev(`document.documentElement.scrollWidth > window.innerWidth + 1`);
    check(`${view}: no horizontal page scroll at phone width`, !overflow, await ev(`document.documentElement.scrollWidth`));
}
await go('overview');
await shot('phone');

const failed = results.filter(r => !r.passed);
console.log(`\n${'='.repeat(60)}\nTOTAL ${results.length} checks: ${results.length - failed.length} passed, ${failed.length} failed`);
failed.forEach(r => console.log(`  FAIL ${r.name}: ${String(r.detail).slice(0, 300)}`));
ws.close();
browser.kill();
server.kill();
await sleep(800);
try { rmSync(work, { recursive: true, force: true, maxRetries: 3 }); } catch { /* the OS may still hold the profile */ }
process.exit(failed.length);
