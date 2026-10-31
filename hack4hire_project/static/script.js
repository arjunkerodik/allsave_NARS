/**
 * ALLSAFE SOC dashboard. Every number and list on the page comes from a backend API.
 * Clicks are handled in one place: any element with data-action calls the method of that
 * name in ACTIONS, so a control cannot exist without something behind it.
 */

// Everything shown can originate from logs an attacker influences (paths, user agents, uploaded
// files), so all values must pass through esc() before reaching innerHTML.
function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function formatTime(value) {
    if (!value) return '--';
    const date = new Date(value);
    return isNaN(date) ? String(value) : date.toLocaleString([], { hour12: false });
}

function formatNumber(value) {
    return value === null || value === undefined ? '--' : Number(value).toLocaleString();
}

const chip = (value) => `<span class="chip chip-${esc(value)}">${esc(String(value ?? '').replace(/_/g, ' '))}</span>`;
const tags = (values) => (values || []).map(value => `<span class="tag">${esc(value)}</span>`).join('');
const plural = (count, word) => `${count} ${word}${Number(count) === 1 ? '' : 's'}`;
const reportLinks = (id) => [['pdf', 'PDF'], ['json&download=1', 'JSON'], ['md', 'MD'], ['csv', 'CSV']]
    .map(([format, label]) => `<a class="btn btn-sm" href="/api/reports/${esc(id)}?format=${format}" download>${label}</a>`).join(' ');
const emptyRow = (columns, message) => `<tr><td colspan="${columns}" class="empty">${esc(message)}</td></tr>`;

async function api(path, options) {
    const response = await fetch(path, options);
    let body = null;
    try {
        body = await response.json();
    } catch (e) {
        throw new Error('The server sent an unexpected response.');
    }
    if (response.status === 401) window.location.assign('/login');
    if (!response.ok) {
        const error = new Error(body.error || `Request failed (${response.status})`);
        error.body = body;
        throw error;
    }
    return body;
}

const postJson = (path, body) => api(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
});

function queryFrom(form) {
    const params = new URLSearchParams();
    new FormData(form).forEach((value, key) => { if (String(value).trim()) params.set(key, String(value).trim()); });
    return params;
}

function debounce(fn, wait) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}

// NARS writes **bold** and "- " lists. Everything is escaped first, so an answer quoting a log
// line, or a model following a hostile one, cannot add markup, links or images to the page.
function narsFormat(text) {
    const inline = line => esc(line).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    let html = '';
    let inList = false;
    String(text).split('\n').forEach(line => {
        const item = line.match(/^\s*[-*]\s+(.*)/);
        if (item) {
            html += `${inList ? '' : '<ul>'}<li>${inline(item[1])}</li>`;
            inList = true;
            return;
        }
        if (inList) html += '</ul>';
        inList = false;
        if (line.trim()) html += `<p>${inline(line)}</p>`;
    });
    return html + (inList ? '</ul>' : '');
}

const VIEW_TITLES = {
    overview: 'Security Overview', events: 'Live Stream', detection: 'Threat Detection',
    investigations: 'Incident Investigation', approvals: 'Response', simulation: 'Simulation Lab',
    intel: 'Threat Intelligence', upload: 'Log Analysis', audit: 'Audit Log', risk: 'Risk Settings', reports: 'Reports',
    attack: 'ATT&CK Coverage', parameters: 'Threat Parameters',
};

// Validated for dark surfaces: categorical slots for identity, the status palette for severity
const SOURCE_COLORS = { network: '#3987e5', endpoint: '#d95926', application: '#199e70' };
const SEVERITY_COLORS = { CRITICAL: '#d03b3b', HIGH: '#ec835a', MEDIUM: '#fab219', LOW: '#898781' };
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const LEVELS = SEVERITY_ORDER;
const MAX_TOASTS = 2;
const CHART_INK = { text: '#c3c2b7', muted: '#898781', grid: '#2c2c2a', axis: '#383835' };
const MAX_STREAM_ROWS = 200;
const QUEUE_LIMIT = 200;

const ORIGIN_HELP = {
    live: 'Real activity collected on this machine',
    simulation: 'Synthetic event from a Simulation Lab scenario',
    upload: 'From an uploaded log file',
    legacy: 'Stored before origins were recorded',
};

const ENTITY_LABELS = {
    src_ip: 'Source IP', dst_ip: 'Destination IP', hostname: 'Host', process_name: 'Process',
    session_id: 'Session', simulation_run: 'Simulation run', user: 'User',
};

const TILES = [
    { key: 'total', label: 'Logs processed', icon: 'fa-database', view: 'events' },
    { key: 'alerts', label: 'Alerts raised', icon: 'fa-triangle-exclamation', view: 'detection' },
    { key: 'responses_pending', label: 'Waiting for SOC approval', icon: 'fa-user-shield', view: 'approvals', filter: { status: 'PENDING' }, alert: true },
    { key: 'responses_automated', label: 'Handled automatically', icon: 'fa-robot', view: 'approvals', filter: { status: 'AUTOMATED' } },
];
const ORIGIN_LABELS = { dataset: 'log file' };
const DATA_ORIGIN_LABELS = { logs: 'Log file', simulation: 'Simulation', live: 'Live' };
const DATASET_KINDS = { upload: 'Uploaded', generated: 'Generated', feed: 'Threat feed' };
const LOG_VERDICTS = { threat: 'THREAT', suspicious: 'SUSPICIOUS', normal: 'NORMAL' };

const FILTER_FORMS = { detection: 'alerts-filter', investigations: 'incidents-filter', approvals: 'approvals-filter' };

// Fixed order, validated against the dark surface. The label on each node also carries its type.
const GRAPH_TYPES = {
    ip: { label: 'IP', color: '#3987e5' },
    user: { label: 'User', color: '#199e70' },
    host: { label: 'Host', color: '#d95926' },
    process: { label: 'Process', color: '#9085e9' },
    domain: { label: 'Domain', color: '#c98500' },
};
const GRAPH = { columnWidth: 210, nodeWidth: 158, nodeHeight: 42, rowGap: 16, pad: 10, labelChars: 19 };
const HEAT_STEPS = [
    { min: 100, label: '100 or more alerts' }, { min: 20, label: '20 to 99' },
    { min: 5, label: '5 to 19' }, { min: 1, label: '1 to 4' }, { min: 0, label: 'No alerts' },
];
const graphQuestion = (node) => (['user', 'host', 'process'].includes(node.type)
    ? `What is stored about ${node.type} ${node.label}?` : `What is stored about ${node.label}?`);
const NARS_HISTORY_MESSAGES = 6;

class ALLSAFEDashboard {
    constructor() {
        this.view = 'overview';
        this.stats = {};
        this.charts = {};
        this.incidentId = null;
        this.paused = false;
        this.missedWhilePaused = 0;
        this.oldestEventId = null;
        this.iocs = [];
        this.requestTokens = {};
        this.receivedAt = [];
        this.streamOrigin = null;
        this.scenarios = [];
        this.activeRun = null;
        this.runTimer = null;
        this.activeDataset = null;
        this.datasetTimer = null;
        this.matrix = null;
        this.narsHistory = [];
        this.narsIncident = null;
        this.narsBusy = false;
        this.flow = null;

        this.loadAnalyst();
        this.renderTiles();
        this.bindEvents();
        this.loadResponseMode();
        this.initializeSocket();
        this.route();
        this.refreshStats();
        this.loadAccount();
        this.loadNars();
    }

    /* ---------- Shared plumbing ---------- */

    // Returns a check for "is this still the newest request of its kind?". Without it, a slow
    // older response could arrive last and overwrite results for the filters now on screen.
    latest(kind) {
        const token = (this.requestTokens[kind] || 0) + 1;
        this.requestTokens[kind] = token;
        return () => this.requestTokens[kind] === token;
    }

    bindEvents() {
        document.addEventListener('click', (event) => {
            const target = event.target.closest('[data-action]');
            if (!target || target.disabled) return;
            const handler = ACTIONS[target.dataset.action];
            if (handler) handler.call(this, target, event);
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') this.closeDrawer();
            if (event.key === 'Enter' && event.target.matches('tr[data-action]')) event.target.click();
            if (event.key === 'Enter' && event.target.matches('g[data-action]')) {
                ACTIONS[event.target.dataset.action].call(this, event.target, event);
            }
            if (event.key === 'Enter' && !event.shiftKey && event.target.id === 'nars-input') {
                event.preventDefault();
                this.narsSubmit();
            }
        });
        window.addEventListener('hashchange', () => this.route());

        const reload = {
            'events-filter': () => this.loadEvents(),
            'alerts-filter': () => this.loadAlerts(),
            'incidents-filter': () => this.loadIncidents(),
            'approvals-filter': () => this.loadApprovals(),
            'audit-filter': () => this.loadAudit(),
            'solution-filter': () => this.renderSolutionPortal(),
        };
        Object.entries(reload).forEach(([id, fn]) => {
            const form = document.getElementById(id);
            const delayed = debounce(fn, 250);
            form.addEventListener('input', delayed);
            form.addEventListener('submit', (event) => { event.preventDefault(); fn(); });
        });

        document.getElementById('overview-range').addEventListener('change', () => this.loadOverview());
        document.getElementById('ioc-search').addEventListener('input', () => this.renderIocs());
        document.getElementById('analyst-name').addEventListener('input', (event) => this.saveAnalyst(event.target.value));
        document.getElementById('upload-form').addEventListener('submit', (event) => this.submitUpload(event));
        document.getElementById('generate-form').addEventListener('submit', (event) => this.submitGenerate(event));
        document.getElementById('risk-form').addEventListener('submit', (event) => this.submitRiskSettings(event));
        document.getElementById('ioc-form').addEventListener('submit', (event) => this.submitIoc(event));
        document.getElementById('ioc-import').addEventListener('submit', (event) => this.submitIocImport(event));
        document.getElementById('flow-range').addEventListener('change', (event) => this.flow.setFilter({ minutes: Number(event.target.value) }).catch(e => this.toast(e.message, true)));
        document.getElementById('flow-origin').addEventListener('change', (event) => this.flow.setFilter({ origin: event.target.value }).catch(e => this.toast(e.message, true)));
        const fileInput = document.getElementById('upload-file');
        const dropzone = document.getElementById('upload-drop');
        const showChosen = () => {
            document.getElementById('upload-file-name').textContent = fileInput.files[0] ? fileInput.files[0].name : 'Drop a log file here, or click to choose';
            dropzone.classList.toggle('dropzone-chosen', Boolean(fileInput.files[0]));
        };
        fileInput.addEventListener('change', showChosen);
        ['dragenter', 'dragover'].forEach(name => dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.add('dropzone-over'); }));
        ['dragleave', 'drop'].forEach(name => dropzone.addEventListener(name, (event) => { event.preventDefault(); dropzone.classList.remove('dropzone-over'); }));
        dropzone.addEventListener('drop', (event) => {
            if (event.dataTransfer.files.length) {
                fileInput.files = event.dataTransfer.files;
                showChosen();
            }
        });
        document.getElementById('nars-form').addEventListener('submit', (event) => { event.preventDefault(); this.narsSubmit(); });
    }

    initializeSocket() {
        const status = document.getElementById('conn-status');
        const setStatus = (online) => {
            status.className = `status-pill ${online ? 'online' : 'offline'}`;
            status.innerHTML = `<i class="fa-solid fa-circle" aria-hidden="true"></i> ${online ? 'Live updates on' : 'Live updates off'}`;
        };
        this.socket = io({ transports: ['polling', 'websocket'] });
        this.socket.on('connect', () => setStatus(true));
        this.socket.on('disconnect', () => setStatus(false));
        this.socket.on('new_log', (log) => this.onNewLog(log));
        this.socket.on('stats_update', (stats) => {
            this.applyStats(stats);
            if (this.view === 'overview') this.loadOverview();
        });
        this.socket.on('new_incident', (incident) => {
            this.toast(`New ${incident.severity} incident: ${incident.title}`);
            this.onDataChanged();
        });
        this.socket.on('incident_update', (incident) => {
            this.onDataChanged();
            if (this.view === 'investigations' && this.incidentId === incident.id && !this.isEditing('incident-detail')) {
                this.loadIncidentDetail(incident.id);
            }
        });
        this.socket.on('response_update', () => this.onDataChanged());
        this.socket.on('alerts_changed', () => this.onDataChanged());
        this.socket.on('notification', (item) => {
            this.toast(item.message);
            this.refreshStats();
            if (this.view === 'risk') this.loadRisk();
        });
        this.socket.on('simulation_progress', (progress) => {
            if (progress.run_id === this.activeRun) this.refreshRun();
        });
        this.socket.on('dataset_progress', (progress) => {
            if (progress.dataset_id === this.activeDataset) this.refreshDataset();
        });
        setInterval(() => { if (this.view === 'events') this.renderStreamStats(); }, 5000);
    }

    // Do not redraw a form under an analyst who is typing in it
    isEditing(containerId) {
        const active = document.activeElement;
        return active && active.matches('input, textarea, select') && document.getElementById(containerId).contains(active);
    }

    onDataChanged() {
        const view = this.view;
        if (view === 'overview') this.loadOverview();
        if (view === 'detection') this.loadAlerts();
        if (view === 'investigations') this.loadIncidents();
        if (view === 'approvals' && !this.isEditing('approvals-body') && !document.querySelector('#approvals-body details[open]')) this.loadApprovals();
        if (view === 'audit') this.loadAudit();
        if (view === 'risk') this.loadRisk();
    }

    toast(message, isError = false) {
        const element = document.createElement('div');
        element.className = `toast${isError ? ' toast-error' : ''}`;
        element.textContent = message;
        const toasts = document.getElementById('toasts');
        toasts.prepend(element);
        while (toasts.children.length > MAX_TOASTS) toasts.lastElementChild.remove();
        setTimeout(() => element.remove(), isError ? 9000 : 6000);
    }

    showError(containerId, error, columns) {
        const message = `Could not load this: ${error.message}`;
        document.getElementById(containerId).innerHTML = columns
            ? `<tr><td colspan="${columns}"><div class="notice notice-error">${esc(message)}</div></td></tr>`
            : `<div class="notice notice-error">${esc(message)}</div>`;
    }

    route() {
        const [view, id] = window.location.hash.replace('#', '').split('/');
        this.view = VIEW_TITLES[view] ? view : 'overview';
        document.getElementById('view-title').textContent = VIEW_TITLES[this.view];
        document.querySelectorAll('.view').forEach(section => { section.hidden = section.id !== `view-${this.view}`; });
        document.querySelectorAll('.nav-item').forEach(item => {
            const active = item.dataset.view === this.view;
            item.classList.toggle('active', active);
            if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
        });
        // Keep the current page visible in the menu when it is one of the secondary ones
        const more = document.getElementById('nav-more');
        if (more.querySelector('.nav-item.active')) more.open = true;
        this.closeDrawer();
        const loaders = {
            overview: () => this.loadOverview(),
            events: () => this.openEventStream(),
            detection: () => { this.loadAlerts(); this.loadRules(); },
            investigations: () => {
                this.loadIncidents();
                if (id) this.loadIncidentDetail(Number(id));
            },
            approvals: () => this.loadApprovals(),
            attack: () => this.loadAttackMatrix(),
            parameters: () => this.loadParameters(),
            simulation: () => this.loadSimulation(),
            intel: () => this.loadIocs(),
            upload: () => this.loadDatasets(),
            risk: () => this.loadRisk(),
            reports: () => this.loadReports(),
            audit: () => this.loadAudit(),
        };
        loaders[this.view]();
        this.renderNarsSuggestions();
    }

    navigate(view, id) {
        const hash = id ? `#${view}/${id}` : `#${view}`;
        if (window.location.hash === hash) this.route(); else window.location.hash = hash;
    }

    /* ---------- Analyst identity ---------- */

    loadAnalyst() {
        try {
            document.getElementById('analyst-name').value = localStorage.getItem('allsafe-analyst') || '';
        } catch (e) { /* Storage can be blocked. The name is then simply re-entered. */ }
    }

    saveAnalyst(name) {
        try {
            localStorage.setItem('allsafe-analyst', name);
        } catch (e) { /* See loadAnalyst */ }
    }

    requireAnalyst() {
        const input = document.getElementById('analyst-name');
        const name = input.value.trim();
        if (!name) {
            this.toast('Enter your analyst name at the top of the page. It goes in the audit log.', true);
            input.focus();
        }
        return name;
    }

    /* ---------- Overview ---------- */

    renderTiles() {
        document.getElementById('tiles').innerHTML = TILES.map(tile => `
            <button class="tile${tile.alert ? ' tile-alert' : ''}" data-action="open-tile" data-key="${tile.key}">
                <span class="tile-label"><i class="fa-solid ${tile.icon}" aria-hidden="true"></i> ${esc(tile.label)}</span>
                <span class="tile-value" id="tile-${tile.key}" data-stat="${tile.key}">--</span>
            </button>`).join('');
    }

    async refreshStats() {
        try {
            this.applyStats(await api('/api/stats'));
        } catch (e) {
            this.toast(`Could not load statistics: ${e.message}`, true);
        }
    }

    applyStats(stats) {
        this.stats = stats;
        document.querySelectorAll('[data-stat]').forEach(element => {
            element.textContent = formatNumber(stats[element.dataset.stat]);
        });
        const badge = (id, value) => {
            const element = document.getElementById(id);
            element.hidden = !value;
            element.textContent = value || '';
        };
        badge('badge-open', stats.incidents_open);
        badge('badge-pending', stats.responses_pending);
        badge('badge-notifications', stats.notifications_unread);
        const more = document.getElementById('nav-more');
        if (more && stats.notifications_unread === undefined) more.open = false;
    }

    async loadOverview() {
        const minutes = document.getElementById('overview-range').value;
        const isLatest = this.latest('overview');
        try {
            const [overview, incidents, stats] = await Promise.all([
                api(`/api/overview?minutes=${minutes}`),
                api('/api/incidents?status=OPEN&sort=risk&limit=5'),
                api('/api/stats'),
            ]);
            if (!isLatest()) return;
            this.applyStats(stats);
            this.renderLatestLog(overview.latest_log);
            this.renderVolumeChart(overview);
            this.renderSeverityChart(overview);
            this.renderRulesChart(overview);
            document.getElementById('overview-range-note').textContent =
                `${formatNumber(overview.events_in_range)} logs arrived in this range. The tiles above cover everything stored.`;
            this.renderOverviewIncidents(incidents);
        } catch (e) {
            this.showError('overview-incidents', e);
        }
    }

    chartOptions(extra = {}) {
        return {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            plugins: {
                legend: { display: false },
                tooltip: { backgroundColor: '#232321', titleColor: '#f0efec', bodyColor: '#c3c2b7', borderColor: CHART_INK.axis, borderWidth: 1 },
            },
            ...extra,
        };
    }

    // Keep the existing chart object and swap its data, so a refresh does not flash
    drawChart(name, config, hasData) {
        const box = document.getElementById(`chart-${name}`).parentElement;
        const showingTable = !document.getElementById(`table-${name}`).hidden;
        document.getElementById(`empty-${name}`).hidden = hasData;
        box.hidden = !hasData || showingTable;
        if (!hasData) {
            document.getElementById(`table-${name}`).hidden = true;
        }
        if (this.charts[name]) {
            this.charts[name].data = config.data;
            this.charts[name].update('none');
        } else if (hasData) {
            this.charts[name] = new Chart(document.getElementById(`chart-${name}`), config);
        }
    }

    renderVolumeChart(overview) {
        const labels = overview.timeline.map(point => new Date(point.time)
            .toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }));
        const useDates = overview.bucket_seconds >= 21600;
        const axisLabels = useDates ? overview.timeline.map(point => new Date(point.time).toLocaleDateString()) : labels;
        const sources = ['network', 'endpoint', 'application'];
        const hasData = overview.events_in_range > 0;
        this.drawChart('volume', {
            type: 'line',
            data: {
                labels: axisLabels,
                datasets: sources.map(source => ({
                    label: source[0].toUpperCase() + source.slice(1),
                    data: overview.timeline.map(point => point[source]),
                    borderColor: SOURCE_COLORS[source],
                    backgroundColor: SOURCE_COLORS[source],
                    borderWidth: 2,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    tension: 0,
                })),
            },
            options: this.chartOptions({
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    ...this.chartOptions().plugins,
                    legend: { display: true, position: 'top', align: 'end', labels: { color: CHART_INK.text, boxWidth: 12, boxHeight: 2 } },
                },
                scales: {
                    x: { grid: { display: false }, border: { color: CHART_INK.axis }, ticks: { color: CHART_INK.muted, maxTicksLimit: 8, maxRotation: 0 } },
                    y: { beginAtZero: true, grid: { color: CHART_INK.grid }, border: { display: false }, ticks: { color: CHART_INK.muted, precision: 0, maxTicksLimit: 5 } },
                },
            }),
        }, hasData);
        document.getElementById('table-volume').innerHTML = `
            <table><thead><tr><th>Period starting</th><th class="num">Network</th><th class="num">Endpoint</th><th class="num">Application</th></tr></thead>
            <tbody>${overview.timeline.map((point, index) => `<tr><td>${esc(axisLabels[index])}</td>
                <td class="num">${esc(point.network)}</td><td class="num">${esc(point.endpoint)}</td><td class="num">${esc(point.application)}</td></tr>`).join('')}</tbody></table>`;
    }

    barOptions() {
        return this.chartOptions({
            indexAxis: 'y',
            scales: {
                x: { beginAtZero: true, grid: { color: CHART_INK.grid }, border: { display: false }, ticks: { color: CHART_INK.muted, precision: 0, maxTicksLimit: 5 } },
                y: { grid: { display: false }, border: { color: CHART_INK.axis }, ticks: { color: CHART_INK.text, autoSkip: false } },
            },
        });
    }

    renderSeverityChart(overview) {
        // JSON object keys arrive sorted alphabetically, so the order has to be set here
        const names = SEVERITY_ORDER;
        const values = names.map(name => overview.alerts_by_severity[name]);
        this.drawChart('severity', {
            type: 'bar',
            data: {
                labels: names,
                datasets: [{ label: 'Alerts', data: values, backgroundColor: names.map(name => SEVERITY_COLORS[name]), borderRadius: 4, maxBarThickness: 18 }],
            },
            options: this.barOptions(),
        }, values.some(Boolean));
        document.getElementById('table-severity').innerHTML = `
            <table><thead><tr><th>Severity</th><th class="num">Alerts</th></tr></thead>
            <tbody>${names.map((name, index) => `<tr><td>${chip(name)}</td><td class="num">${esc(values[index])}</td></tr>`).join('')}</tbody></table>`;
    }

    renderRulesChart(overview) {
        const rules = overview.top_rules;
        this.drawChart('rules', {
            type: 'bar',
            data: {
                labels: rules.map(rule => rule.rule_id),
                datasets: [{ label: 'Alerts', data: rules.map(rule => rule.alerts), backgroundColor: '#3987e5', borderRadius: 4, maxBarThickness: 18 }],
            },
            options: (() => {
                const options = this.barOptions();
                options.plugins.tooltip.callbacks = { title: (items) => rules[items[0].dataIndex] ? `${rules[items[0].dataIndex].rule_id} ${rules[items[0].dataIndex].rule_name}` : '' };
                return options;
            })(),
        }, rules.length > 0);
        document.getElementById('table-rules').innerHTML = `
            <table><thead><tr><th>Rule</th><th>Name</th><th class="num">Alerts</th></tr></thead>
            <tbody>${rules.map(rule => `<tr><td>${esc(rule.rule_id)}</td><td>${esc(rule.rule_name)}</td><td class="num">${esc(rule.alerts)}</td></tr>`).join('')}</tbody></table>`;
    }

    renderLatestLog(latest) {
        const element = document.getElementById('latest-log');
        if (!latest) {
            element.innerHTML = `<article class="card latest-log"><div class="latest-log-text"><span class="muted">Latest log analysis</span><strong>No log file has been analyzed yet</strong></div>
                <button class="btn btn-primary" data-action="nav" data-view="upload"><i class="fa-solid fa-file-arrow-up" aria-hidden="true"></i> Add a log file</button></article>`;
            return;
        }
        const facts = latest.kind === 'feed'
            ? `${formatNumber(latest.indicators)} indicators imported`
            : `${formatNumber(latest.events)} logs, ${formatNumber(latest.alerts || 0)} alerts, ${formatNumber(latest.incidents || 0)} incidents`;
        element.innerHTML = `<article class="card latest-log latest-log-${esc(latest.verdict)}">
            <div class="latest-log-text"><span class="muted">Latest log analysis, ${esc(formatTime(latest.created_at))}</span>
                <strong class="break">${esc(latest.name)}</strong><span>${esc(facts)}</span></div>
            ${chip(latest.verdict)}
            <button class="btn" data-action="nars-open-dataset" data-id="${esc(latest.dataset_id)}">Open the result</button>
            <button class="btn btn-primary" data-action="nav" data-view="upload"><i class="fa-solid fa-file-arrow-up" aria-hidden="true"></i> Add a log file</button></article>`;
    }

    responseChip(incident) {
        const status = incident.response_status;
        if (status === 'AWAITING_APPROVAL') return '<span class="tag tag-soc"><i class="fa-solid fa-user-shield" aria-hidden="true"></i> SOC approval</span>';
        if (status === 'AUTOMATED') return '<span class="tag tag-auto"><i class="fa-solid fa-robot" aria-hidden="true"></i> Automated</span>';
        if (status === 'COMPLETE') return '<span class="tag">Decided</span>';
        return '<span class="muted">None</span>';
    }

    originTag(incident) {
        return `<span class="tag" title="${esc(incident.data_name || '')}">${esc(DATA_ORIGIN_LABELS[incident.data_origin] || 'Live')}</span>`;
    }

    renderOverviewIncidents(incidents) {
        const element = document.getElementById('overview-incidents');
        if (!incidents.length) {
            element.innerHTML = '<p class="empty">No open incidents.</p>';
            return;
        }
        element.innerHTML = `<div class="scroll-x"><table><thead><tr><th>Incident</th><th>Severity</th><th class="num">Confidence</th><th class="num">Risk</th><th>Response</th><th>From</th><th>Status</th><th>Last activity</th></tr></thead><tbody>
            ${incidents.map(incident => `<tr class="clickable" tabindex="0" data-action="open-incident" data-id="${esc(incident.id)}">
                <td class="break"><strong>${esc(incident.incident_uid || '#' + incident.id)}</strong> ${esc(incident.title)}</td>
                <td>${chip(incident.severity)}</td>
                <td class="num">${incident.confidence === null ? '--' : esc(incident.confidence) + '%'}</td>
                <td class="num">${incident.risk_score === null ? '--' : esc(incident.risk_score)}</td>
                <td class="nowrap">${this.responseChip(incident)}</td>
                <td>${this.originTag(incident)}</td>
                <td>${chip(incident.status)}</td>
                <td class="nowrap">${esc(formatTime(incident.last_seen || incident.timestamp))}</td></tr>`).join('')}
        </tbody></table></div>`;
    }

    captureText(capture) {
        return {
            live: 'Live packet capture',
            simulated: 'Unavailable: showing labelled simulated traffic',
            unavailable: 'Unavailable: needs administrator rights and Npcap. Network data comes from uploads and simulations.',
            starting: 'Starting',
        }[capture] || 'Unknown';
    }

    renderHealth(health, stats, behavioralRules) {
        const engine = health.engine;
        const origins = Object.entries(stats.by_origin || {}).map(([origin, total]) => `${origin} ${formatNumber(total)}`).join(', ');
        const facts = [
            ['Detection engine', engine.last_run ? `Running, last pass ${formatTime(engine.last_run)}` : 'Waiting for first pass'],
            ['Events analyzed since start', formatNumber(engine.events_processed)],
            ['Stored events by origin', origins || 'None yet'],
            ['Engine errors', formatNumber(engine.errors)],
            ['Rules loaded', `${health.rules_loaded}${health.rule_errors.length ? `, ${health.rule_errors.length} with errors` : ''}`],
            ['Behavioral checks', `${behavioralRules} running, compared with each entity's own history`],
            ['Network capture', this.captureText(health.network_capture)],
            ['Endpoint monitoring', health.endpoint_monitoring ? 'Running' : 'Not running'],
            ['Saved network model', health.ml_model_available ? 'Used only on flow data with its 78 CIC-IDS2017 features. Not validated, so no accuracy is claimed.' : 'Not available. Flow data cannot be classified.'],
            ['Anomaly model', health.anomaly_model_available ? 'Runs on uploaded and simulated data. Its findings are never treated as confirmed.' : 'Not available.'],
        ];
        document.getElementById('overview-health').innerHTML = facts.map(([term, value]) => `<dt>${esc(term)}</dt><dd>${esc(value)}</dd>`).join('');
    }

    /* ---------- Live event stream ---------- */

    async openEventStream() {
        try {
            const [facets, health] = await Promise.all([api('/api/logs/facets'), api('/api/health')]);
            const form = document.getElementById('events-filter');
            const fill = (name, values) => {
                const select = form.elements[name];
                const current = select.value;
                select.innerHTML = '<option value="">All</option>' + values.map(value => `<option>${esc(value)}</option>`).join('');
                select.value = values.includes(current) ? current : '';
            };
            fill('source', facets.sources);
            fill('event_type', facets.event_types);
            fill('origin', facets.origins);
            if (this.streamOrigin) {
                form.elements.origin.value = this.streamOrigin;
                this.streamOrigin = null;
            }
            document.getElementById('capture-note').textContent = health.network_capture === 'live' ? 'Live packet capture is on.' : '';
        } catch (e) {
            this.toast(`Could not load filters: ${e.message}`, true);
        }
        this.loadEvents();
        this.openFlow();
    }

    openFlow() {
        if (!this.flow) {
            this.flow = new LiveFlow(document.getElementById('live-flow'), { height: 300 });
            this.flow.onData = (data) => {
                document.getElementById('flow-table').innerHTML = this.flow.tableHtml();
                this.renderFlowStats(data);
            };
            setInterval(() => this.renderFlowRate(), 2000);
        }
        this.flow.refresh().catch(e => { document.getElementById('flow-rate').textContent = e.message; });
        this.renderFlowRate();
    }

    renderFlowStats(data) {
        const count = (id) => (data.nodes.find(node => node.id === id) || {}).logs_in || 0;
        const stat = (value, label, className = '') => `<div class="stream-stat ${className}"><strong>${formatNumber(value)}</strong><span>${esc(label)}</span></div>`;
        document.getElementById('flow-stats').innerHTML = stat(data.total, 'logs in this range')
            + stat(count('verdict:threat'), 'threat evidence', 'stat-threat')
            + stat(count('verdict:suspicious'), 'suspicious', 'stat-suspicious')
            + stat(count('verdict:normal'), 'no detection')
            + stat(count('outcome:incident'), 'logs in an incident');
    }

    renderFlowRate() {
        if (this.view === 'events' && this.flow) document.getElementById('flow-rate').textContent = `${plural(this.flow.eventsLastMinute(), 'log')} arrived in the last minute`;
    }

    async loadEvents() {
        const body = document.getElementById('events-body');
        const isLatest = this.latest('events');
        try {
            const logs = await api(`/api/logs?limit=100&${queryFrom(document.getElementById('events-filter'))}`);
            if (!isLatest()) return;
            body.innerHTML = logs.length ? logs.map(log => this.eventRow(log)).join('') : emptyRow(8, 'No logs match these filters.');
            this.oldestEventId = logs.length ? logs[logs.length - 1].id : null;
            document.getElementById('events-older').disabled = logs.length < 100;
            this.renderStreamStats();
        } catch (e) {
            this.showError('events-body', e, 8);
        }
    }

    async loadOlderEvents() {
        if (!this.oldestEventId) return;
        const params = queryFrom(document.getElementById('events-filter'));
        params.set('before_id', this.oldestEventId);
        try {
            const logs = await api(`/api/logs?limit=100&${params}`);
            document.getElementById('events-body').insertAdjacentHTML('beforeend', logs.map(log => this.eventRow(log)).join(''));
            if (logs.length) this.oldestEventId = logs[logs.length - 1].id;
            document.getElementById('events-older').disabled = logs.length < 100;
        } catch (e) {
            this.toast(`Could not load older events: ${e.message}`, true);
        }
    }

    eventRow(log) {
        const detections = log.detections || [];
        const rules = [...new Set(detections.map(d => d.rule_id))];
        const incident = detections.map(d => d.incident_id).find(Boolean);
        const { verdict } = (this.flow || LiveFlow.prototype).classify(log);
        return `<tr class="clickable stream-row stream-${verdict}${rules.length ? ' detected' : ''}" tabindex="0" data-action="open-event" data-id="${esc(log.id)}">
            <td class="nowrap">${esc(formatTime(log.timestamp))}</td>
            <td>${chip(LOG_VERDICTS[verdict])}</td>
            <td>${esc(log.source)}</td>
            <td>${esc(log.event_type)}</td>
            <td class="break"><span class="clamp" title="${esc(log.summary)}">${esc(log.summary)}</span></td>
            <td>${rules.length ? tags(rules) : '<span class="muted nowrap">No detection</span>'}</td>
            <td>${incident ? `<button class="link" data-action="open-incident" data-id="${esc(incident)}">#${esc(incident)}</button>` : '<span class="muted">--</span>'}</td>
            <td><span class="tag" title="${esc(ORIGIN_HELP[log.origin || 'legacy'] || '')}">${esc(ORIGIN_LABELS[log.origin] || log.origin || 'legacy')}</span></td>
        </tr>`;
    }

    renderStreamStats() {
        const cutoff = Date.now() - 60000;
        this.receivedAt = this.receivedAt.filter(time => time >= cutoff);
        const shown = document.querySelectorAll('#events-body tr.clickable').length;
        const detected = document.querySelectorAll('#events-body tr.detected').length;
        document.getElementById('stream-stats').textContent =
            `Showing ${formatNumber(shown)}, ${formatNumber(detected)} with detections. ${plural(this.receivedAt.length, 'log')} received in the last minute.`;
    }

    matchesEventFilter(log) {
        const params = queryFrom(document.getElementById('events-filter'));
        if (params.get('source') && log.source !== params.get('source')) return false;
        if (params.get('event_type') && log.event_type !== params.get('event_type')) return false;
        if (params.get('origin') && log.origin !== params.get('origin')) return false;
        if (params.get('detected') && !(log.detections || []).length) return false;
        if (params.get('exclude_system') && log.event_category === 'system') return false;
        const text = (params.get('q') || '').toLowerCase();
        if (text && !JSON.stringify(log).toLowerCase().includes(text)) return false;
        return true;
    }

    onNewLog(log) {
        this.receivedAt.push(Date.now());
        if (this.flow) this.flow.addEvent(log);
        if (this.view !== 'events') return;
        this.renderStreamStats();
        if (!this.matchesEventFilter(log)) return;
        if (this.paused) {
            this.missedWhilePaused += 1;
            this.updatePauseButton();
            return;
        }
        const body = document.getElementById('events-body');
        const placeholder = body.querySelector('.empty');
        if (placeholder) placeholder.parentElement.remove();
        body.insertAdjacentHTML('afterbegin', this.eventRow(log));
        body.firstElementChild.classList.add('row-new');
        while (body.children.length > MAX_STREAM_ROWS) {
            body.lastElementChild.remove();
            this.oldestEventId = Number(body.lastElementChild.dataset.id);
        }
        this.renderStreamStats();
    }

    updatePauseButton() {
        const button = document.getElementById('events-pause');
        button.innerHTML = this.paused
            ? `<i class="fa-solid fa-play" aria-hidden="true"></i> Resume${this.missedWhilePaused ? ` (${this.missedWhilePaused} new)` : ''}`
            : '<i class="fa-solid fa-pause" aria-hidden="true"></i> Pause';
    }

    async openEventDrawer(id) {
        this.openDrawer('Event details', '<p class="muted">Loading...</p>');
        try {
            const log = await api(`/api/logs/${id}`);
            const hidden = new Set(['raw_event', 'normalized_fields', 'detections', 'summary', 'id']);
            const fields = Object.entries(log).filter(([key, value]) => !hidden.has(key) && value !== null && value !== '');
            const detections = (log.detections || []).map(d => `<li><strong>${esc(d.rule_id)}</strong> ${chip(d.severity)}
                ${d.incident_id ? `<button class="link" data-action="open-incident" data-id="${esc(d.incident_id)}">Open incident #${esc(d.incident_id)}</button>` : ''}</li>`).join('');
            document.getElementById('drawer-body').innerHTML = `
                <p>${esc(log.summary)}</p>
                <div id="event-verdict"><p class="muted">Measuring this log against the rules...</p></div>
                <h3 class="section-title">Detections</h3>
                ${detections ? `<ul>${detections}</ul>` : '<p class="muted">No rule or indicator matched this event.</p>'}
                <h3 class="section-title">Normalized fields</h3>
                <dl class="facts">${fields.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`).join('')}</dl>
                ${log.normalized_fields ? `<h3 class="section-title">Source-specific fields</h3><pre>${esc(JSON.stringify(log.normalized_fields, null, 2))}</pre>` : ''}
                <h3 class="section-title">Original record</h3>
                ${log.raw_event ? `<pre>${esc(JSON.stringify(log.raw_event, null, 2))}</pre>` : '<p class="muted">Stored before raw records were preserved.</p>'}`;
            this.loadEventVerdict(id);
        } catch (e) {
            this.showError('drawer-body', e);
        }
    }

    async loadEventVerdict(id) {
        const holder = () => document.getElementById('event-verdict');
        try {
            const result = await api(`/api/logs/${id}/verdict`);
            if (holder()) holder().innerHTML = this.renderLogVerdict(result);
        } catch (e) {
            if (holder()) holder().innerHTML = `<div class="notice notice-error">Could not measure this log: ${esc(e.message)}</div>`;
        }
    }

    renderLogVerdict(result) {
        const rules = result.rules.map(row => `<div class="verdict-rule">
                <div><strong>${esc(row.id)}</strong> ${esc(row.name)} ${row.confirmed ? chip('THREAT') : row.alert_id ? chip('SUSPICIOUS') : ''}</div>
                <div class="parameter-bar"><span>${esc(row.observed_text)} ${esc(row.measure)}</span><span>limit ${esc(row.threshold_text)} in ${esc(row.window_seconds)} s</span><strong>${row.threshold_reached ? 'Limit reached' : 'Limit not reached'}</strong></div>
                <div class="table-wrap"><table><thead><tr><th>Field</th><th>This log has</th><th>The rule needs</th><th>Met</th></tr></thead><tbody>
                ${row.checks.map(check => `<tr><td>${esc(check.field)}</td><td class="break">${esc(check.actual === null || check.actual === undefined ? '--' : check.actual)}</td><td class="break">${esc(check.required)}</td><td>${check.met ? 'Yes' : 'No'}</td></tr>`).join('')}
                </tbody></table></div></div>`).join('');
        const other = result.other_evidence.map(item => `<div class="verdict-rule"><div><strong>${esc(item.rule_id)}</strong> ${esc(item.name)} ${chip(item.confirmed ? 'THREAT' : 'SUSPICIOUS')}</div><p class="muted">${esc(item.explanation)}</p></div>`).join('');
        return `<div class="log-verdict log-verdict-${esc(result.verdict)}" role="status"><strong>${esc(result.verdict)}</strong><p>${esc(result.statement)}</p></div>${rules}${other}
            <p class="muted">Checked against ${esc(result.rules_checked)} rules. <button class="link" data-action="nav" data-view="parameters">See every rule's parameters</button></p>`;
    }

    openDrawer(title, html) {
        document.getElementById('drawer-title').textContent = title;
        document.getElementById('drawer-body').innerHTML = html;
        document.getElementById('drawer').hidden = false;
    }

    closeDrawer() {
        document.getElementById('drawer').hidden = true;
    }

    /* ---------- Threat detection ---------- */

    async loadAlerts() {
        const body = document.getElementById('alerts-body');
        const isLatest = this.latest('alerts');
        try {
            const alerts = await api(`/api/alerts?limit=200&${queryFrom(document.getElementById('alerts-filter'))}`);
            if (!isLatest()) return;
            body.innerHTML = alerts.length ? alerts.map(alert => `
                <tr class="clickable" tabindex="0" data-action="open-alert" data-id="${esc(alert.id)}">
                    <td class="nowrap">${esc(formatTime(alert.last_seen))}</td>
                    <td>${chip(alert.severity)}</td>
                    <td><strong>${esc(alert.rule_id)}</strong><br>${esc(alert.rule_name)}</td>
                    <td class="break">${esc(alert.explanation)}</td>
                    <td class="num">${esc(alert.confidence)}%</td>
                    <td class="num">${esc(alert.event_count)}</td>
                    <td>${alert.incident_id ? `<button class="link" data-action="open-incident" data-id="${esc(alert.incident_id)}">#${esc(alert.incident_id)}</button>` : '<span class="muted">None: too weak alone</span>'}</td>
                </tr>`).join('') : emptyRow(7, 'No alerts match these filters.');
        } catch (e) {
            this.showError('alerts-body', e, 7);
        }
    }

    ruleLogic(rule) {
        if (rule.type === 'baseline') return rule.logic;
        const window = `${rule.window_seconds}s`;
        if (rule.type === 'periodic') return `${rule.min_events}+ events at regular intervals in ${window}`;
        if (rule.type === 'sum') return `${formatNumber(rule.threshold / (1024 * 1024))} MB of ${rule.field} in ${window}, by ${rule.group_by.join(', ')}`;
        if (rule.type === 'sequence') return `${rule.threshold}+ failures then a success in ${window}, by ${rule.group_by.join(', ')}`;
        if (rule.distinct) return `${rule.threshold}+ distinct ${rule.distinct} in ${window}, by ${rule.group_by.join(', ')}`;
        if (rule.threshold === 1) return 'Any matching event';
        return `${rule.threshold}+ events in ${window}, by ${rule.group_by.join(', ')}`;
    }

    async loadRules() {
        const body = document.getElementById('rules-body');
        try {
            const { rules: ioaRules, behavioral_rules: behavioralRules, errors } = await api('/api/rules');
            const rules = ioaRules.concat(behavioralRules);
            const select = document.querySelector('#alerts-filter [name="rule_id"]');
            const current = select.value;
            select.innerHTML = '<option value="">All</option>' + rules.map(rule => `<option value="${esc(rule.id)}">${esc(rule.id)} ${esc(rule.name)}</option>`).join('');
            select.value = current;
            body.innerHTML = rules.map(rule => `<tr>
                <td class="nowrap"><strong>${esc(rule.id)}</strong></td>
                <td class="break">${esc(rule.name)}</td>
                <td class="break">${esc(this.ruleLogic(rule))}</td>
                <td>${chip(rule.severity)}</td>
                <td>${tags((rule.mitre || []).map(t => `${t.id} ${t.tactic}`))}</td>
                <td class="num">${esc(rule.alerts)}</td>
                <td class="nowrap">${esc(formatTime(rule.last_fired))}</td>
                <td><button class="btn btn-sm" data-action="filter-rule" data-rule="${esc(rule.id)}" ${rule.alerts ? '' : 'disabled'}>Show alerts</button></td>
            </tr>`).join('') + (errors.length ? `<tr><td colspan="8"><div class="notice notice-error">${esc(errors.length)} rule(s) could not load: ${esc(errors.map(e => `${e.rule}: ${e.error}`).join('; '))}</div></td></tr>` : '');
        } catch (e) {
            this.showError('rules-body', e, 8);
        }
    }

    async openAlertDrawer(id) {
        this.openDrawer('Alert details', '<p class="muted">Loading...</p>');
        try {
            document.getElementById('drawer-body').innerHTML = this.alertDetail(await api(`/api/alerts/${id}`));
        } catch (e) {
            this.showError('drawer-body', e);
        }
    }

    alertDetail(alert) {
        const evidence = alert.evidence || {};
        const samples = (evidence.sample_events || []).map(e => `<li>${esc(formatTime(e.timestamp))}: ${esc(e.summary)}</li>`).join('');
        const links = (alert.correlation_reasons || []).map(reason => {
            if (reason.type === 'first_alert') return 'First alert in this incident';
            if (reason.type === 'pivot') return `Earlier destination now acting as a source: ${(reason.values || []).join(', ')}`;
            if (reason.type === 'asset_mapping') return `Same machine per the asset list: ${(reason.values || []).join(', ')}`;
            return `Shared ${reason.field}: ${(reason.values || []).join(', ')}`;
        });
        const ioc = evidence.matched_indicator ? `<p><strong>Matched indicator:</strong> ${esc(evidence.matched_indicator)} in <code>${esc(evidence.matched_field)}</code>, from feed ${esc(evidence.feed_source)}</p>` : '';
        return `
            <p><strong>Why it was flagged:</strong> ${esc(alert.explanation)}</p>
            ${ioc}
            <p>${(alert.mitre || []).map(t => `<span class="tag">${esc(t.id)} ${esc(t.name)} (${esc(t.tactic)})</span>`).join('')}</p>
            ${links.length ? `<p><strong>Why it belongs to this incident:</strong> ${links.map(esc).join('; ')}${alert.correlation_score !== null ? ` (link score ${esc(alert.correlation_score)})` : ''}</p>` : ''}
            <p><strong>Matched evidence</strong> (${esc(plural(alert.event_count, 'event'))}):</p>
            <ul>${samples}</ul>
            ${evidence.rule_logic ? `<details class="block"><summary>Rule logic</summary><pre>${esc(JSON.stringify(evidence.rule_logic, null, 2))}</pre></details>` : ''}
            ${alert.supporting_log_ids ? `<h3 class="section-title">Supporting events (${esc(alert.supporting_event_count)})</h3>
                <p class="event-links">${alert.supporting_log_ids.map(id => `<button class="link" data-action="open-event" data-id="${esc(id)}">Event ${esc(id)}</button>`).join(' ')}</p>
                ${alert.supporting_event_count > alert.supporting_log_ids.length ? `<p class="muted">Showing the first ${esc(alert.supporting_log_ids.length)}.</p>` : ''}` : ''}`;
    }

    /* ---------- Investigations ---------- */

    async loadIncidents() {
        const body = document.getElementById('incidents-body');
        const isLatest = this.latest('incidents');
        try {
            const incidents = await api(`/api/incidents?limit=200&${queryFrom(document.getElementById('incidents-filter'))}`);
            if (!isLatest()) return;
            body.innerHTML = incidents.length ? incidents.map(incident => `
                <tr class="clickable${incident.id === this.incidentId ? ' selected' : ''}" tabindex="0" data-action="open-incident" data-id="${esc(incident.id)}">
                    <td class="nowrap">${esc(incident.incident_uid || '#' + incident.id)}</td>
                    <td class="break">${esc(incident.title)}</td>
                    <td>${chip(incident.severity)}</td>
                    <td class="num">${incident.confidence === null ? '--' : esc(incident.confidence) + '%'}</td>
                    <td class="num">${incident.risk_score === null ? '--' : esc(incident.risk_score)}</td>
                    <td class="nowrap">${this.responseChip(incident)}</td>
                    <td>${this.originTag(incident)}</td>
                    <td>${chip(incident.status)}</td>
                    <td class="nowrap">${esc(formatTime(incident.last_seen || incident.timestamp))}</td>
                </tr>`).join('') : emptyRow(9, 'No incidents match these filters. Add a log file in Log Analysis, or run a scenario in the Simulation Lab.');
        } catch (e) {
            this.showError('incidents-body', e, 9);
        }
    }

    async loadIncidentDetail(id) {
        this.incidentId = id;
        const isLatest = this.latest('incident-detail');
        try {
            const detail = await api(`/api/incidents/${id}`);
            if (!isLatest()) return;
            document.getElementById('incident-detail').innerHTML = this.renderIncidentDetail(detail);
            document.querySelectorAll('#incidents-body tr').forEach(row => row.classList.toggle('selected', Number(row.dataset.id) === id));
        } catch (e) {
            this.showError('incident-detail', e);
        }
    }

    statusControl(incident) {
        const options = [['ACTIVE', 'Reopen'], ['INVESTIGATING', 'Start investigating'], ['RESOLVED', 'Resolve']];
        const available = options.filter(([status]) => status !== incident.status);
        return `<div class="status-control">
            <input type="text" id="status-reason" maxlength="500" placeholder="Reason (optional)">
            ${available.map(([status, label]) => `<button class="btn" data-action="set-status" data-id="${esc(incident.id)}" data-status="${status}">${label}</button>`).join('')}
            <a class="btn" id="incident-report" href="/api/incidents/${esc(incident.id)}/report" download><i class="fa-solid fa-download" aria-hidden="true"></i> Report</a>
            <a class="btn" href="/api/incidents/${esc(incident.id)}/report?format=pdf" download><i class="fa-solid fa-file-pdf" aria-hidden="true"></i> PDF</a>
            <button class="btn btn-primary" data-action="nars-ask" data-question="Explain ${esc(incident.incident_uid || `incident ${incident.id}`)}"><i class="fa-solid fa-robot" aria-hidden="true"></i> Ask NARS</button>
        </div>`;
    }

    renderAttackGraph(graph) {
        if (!graph || !graph.nodes.length) return '<p class="empty">These events name no hosts, users or addresses to connect.</p>';
        const columns = {};
        graph.nodes.forEach(node => { (columns[node.rank] = columns[node.rank] || []).push(node); });
        const positions = {};
        const ranks = Object.keys(columns).map(Number).sort((a, b) => a - b);
        const tallest = Math.max(...ranks.map(rank => columns[rank].length));
        const rowHeight = GRAPH.nodeHeight + GRAPH.rowGap;
        const height = tallest * rowHeight + GRAPH.pad * 2;
        ranks.forEach((rank, column) => {
            const nodes = columns[rank].sort((a, b) => b.events - a.events || a.label.localeCompare(b.label));
            const top = (height - nodes.length * rowHeight + GRAPH.rowGap) / 2;
            nodes.forEach((node, row) => {
                positions[node.id] = { x: GRAPH.pad + column * GRAPH.columnWidth, y: top + row * rowHeight };
            });
        });
        const width = ranks.length * GRAPH.columnWidth - (GRAPH.columnWidth - GRAPH.nodeWidth) + GRAPH.pad * 2;
        const labelEdges = graph.edges.length <= 12;

        const edges = graph.edges.map(edge => {
            const from = positions[edge.from];
            const to = positions[edge.to];
            if (!from || !to) return '';
            const midY = (y) => y + GRAPH.nodeHeight / 2;
            const forward = to.x > from.x;
            const startX = forward ? from.x + GRAPH.nodeWidth : from.x + GRAPH.nodeWidth / 2;
            const endX = forward ? to.x - 3 : to.x + GRAPH.nodeWidth / 2;
            const startY = forward ? midY(from.y) : from.y + (to.y > from.y ? GRAPH.nodeHeight : 0);
            const endY = forward ? midY(to.y) : to.y + (to.y > from.y ? 0 : GRAPH.nodeHeight);
            const bend = forward ? (endX - startX) / 2 : 0;
            const path = forward
                ? `M${startX} ${startY} C${startX + bend} ${startY} ${endX - bend} ${endY} ${endX} ${endY}`
                : `M${startX} ${startY} C${startX + 46} ${(startY + endY) / 2} ${endX + 46} ${(startY + endY) / 2} ${endX} ${endY}`;
            const tip = `${edge.from.split(':').slice(1).join(':')} ${edge.relation} ${edge.to.split(':').slice(1).join(':')}: ${plural(edge.events, 'event')}`
                + `${edge.failed ? `, ${edge.failed} failed` : ''}${edge.ports.length ? `, ports ${edge.ports.join(', ')}` : ''}${edge.rules.length ? `. Rules: ${edge.rules.join(', ')}` : ''}`;
            const label = labelEdges && forward
                ? `<text class="graph-edge-label" x="${(startX + endX) / 2}" y="${(startY + endY) / 2 - 5}" text-anchor="middle">${esc(edge.relation)}${edge.events > 1 ? ` x${esc(edge.events)}` : ''}</text>` : '';
            return `<g class="graph-edge"><title>${esc(tip)}</title><path class="graph-edge-hit" d="${path}"></path><path class="graph-edge-line" d="${path}" marker-end="url(#graph-arrow)"></path>${label}</g>`;
        }).join('');

        const nodes = graph.nodes.map(node => {
            const { x, y } = positions[node.id];
            const type = GRAPH_TYPES[node.type];
            const shown = node.label.length > GRAPH.labelChars ? `${node.label.slice(0, GRAPH.labelChars - 1)}...` : node.label;
            const tip = `${type.label} ${node.label}: ${plural(node.events, 'event')}${node.rules.length ? `. Rules: ${node.rules.join(', ')}` : ''}${node.is_indicator ? '. Listed in threat intelligence.' : ''} Select to ask NARS.`;
            return `<g class="graph-node" tabindex="0" role="button" aria-label="${esc(tip)}" data-action="nars-ask" data-question="${esc(graphQuestion(node))}" data-type="${esc(node.type)}">
                <title>${esc(tip)}</title>
                <rect class="graph-node-box" x="${x}" y="${y}" width="${GRAPH.nodeWidth}" height="${GRAPH.nodeHeight}" rx="6" style="stroke:${type.color}"></rect>
                <text class="graph-node-label" x="${x + 10}" y="${y + 17}">${esc(shown)}</text>
                <text class="graph-node-meta" x="${x + 10}" y="${y + 33}">${esc(type.label)}, ${esc(plural(node.events, 'event'))}${node.is_indicator ? ', IOC' : ''}</text>
            </g>`;
        }).join('');

        const usedTypes = Object.keys(GRAPH_TYPES).filter(key => graph.nodes.some(node => node.type === key));
        return `<div class="graph-legend">${usedTypes.map(key => `<span><i class="graph-swatch" style="background:${GRAPH_TYPES[key].color}"></i>${esc(GRAPH_TYPES[key].label)}</span>`).join('')}
                <span class="muted">Select a node to ask NARS about it.</span></div>
            <div class="graph-wrap"><svg class="attack-graph" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="group" aria-label="Attack graph with ${esc(plural(graph.nodes.length, 'entity'))}">
                <defs><marker id="graph-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="4" markerHeight="4" orient="auto-start-reverse"><path d="M0 0L8 4L0 8Z" class="graph-arrow"></path></marker></defs>
                ${edges}${nodes}</svg></div>
            ${graph.hidden_nodes ? `<p class="muted">Showing the ${esc(graph.nodes.length)} most active entities. ${esc(graph.hidden_nodes)} more are not drawn.</p>` : ''}
            ${graph.events_read < graph.events_total ? `<p class="muted">Built from the first ${formatNumber(graph.events_read)} of ${formatNumber(graph.events_total)} events.</p>` : ''}
            <details class="block"><summary>Connections as a table (${esc(graph.edges.length)})</summary><div class="table-wrap short"><table>
                <thead><tr><th>From</th><th>Relation</th><th>To</th><th class="num">Events</th><th class="num">Failed</th><th>Rules</th></tr></thead>
                <tbody>${graph.edges.map(edge => `<tr><td class="break">${esc(edge.from.split(':').slice(1).join(':'))}</td><td>${esc(edge.relation)}</td><td class="break">${esc(edge.to.split(':').slice(1).join(':'))}</td><td class="num">${esc(edge.events)}</td><td class="num">${esc(edge.failed)}</td><td>${tags(edge.rules)}</td></tr>`).join('')}</tbody>
            </table></div></details>`;
    }

    renderIncidentDetail(detail) {
        const { incident, alerts, timeline } = detail;
        if (!alerts.length) {
            return `<article class="card">
                <div class="incident-head"><h2>${esc(incident.title)}</h2>${this.statusControl(incident)}</div>
                <p>${esc(incident.description)}</p>
                <p class="muted">Recorded before evidence tracking was added, so it has no linked alerts or timeline.</p>
            </article>`;
        }
        const breakdown = incident.score_breakdown || {};
        const risk = breakdown.risk || { components: [] };
        const confidence = breakdown.confidence || { reasons: [] };
        const entities = incident.entities || {};
        const correlation = incident.correlation_confidence === null ? 'Single detection' : `${Math.round(incident.correlation_confidence * 100)}%`;
        const tactics = (detail.potential_impact || []).map(item => item.tactic);
        const origins = [...new Set(detail.related_events.map(event => event.origin || 'legacy'))];
        const awaiting = (detail.response_actions || []).filter(action => action.status === 'PENDING').length;

        return `
            <article class="card">
                <div class="incident-head">
                    <div><h2>${esc(incident.incident_uid)}: ${esc(incident.title)}</h2>
                    <p class="muted">${esc(formatTime(incident.first_seen))} to ${esc(formatTime(incident.last_seen))}</p></div>
                    ${this.statusControl(incident)}
                </div>
                <div class="metrics">
                    <div class="metric"><span>Severity (impact)</span><strong>${chip(incident.severity)}</strong></div>
                    <div class="metric"><span>Confidence (evidence)</span><strong>${esc(incident.confidence)}%</strong></div>
                    <div class="metric"><span>Risk (priority)</span><strong>${esc(incident.risk_score)}/100 ${esc(incident.risk_level)}</strong></div>
                    <div class="metric"><span>Correlation</span><strong>${esc(correlation)}</strong></div>
                    <div class="metric"><span>Alerts / events</span><strong>${esc(incident.alert_count)} / ${esc(incident.event_count)}</strong></div>
                    <div class="metric"><span>Status</span><strong>${chip(incident.status)}</strong></div>
                    <div class="metric"><span>Priority</span><strong>${esc(incident.priority || '--')}</strong></div>
                    <div class="metric"><span>Awaiting decision</span><strong>${esc(awaiting)}</strong></div>
                    <div class="metric"><span>Data origin</span><strong>${esc(origins.join(', '))}</strong></div>
                </div>
                ${origins.includes('simulation') ? '<p class="notice">Built from synthetic events. It shows how the pipeline behaves, not a real compromise.</p>' : ''}
                ${tactics.length ? `<ol class="chain" aria-label="Attack progression">${tactics.map(t => `<li>${esc(t)}</li>`).join('')}</ol>` : ''}
            </article>
            <div class="detail-grid">
                <article class="card">
                    <h3>Who and what was involved</h3>
                    <dl class="facts" style="margin-top:8px">${Object.entries(entities).map(([field, values]) => `<dt>${esc(ENTITY_LABELS[field] || field)}</dt><dd>${values.map(esc).join(', ')}</dd>`).join('')}</dl>
                </article>
                <article class="card">
                    <h3>Potential impact</h3>
                    <p class="muted">If this activity is genuine:</p>
                    <ul>${(detail.potential_impact || []).map(item => `<li><strong>${esc(item.tactic)}:</strong> ${esc(item.impact)}</li>`).join('') || '<li>No MITRE tactic is mapped to these detections.</li>'}</ul>
                </article>
            </div>
            <article class="card" id="attack-graph-card">
                <h3>Attack graph</h3>
                <p class="muted">Who and what connects to what, read from the events behind these detections.</p>
                ${this.renderAttackGraph(detail.attack_graph)}
            </article>
            <article class="card">
                <h3>Attack timeline</h3>
                <ol class="timeline" style="margin-top:8px">${timeline.map(entry => `<li>
                    <time>${esc(formatTime(entry.timestamp))}</time>
                    <span>${esc(entry.summary)}${entry.count > 1 ? ` <strong>x${esc(entry.count)}</strong>` : ''}
                    <span class="tag">${esc(entry.source)}</span>${tags(entry.rule_ids)}</span></li>`).join('')}</ol>
            </article>
            <article class="card">
                <h3>Detections and evidence</h3>
                ${alerts.map(alert => `<details class="block"><summary>${chip(alert.severity)} <strong>${esc(alert.rule_id)}</strong> ${esc(alert.rule_name)}
                    <span class="muted">${esc(alert.confidence)}% confidence, ${esc(plural(alert.event_count, 'event'))}</span></summary>${this.alertDetail(alert)}</details>`).join('')}
            </article>
            <article class="card">
                <h3>How this was scored</h3>
                <p style="margin-top:6px"><strong>Severity:</strong> ${esc((breakdown.severity || {}).reason)}</p>
                <p><strong>Confidence:</strong> ${esc(confidence.method)} ${confidence.reasons.map(esc).join('; ')}</p>
                <div class="table-wrap" style="margin-top:8px"><table>
                    <thead><tr><th>Risk factor</th><th class="num">Weight</th><th class="num">Points</th><th>Reason</th></tr></thead>
                    <tbody>${risk.components.map(c => `<tr><td class="nowrap">${esc(c.factor.replace(/_/g, ' '))}</td><td class="num">${esc(c.weight)}</td><td class="num">${esc(c.points)}</td><td class="break">${esc(c.reason)}</td></tr>`).join('')}
                    <tr><td><strong>Total</strong></td><td></td><td class="num"><strong>${esc(risk.subtotal)}</strong></td><td>Capped at 100, gives <strong>${esc(risk.value)}</strong> (${esc(risk.level)})</td></tr></tbody>
                </table></div>
                <p class="muted" style="margin-top:6px">${esc(risk.note)}</p>
            </article>
            <article class="card">
                <h3>Automatic handling</h3>
                <p style="margin-top:6px">${esc(incident.automation_status || 'None recorded.')}</p>
                <p>${tags(incident.tags)}</p>
                <ul>${(detail.automation_log || []).map(step => `<li>${esc(formatTime(step.created_at))}: ${esc((step.detail || {}).title || step.step)} <span class="muted">(${esc(step.risk_level)} tier)</span></li>`).join('')}</ul>
                <p class="muted">These steps only read stored data and write SOC records. They never change a system.</p>
            </article>
            <article class="card">
                <h3>Recommended response</h3>
                <p class="muted">${['LOW', 'MEDIUM'].includes(incident.risk_level)
        ? 'This is a small risk, so safe steps ran automatically, in simulation. Disruptive actions are held unless you approve them, and go to the SOC queue if the risk rises.'
        : `This risk needs a SOC decision. Each open action waits for your approval, ${this.simulationWording()}. A safe step marked as handled automatically ran while the risk was still small.`}</p>
                <div id="incident-actions">${(detail.response_actions || []).map(action => this.actionRow(action)).join('') || '<p class="empty">No response is recommended for these detections.</p>'}</div>
            </article>
            <article class="card">
                <details><summary><strong>Related events (${esc(detail.related_events_total)})</strong>${detail.related_events_truncated ? ` <span class="muted">showing the first ${esc(detail.related_events.length)}</span>` : ''}</summary>
                ${detail.related_events.map(e => `<details class="block"><summary>${esc(formatTime(e.timestamp))} ${esc(e.source)} / ${esc(e.event_type)} <span class="muted">${esc(e.event_id)}</span></summary><pre>${esc(JSON.stringify(e.raw_event, null, 2))}</pre></details>`).join('')}
                </details>
            </article>
            <article class="card">
                <details><summary><strong>Audit trail (${esc((detail.audit_log || []).length)})</strong></summary>
                ${this.auditTable(detail.audit_log || [], false)}
                </details>
            </article>`;
    }

    /* ---------- Response approvals ---------- */

    commandsPanel(action) {
        const commands = action.manual_commands;
        if (!commands) return '';
        const lines = (title, list) => (list.length ? `<div class="command-group"><div class="command-head"><strong>${esc(title)}</strong>
                <button class="btn btn-sm btn-ghost" data-action="copy-text" data-text="${esc(list.join('\n'))}">Copy</button></div>
                <pre class="command">${esc(list.join('\n'))}</pre></div>` : '');
        return `<details class="manual-commands"><summary>Real commands to run by hand</summary>
            <p class="muted">${esc(commands.note)}</p>
            ${lines('Windows', commands.windows)}${lines('Windows: undo', commands.windows_undo)}
            ${lines('Linux', commands.linux)}${lines('Linux: undo', commands.linux_undo)}
        </details>`;
    }

    async loadResponseMode() {
        try {
            this.responseMode = await api('/api/response-mode');
        } catch (e) {
            return;
        }
        if (!this.responseMode.enabled) return;
        const note = this.responseMode.ready
            ? 'Real mode is on. After approval, Block IP adds a real Windows Firewall rule on this machine, and it can be undone. Everything else runs in simulation.'
            : `Real mode is on, but it cannot run yet. ${this.responseMode.reason}`;
        document.getElementById('mode-note-response').textContent = note;
        document.getElementById('mode-note-sidebar').textContent = note;
    }

    simulationWording() {
        return this.responseMode && this.responseMode.enabled ? 'and runs in simulation, apart from a real firewall block' : 'and runs only in simulation';
    }

    actionRow(action) {
        const undecided = `<div class="action-controls">
                <input type="text" data-field="reason" maxlength="500" placeholder="Reason (optional)" aria-label="Reason">
                <button class="btn btn-primary" data-action="decide" data-decision="approve" data-id="${esc(action.id)}">Approve</button>
                <button class="btn" data-action="decide" data-decision="reject" data-id="${esc(action.id)}">Reject</button>
                ${action.status === 'PENDING' ? `<button class="btn" data-action="decide" data-decision="investigate" data-id="${esc(action.id)}">Needs investigation</button>` : ''}
                <details class="change-target"><summary>Change target</summary>
                    <input type="text" data-field="target" value="${esc(action.target)}" aria-label="Target (${esc(action.target_type)})">
                    <button class="btn" data-action="decide" data-decision="modify" data-id="${esc(action.id)}">Approve with this target</button>
                </details>
            </div>`;
        const controls = {
            PENDING: undecided,
            NEEDS_INVESTIGATION: undecided,
            HELD: undecided,
            APPROVED: action.runs_for_real
                ? `<p class="notice notice-real">Running this adds a real Windows Firewall rule on this machine. You can undo it.</p>
                    <div class="action-controls"><button class="btn btn-primary" data-action="execute" data-id="${esc(action.id)}">Block for real</button></div>`
                : `<div class="action-controls"><button class="btn btn-primary" data-action="execute" data-id="${esc(action.id)}">Run in simulation</button></div>`,
            EXECUTED: action.mode === 'real'
                ? `<div class="action-controls"><button class="btn" data-action="undo-real" data-id="${esc(action.id)}">Undo: remove the firewall rule</button></div>` : '',
        }[action.status] || '';
        const decision = action.decided_by
            ? `<div class="muted">${action.decided_by === 'automation' ? 'Handled automatically' : `${esc({ REJECTED: 'Rejected', NEEDS_INVESTIGATION: 'Marked for investigation' }[action.status] || 'Approved')} by ${esc(action.decided_by)}`}, ${esc(formatTime(action.decided_at))}${action.decision_reason ? `: ${esc(action.decision_reason)}` : ''}${action.target !== action.original_target ? `. Target changed from ${esc(action.original_target)}.` : ''}</div>` : '';
        const ran = action.executed_at ? `<div class="muted">Run by ${esc(action.executed_by)}, ${esc(formatTime(action.executed_at))}.</div>` : '';
        const result = action.result ? `<div>${action.status === 'FAILED' ? `<strong>Failed:</strong> ${esc(action.result.error)}` : esc(action.result.summary)}
            <span class="muted">Verification: ${action.verification && action.verification.verified ? 'passed.' : `failed. ${esc((action.verification || {}).reason)}`} ${esc((action.verification || {}).method)}</span></div>` : '';
        return `<div class="action-row">
            <div class="action-title">${chip(action.status)} <strong>${esc(action.label)}</strong> <code>${esc(action.target)}</code>
                ${action.disruptive ? '<span class="tag">Disruptive</span>' : ''}
                ${action.mode === 'real' ? '<span class="tag tag-real">Real change</span>' : ''}</div>
            <div class="muted">${esc(action.rationale)}</div>
            ${action.expected_impact ? `<div class="muted"><strong>Expected impact:</strong> ${esc(action.expected_impact)}</div>` : ''}
            ${decision}${ran}${result}${controls}${this.commandsPanel(action)}
        </div>`;
    }

    async loadApprovals() {
        const body = document.getElementById('approvals-body');
        const isLatest = this.latest('approvals');
        try {
            const [actions, incidents, stats] = await Promise.all([
                api(`/api/response-actions?limit=${QUEUE_LIMIT}&${queryFrom(document.getElementById('approvals-filter'))}`),
                api('/api/incidents?limit=1000'),
                api('/api/stats'),
            ]);
            if (!isLatest()) return;
            this.renderApprovalTiles(stats, incidents);
            const limited = actions.length === QUEUE_LIMIT
                ? `<p class="muted">Showing the oldest ${QUEUE_LIMIT} in this state. Decide on some, or change the filter, to see the rest.</p>` : '';
            const filter = document.getElementById('approvals-filter').elements.status.value;
            body.innerHTML = actions.length ? limited + this.actionGroups(actions, incidents)
                : `<p class="empty">${filter === 'PENDING' ? 'Nothing is waiting for the SOC. High and critical risks appear here.' : 'No response actions in this state.'}</p>`;
        } catch (e) {
            this.showError('approvals-body', e);
        }
    }

    renderApprovalTiles(stats, incidents) {
        const waiting = incidents.filter(incident => incident.response_status === 'AWAITING_APPROVAL');
        const tile = (label, value, status, extra = '') => `<button class="tile ${extra}" data-action="approvals-show" data-status="${status}"><span class="tile-label">${esc(label)}</span><span class="tile-value">${formatNumber(value)}</span></button>`;
        document.getElementById('approvals-tiles').innerHTML = tile('Waiting for SOC approval', stats.responses_pending, 'PENDING', 'tile-alert')
            + tile('Critical incidents waiting', waiting.filter(incident => incident.risk_level === 'CRITICAL').length, 'PENDING')
            + tile('Handled automatically', stats.responses_automated, 'AUTOMATED')
            + tile('Held at small risk', stats.responses_held, 'HELD');
    }

    // One group per incident, highest risk first, so the queue reads in triage order
    actionGroups(actions, incidents) {
        const known = new Map(incidents.map(incident => [incident.id, incident]));
        const groups = new Map();
        actions.forEach(action => {
            if (!groups.has(action.incident_id)) groups.set(action.incident_id, []);
            groups.get(action.incident_id).push(action);
        });
        const risk = (id) => (known.get(id) || {}).risk_score || 0;
        return [...groups.entries()].sort((a, b) => risk(b[0]) - risk(a[0]) || a[0] - b[0]).map(([id, group]) => {
            const incident = known.get(id);
            return `<section class="action-group" data-incident="${esc(id)}">
                <div class="group-head">
                    <button class="link" data-action="open-incident" data-id="${esc(id)}">${incident ? `${esc(incident.incident_uid || '#' + id)}: ${esc(incident.title)}` : `Incident #${esc(id)}`}</button>
                    ${incident ? `${chip(incident.severity)} <span class="muted">Risk ${incident.risk_score === null ? '--' : esc(incident.risk_score)}/100, confidence ${incident.confidence === null ? '--' : esc(incident.confidence)}%, priority ${esc(incident.priority || '--')}</span>` : ''}
                    <span class="muted">${esc(plural(group.length, 'action'))}</span>
                </div>
                ${group.map(action => this.actionRow(action)).join('')}
            </section>`;
        }).join('');
    }

    async afterResponseChange() {
        if (this.view === 'approvals') this.loadApprovals();
        if (this.view === 'investigations' && this.incidentId) this.loadIncidentDetail(this.incidentId);
        if (this.view === 'simulation' && this.solutionRun) this.loadRunSolutions();
        this.refreshStats();
    }

    async decide(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        const row = button.closest('.action-row');
        const body = { decision: button.dataset.decision, analyst, reason: row.querySelector('[data-field="reason"]').value };
        if (body.decision === 'modify') body.target = row.querySelector('[data-field="target"]').value;
        button.disabled = true;
        try {
            const action = await postJson(`/api/response-actions/${button.dataset.id}/decision`, body);
            this.toast(`${action.label}: ${action.status.toLowerCase()} by ${analyst}.`);
        } catch (e) {
            this.toast(e.message, true);
            button.disabled = false;
        }
        this.afterResponseChange();
    }

    async execute(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        button.disabled = true;
        try {
            const action = await postJson(`/api/response-actions/${button.dataset.id}/execute`, { analyst });
            if (action.status === 'FAILED') this.toast(`Failed: ${action.result.error}`, true);
            else this.toast(action.result.summary);
        } catch (e) {
            this.toast(e.message, true);
        }
        this.afterResponseChange();
    }

    async undoReal(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        button.disabled = true;
        try {
            const action = await postJson(`/api/response-actions/${button.dataset.id}/undo`, { analyst });
            this.toast(action.result.summary);
        } catch (e) {
            this.toast(e.message, true);
        }
        this.afterResponseChange();
    }

    async setStatus(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        const reason = document.getElementById('status-reason');
        button.disabled = true;
        try {
            const incident = await postJson(`/api/incidents/${button.dataset.id}/status`, {
                status: button.dataset.status, analyst, reason: reason ? reason.value : '',
            });
            this.toast(`${incident.incident_uid || 'Incident'} is now ${incident.status}.`);
            this.loadIncidents();
            this.loadIncidentDetail(incident.id);
            this.refreshStats();
        } catch (e) {
            this.toast(e.message, true);
            button.disabled = false;
        }
    }

    /* ---------- Simulation lab ---------- */

    async loadSimulation() {
        try {
            const [data, control] = await Promise.all([api('/api/simulate'), api('/api/simulations?limit=1')]);
            this.renderValidation(data.validation);
            this.scenarios = data.scenarios;
            this.fillSimulationControls(control);
            if (control.active_run && !this.activeRun) this.trackRun(control.active_run);
            const order = (scenario) => (scenario.id === 'multi_stage' ? 0 : scenario.id === 'benign' ? 1 : 2);
            const scenarios = [...data.scenarios].sort((a, b) => order(a) - order(b));
            document.getElementById('scenarios').innerHTML = scenarios.map(scenario => `
                <article class="card scenario${scenario.id === 'multi_stage' ? ' scenario-featured' : ''}">
                    <h3>${esc(scenario.name)}</h3>
                    <p class="muted">${esc(scenario.description)}</p>
                    <div>${scenario.expected_rules.length ? tags(scenario.expected_rules) : '<span class="muted">Expected: no detections</span>'}</div>
                    <p class="muted scenario-last">${esc(this.lastRunText(data.recent_runs.find(run => run.scenario === scenario.id)))}</p>
                    <div class="status-control"><button class="btn${scenario.id === 'multi_stage' ? ' btn-primary' : ''}" data-action="run-scenario" data-id="${esc(scenario.id)}" ${this.activeRun ? 'disabled' : ''}><i class="fa-solid fa-play" aria-hidden="true"></i> Run</button>
                        <button class="btn" data-action="open-scenario-solution" data-id="${esc(scenario.id)}">Solution</button></div>
                </article>`).join('');
            this.renderRuns(data.recent_runs);
        } catch (e) {
            this.showError('scenarios', e);
        }
        this.loadSolutionPortal();
    }

    async loadSolutionPortal() {
        if (!this.solutionData) {
            try {
                this.solutionData = await api('/api/solutions');
            } catch (e) {
                this.showError('solution-list', e);
                return;
            }
            const form = document.getElementById('solution-filter');
            const option = (value, label) => `<option value="${esc(value)}">${esc(label)}</option>`;
            form.elements.scenario.insertAdjacentHTML('beforeend', this.solutionData.scenarios.map(item => option(item.id, item.name)).join(''));
            form.elements.tactic.insertAdjacentHTML('beforeend', this.solutionData.tactics.map(item => option(item, item)).join(''));
        }
        this.renderSolutionPortal();
    }

    renderSolutionPortal() {
        const data = this.solutionData;
        if (!data) return;
        const form = document.getElementById('solution-filter');
        const query = form.elements.q.value.trim().toLowerCase();
        const scenario = form.elements.scenario.value;
        const tactic = form.elements.tactic.value;
        const run = this.solutionRun;
        const fired = new Set(run ? run.alerts.map(alert => alert.rule_id) : []);
        const chosen = data.scenarios.find(item => item.id === scenario);
        const threats = data.threats
            .filter(threat => !chosen || chosen.expected_rules.includes(threat.id))
            .filter(threat => scenario !== 'last-run' || fired.has(threat.id))
            .filter(threat => !tactic || threat.tactics.includes(tactic))
            .filter(threat => !query || JSON.stringify([threat.id, threat.name, threat.description, threat.detected_when, threat.fix_steps, threat.techniques]).toLowerCase().includes(query))
            .sort((a, b) => fired.has(b.id) - fired.has(a.id));

        const note = document.getElementById('solution-run-note');
        note.hidden = !run;
        if (run) {
            note.textContent = fired.size
                ? `Your last run, ${run.view.name}, raised ${plural(fired.size, 'threat')}. They come first below, marked "In your last run".`
                : `Your last run, ${run.view.name}, raised no alert, so none of these applied to it. This is how each threat would be fixed if it appeared.`;
        }
        document.getElementById('solution-count').textContent = `Showing ${plural(threats.length, 'threat')} of ${formatNumber(data.threats.length)}.`;

        const list = document.getElementById('solution-list');
        const opened = [...list.querySelectorAll('.portal-item[open]')].map(item => item.dataset.rule);
        const nothing = chosen && !chosen.expected_rules.length
            ? `${chosen.name} is normal activity, so it has no threat to fix. Choose another scenario to see its solution.`
            : 'No threat matches this search.';
        list.innerHTML = threats.length ? threats.map(threat => this.solutionEntry(threat, fired.has(threat.id))).join('') : `<p class="empty">${esc(nothing)}</p>`;
        list.querySelectorAll('.portal-item').forEach((item) => { item.open = opened.includes(item.dataset.rule) || threats.length === 1; });
    }

    solutionEntry(threat, inLastRun) {
        const action = item => `<div class="portal-action">
                <div class="action-title"><strong>${esc(item.label)}</strong> <span class="tag">${item.disruptive ? 'Disruptive' : 'Safe'}</span></div>
                <div class="muted">${esc(item.description)}</div>
                <div class="muted"><strong>Who decides:</strong> ${esc(item.who_decides)}</div>
                ${item.expected_impact ? `<div class="muted"><strong>Expected impact:</strong> ${esc(item.expected_impact)}</div>` : ''}
                ${this.commandsPanel({ manual_commands: item.commands })}
            </div>`;
        return `<details class="portal-item" data-rule="${esc(threat.id)}">
            <summary>${threat.severity ? chip(threat.severity) : '<span class="tag">Severity set by the feed</span>'} <strong>${esc(threat.id)} ${esc(threat.name)}</strong>
                <span class="tag">${esc(threat.kind)}</span>${inLastRun ? ' <span class="tag tag-soc">In your last run</span>' : ''}</summary>
            <div class="portal-body">
                <p>${esc(threat.description)}</p>
                <h4>How ALLSAFE spots it</h4>
                <p class="muted">${esc(threat.detected_when)}</p>
                ${threat.techniques.length ? `<p>${threat.techniques.map(item => `<span class="tag">${esc(item.id)} ${esc(item.name)}</span>`).join('')}</p>` : ''}
                <h4>How to fix it</h4>
                ${threat.fix_steps.length ? `<ol class="solution-steps">${threat.fix_steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol>` : '<p class="muted">No fix steps are listed.</p>'}
                ${threat.actions.length ? `<h4>Response actions</h4>
                    <p class="muted">Commands use example targets. Replace them with the real address, account, process or host. An incident's own page fills them in.</p>
                    ${threat.actions.map(action).join('')}` : ''}
                ${threat.scenarios.length ? `<h4>Practise it</h4><div class="status-control">${threat.scenarios.map(item => `<button class="btn btn-sm" data-action="portal-run" data-id="${esc(item.id)}"><i class="fa-solid fa-play" aria-hidden="true"></i> Run ${esc(item.name)}</button>`).join('')}</div>` : ''}
            </div>
        </details>`;
    }

    openSolutionFor(scenario) {
        const form = document.getElementById('solution-filter');
        form.elements.q.value = '';
        form.elements.tactic.value = '';
        form.elements.scenario.value = scenario;
        this.renderSolutionPortal();
        document.getElementById('solution-portal').scrollIntoView({ block: 'start' });
    }

    fillSimulationControls(control) {
        const form = document.getElementById('sim-controls');
        if (form.elements.intensity.options.length) return;
        form.elements.intensity.innerHTML = Object.entries(control.intensities).sort((a, b) => a[1] - b[1])
            .map(([name, count]) => `<option value="${esc(name)}">${esc(name)}: ${esc(plural(count, 'background event'))}</option>`).join('');
        form.elements.speed.innerHTML = control.speeds.map(name => `<option value="${esc(name)}">${esc(name)}</option>`).join('');
        form.elements.speed.value = 'fast';
    }

    renderValidation(validation) {
        const tiles = [
            ['Runs counted', validation.runs],
            ['Expected detections', validation.expected_detections],
            ['Missed', validation.missed_detections],
            ['Unexpected', validation.unexpected_detections],
            ['Benign runs', validation.benign_runs],
            ['Benign runs with alerts', validation.benign_runs_with_alerts],
        ];
        document.getElementById('validation-tiles').innerHTML = tiles.map(([label, value]) => `
            <div class="tile"><span class="tile-label">${esc(label)}</span><span class="tile-value">${formatNumber(value)}</span></div>`).join('');
        document.getElementById('validation-scope').textContent = `Counts the latest ${formatNumber(validation.runs)} of ${formatNumber(validation.total_runs)} runs.`;
    }

    runMatched(run) {
        return !run.missed_rules.length && !run.unexpected_rules.length;
    }

    lastRunText(run) {
        if (!run) return 'Not run recently.';
        return `Last run ${formatTime(run.started_at)}: ${this.runMatched(run) ? 'matched its ground truth' : 'did not match its ground truth'}.`;
    }

    renderRuns(runs) {
        document.getElementById('runs-body').innerHTML = runs.length ? runs.map(run => `<tr>
            <td class="nowrap">${esc(formatTime(run.started_at))}</td>
            <td><button class="link" data-action="view-run" data-id="${esc(run.run_id)}">${esc((this.scenarios.find(scenario => scenario.id === run.scenario) || {}).name || run.scenario)}</button></td>
            <td>${run.status !== 'COMPLETED' ? `<strong>${esc(run.status)}</strong>` : this.runMatched(run) ? 'Matched' : '<strong>Did not match</strong>'}</td>
            <td class="num">${esc(run.event_count)}</td>
            <td class="num">${esc(run.expected_rules.length)}</td>
            <td class="num">${esc(run.fired_rules.length)}</td>
            <td>${run.missed_rules.length ? tags(run.missed_rules) : '<span class="muted">None</span>'}</td>
            <td>${run.unexpected_rules.length ? tags(run.unexpected_rules) : '<span class="muted">None</span>'}</td>
            <td>${run.incident_ids.map(id => `<button class="link" data-action="open-incident" data-id="${esc(id)}">#${esc(id)}</button>`).join(' ') || '<span class="muted">None</span>'}</td>
        </tr>`).join('') : emptyRow(9, 'No scenarios have been run yet.');
    }

    async runScenario(button) {
        const panel = document.getElementById('sim-result');
        const params = Object.fromEntries(new FormData(document.getElementById('sim-controls')));
        params.scenario = button.dataset.id;
        document.querySelectorAll('[data-action="run-scenario"]').forEach(b => { b.disabled = true; });
        panel.innerHTML = '';
        try {
            const view = await postJson('/api/simulations', params);
            this.trackRun(view.run_id);
        } catch (e) {
            panel.innerHTML = `<div class="notice notice-error">Could not start this scenario: ${esc(e.message)}</div>`;
            document.querySelectorAll('[data-action="run-scenario"]').forEach(b => { b.disabled = false; });
        }
    }

    trackRun(runId) {
        this.activeRun = runId;
        clearInterval(this.runTimer);
        // Socket.IO makes progress prompt. The timer still finishes the job if the connection drops.
        this.runTimer = setInterval(() => this.refreshRun(), 1000);
        this.refreshRun();
    }

    async refreshRun() {
        const runId = this.activeRun;
        if (!runId) return;
        const isLatest = this.latest('run');
        try {
            const view = await api(`/api/simulations/${runId}`);
            if (!isLatest() || this.activeRun !== runId) return;
            if (view.active || ['RUNNING', 'PAUSED'].includes(view.status)) {
                this.renderRunProgress(view);
                return;
            }
            this.activeRun = null;
            clearInterval(this.runTimer);
            document.getElementById('sim-progress').hidden = true;
            await this.showRunResult(view);
            if (this.view === 'simulation') await this.loadSimulation();
            else this.toast(`Simulation ${view.name} ended: ${view.status}.`);
            this.refreshStats();
        } catch (e) {
            this.toast(`Could not read the simulation: ${e.message}`, true);
        }
    }

    renderRunProgress(view) {
        const box = document.getElementById('sim-progress');
        const percent = view.event_count ? Math.round(view.processed_count / view.event_count * 100) : 0;
        box.hidden = false;
        box.innerHTML = `
            <div class="card-head"><h3>${esc(view.name)}: ${esc(view.status)}</h3>
                <div class="status-control">
                    ${view.status === 'PAUSED'
                        ? `<button class="btn" data-action="sim-control" data-control="resume" data-id="${esc(view.run_id)}"><i class="fa-solid fa-play" aria-hidden="true"></i> Resume</button>`
                        : `<button class="btn" data-action="sim-control" data-control="pause" data-id="${esc(view.run_id)}"><i class="fa-solid fa-pause" aria-hidden="true"></i> Pause</button>`}
                    <button class="btn btn-danger" data-action="sim-control" data-control="stop" data-id="${esc(view.run_id)}"><i class="fa-solid fa-stop" aria-hidden="true"></i> Stop</button>
                </div></div>
            <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><span style="width:${percent}%"></span></div>
            <p class="muted">${formatNumber(view.processed_count)} of ${formatNumber(view.event_count)} events processed. ${esc(plural(view.alert_count, 'alert'))} and ${esc(plural(view.incidents.length, 'incident'))} so far. Run ${esc(view.run_id)}.</p>`;
    }

    async controlRun(button) {
        try {
            await postJson(`/api/simulations/${button.dataset.id}/${button.dataset.control}`, {});
            this.refreshRun();
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    async viewRun(runId) {
        try {
            await this.showRunResult(await api(`/api/simulations/${runId}`));
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    async showRunResult(view) {
        const [alerts, events] = await Promise.all([
            api(`/api/simulations/${view.run_id}/alerts`),
            api(`/api/simulations/${view.run_id}/events?limit=100`),
        ]);
        const panel = document.getElementById('sim-result');
        panel.innerHTML = this.renderRunResult(view, alerts, events);
        this.loadImpact(view.run_id);
        this.solutionRun = { view, alerts };
        this.loadRunSolutions();
        this.showRunInPortal();
        panel.scrollIntoView({ block: 'nearest' });
    }

    showRunInPortal() {
        const select = document.getElementById('solution-filter').elements.scenario;
        let option = select.querySelector('option[value="last-run"]');
        if (!option) {
            select.insertAdjacentHTML('afterbegin', '<option value="last-run"></option>');
            option = select.querySelector('option[value="last-run"]');
        }
        const { view, alerts } = this.solutionRun;
        option.textContent = `My last run: ${view.name}`;
        select.value = alerts.length ? 'last-run' : '';
        this.renderSolutionPortal();
    }

    async loadRunSolutions() {
        const { view, alerts } = this.solutionRun;
        const holder = () => document.getElementById('sim-solutions');
        if (!holder()) return;
        if (!alerts.length) {
            const scenario = (this.scenarios || []).find(item => item.id === view.scenario);
            const unusual = view.metrics && view.metrics.anomaly_level ? view.metrics.anomaly_level.false_positives : 0;
            holder().innerHTML = `<section class="solutions"><h3>Recommended solution</h3>
                <p>This run raised no alert, so there is nothing to fix.${scenario ? ` ${esc(scenario.description)}.` : ''}</p>
                ${unusual ? `<p class="muted">The anomaly model marked ${esc(unusual)} of these logs as unusual. That is a signal to look at, not a threat, and it calls for no action here.</p>` : ''}
                <p><button class="btn" data-action="open-portal"><i class="fa-solid fa-kit-medical" aria-hidden="true"></i> See how each threat is fixed</button></p></section>`;
            return;
        }
        // A refresh after a decision keeps open what the analyst had open
        const opened = [...holder().querySelectorAll('.solution-actions[open]')].map(item => item.dataset.rule);
        try {
            const lists = await Promise.all(view.incidents.map(incident => api(`/api/incidents/${incident.id}/response-actions`)));
            if (!holder() || this.solutionRun.view.run_id !== view.run_id) return;
            holder().innerHTML = this.renderSolutions(view, alerts, lists.flat());
            holder().querySelectorAll('.solution-actions').forEach((item) => { item.open = opened.includes(item.dataset.rule); });
        } catch (e) {
            if (holder()) holder().innerHTML = `<p class="notice notice-error">Could not load the recommended solutions: ${esc(e.message)}</p>`;
        }
    }

    renderSolutions(view, alerts, actions) {
        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const threats = [...new Map(alerts.map(alert => [alert.rule_id, alert])).values()]
            .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.rule_id.localeCompare(b.rule_id));
        const policy = (incident) => {
            if (!incident) return '<span class="tag">No incident</span> <span class="muted">This alert alone opened no incident, so no action is waiting.</span>';
            return ['HIGH', 'CRITICAL'].includes(incident.risk_level)
                ? `<span class="tag tag-soc"><i class="fa-solid fa-user-shield" aria-hidden="true"></i> SOC approval</span> <span class="muted">${esc(incident.incident_uid)} is ${esc(incident.risk_level)} risk, so open actions wait for your approval.</span>`
                : `<span class="tag tag-auto"><i class="fa-solid fa-robot" aria-hidden="true"></i> Automated</span> <span class="muted">${esc(incident.incident_uid)} is ${esc(incident.risk_level)} risk, so safe steps ran in simulation, and disruptive actions are held.</span>`;
        };
        return `<section class="solutions"><h3>Recommended solution</h3>
            <p class="muted">What to do about each threat in this run, most severe first.</p>
            ${threats.map((threat) => {
                const steps = threat.recommendations || [];
                const own = actions.filter(action => action.recommended_by === threat.rule_id);
                return `<article class="solution">
                    <div class="action-title">${chip(threat.severity)} <strong>${esc(threat.rule_id)} ${esc(threat.rule_name)}</strong></div>
                    <p class="muted">${esc(threat.explanation || '')}</p>
                    ${steps.length ? `<ol class="solution-steps">${steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol>` : '<p class="muted">This detection lists no fix steps.</p>'}
                    <p>${policy(view.incidents.find(incident => incident.id === threat.incident_id))}</p>
                    ${own.length ? `<details class="solution-actions" data-rule="${esc(threat.rule_id)}"><summary>Response actions and real commands (${esc(own.length)})</summary>
                        ${own.map(action => this.actionRow(action)).join('')}</details>` : ''}
                </article>`;
            }).join('')}
            <p><button class="btn" data-action="open-portal"><i class="fa-solid fa-kit-medical" aria-hidden="true"></i> See every threat in the Solution Portal</button></p>
        </section>`;
    }

    renderRunResult(view, alerts, events) {
        const passed = this.runMatched(view);
        const verdict = view.status === 'COMPLETED'
            ? (passed ? 'matched its ground truth' : 'did not match its ground truth')
            : `ended as ${view.status}`;
        const rules = [...new Set([...view.expected_rules, ...view.fired_rules])].sort();
        const rows = rules.map(rule => {
            const expected = view.expected_rules.includes(rule);
            const fired = view.fired_rules.includes(rule);
            const outcome = expected && fired ? 'As expected' : expected ? 'MISSED' : 'UNEXPECTED';
            return `<tr><td>${esc(rule)}</td><td>${expected ? 'Yes' : 'No'}</td><td>${fired ? 'Yes' : 'No'}</td><td>${esc(outcome)}</td></tr>`;
        }).join('');
        const risk = Object.entries(view.alert_risk_distribution).map(([level, count]) => `${level} ${count}`).join(', ');
        const metrics = view.metrics || {};
        return `<article class="card">
            <div class="card-head"><h3>${esc(view.name)}: ${esc(verdict)}</h3>
                <div class="status-control">
                    <button class="btn" data-action="open-simulated-stream">Watch in live stream</button>
                    ${view.incidents[0] ? `<button class="btn btn-primary" data-action="open-incident" data-id="${esc(view.incidents[0].id)}">Investigate ${esc(view.incidents[0].incident_uid)}</button>` : ''}
                    <button class="btn btn-ghost" data-action="clear-sim-result">Clear</button>
                </div></div>
            ${view.error ? `<div class="notice notice-error">${esc(view.error)}</div>` : ''}
            <p class="muted">Run ${esc(view.run_id)}, ${esc(formatTime(view.started_at))} to ${esc(formatTime(view.completed_at))}. Seed ${esc(view.seed === null ? 'not recorded' : view.seed)}, ${esc(plural(view.background_events, 'background event'))}.</p>
            <ul class="flow">
                <li><strong>${esc(view.event_count)}</strong><span>events generated</span></li>
                <li><strong>${esc(view.processed_count)}</strong><span>processed</span></li>
                <li><strong>${esc(view.failed_count)}</strong><span>failed</span></li>
                <li><strong>${esc(view.alert_count)}</strong><span>alerts</span></li>
                <li><strong>${esc(view.incidents.length)}</strong><span>incidents</span></li>
                <li><strong>${esc(view.missed_rules.length)}</strong><span>detections missed</span></li>
                <li><strong>${esc(view.unexpected_rules.length)}</strong><span>unexpected detections</span></li>
                <li><strong>${metrics.detection_latency_seconds === null || metrics.detection_latency_seconds === undefined ? '--' : esc(metrics.detection_latency_seconds) + ' s'}</strong><span>detection latency</span></li>
            </ul>
            <p><strong>Alert risk:</strong> ${esc(risk || 'No alerts')}</p>
            <div id="sim-impact"><p class="muted">Working out what the threat affected...</p></div>
            <div id="sim-solutions"><p class="muted">Working out what to do about it...</p></div>
            ${this.incidentTable(view.incidents)}
            ${rows ? `<div class="table-wrap"><table><thead><tr><th>Detection</th><th>Expected</th><th>Fired</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table></div>`
                : '<p class="notice">No detections were expected and none fired.</p>'}
            ${this.metricsTable(metrics)}
            <details class="block"><summary>Triggered alerts (${esc(alerts.length)})</summary>${alerts.length ? `<div class="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Rule</th><th class="num">Risk</th><th>Why it was flagged</th></tr></thead>
                <tbody>${alerts.map(alert => `<tr class="clickable" tabindex="0" data-action="open-alert" data-id="${esc(alert.id)}"><td>${chip(alert.severity)}</td><td class="nowrap">${esc(alert.rule_id)}</td><td class="num">${esc(alert.risk_score)}</td><td class="break">${esc(alert.explanation)}</td></tr>`).join('')}</tbody>
            </table></div>` : '<p class="muted">None.</p>'}</details>
            <details class="block"><summary>Generated events (showing ${esc(events.length)} of ${esc(view.event_count)})</summary><div class="table-wrap"><table>
                <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Host</th><th>User</th></tr></thead>
                <tbody>${events.map(event => `<tr class="clickable" tabindex="0" data-action="open-event" data-id="${esc(event.id)}"><td class="nowrap">${esc(formatTime(event.timestamp))}</td><td>${esc(event.source)}</td><td>${esc(event.event_type)}</td><td>${esc(event.hostname)}</td><td>${esc(event.user)}</td></tr>`).join('')}</tbody>
            </table></div></details>
            ${view.report_id ? `<p class="report-links"><strong>Report ${esc(view.report_id)}:</strong> ${reportLinks(view.report_id)}</p>` : ''}
        </article>`;
    }

    async loadImpact(runId) {
        const holder = () => document.getElementById('sim-impact');
        try {
            const impact = await api(`/api/simulations/${encodeURIComponent(runId)}/impact`);
            if (holder()) holder().innerHTML = this.renderImpact(impact);
        } catch (e) {
            if (holder()) holder().innerHTML = `<div class="notice notice-error">Could not work out the impact: ${esc(e.message)}</div>`;
        }
    }

    renderImpact(impact) {
        const detection = impact.detection;
        const stateClass = level => `asset-state asset-state-${level}`;
        const assets = impact.assets.map(asset => `<tr>
            <td>${esc(asset.kind)}</td><td class="break"><code>${esc(asset.name)}</code></td><td>${esc(asset.before)}</td>
            <td><span class="${stateClass(asset.level)}">${esc(asset.after)}</span></td>
            <td class="break"><ul class="plain">${asset.steps.map(step => `<li>${esc(step.effect)} <span class="tag">${esc(step.rule_id)}</span></li>`).join('')}</ul></td>
            <td>${esc(asset.cia.join(', ') || '--')}</td><td>${esc(asset.response || 'Not contained')}</td></tr>`).join('');
        const parameters = impact.parameters.map(row => `<tr>
            <td class="nowrap">${esc(row.rule_id)}</td><td>${esc(row.name)}</td><td>${esc(row.measure)}</td>
            <td class="num">${esc(row.normal_text)}</td><td class="num"><strong>${esc(row.attack_text)}</strong></td><td class="num">${esc(row.threshold_text)}</td>
            <td>${row.crossed ? 'Crossed' : 'Not crossed'}${row.normal_crossed ? ', also by normal logs' : ''}</td></tr>`).join('');
        const activity = impact.activity.map(row => `<tr><td>${esc(row.name)}</td><td class="num">${formatNumber(row.normal)}</td><td class="num"><strong>${formatNumber(row.attack)}</strong></td></tr>`).join('');
        return `<section class="impact" id="impact-panel">
            <h3>${impact.simulated ? 'What the threat did to this simulated environment' : 'What the threat affected in this log'}</h3>
            <p class="impact-headline">${esc(impact.headline)}</p>
            <ul class="flow">
                <li><strong>${esc(impact.assets_unaffected)}</strong><span>assets unaffected</span></li>
                ${Object.entries(impact.state_counts).map(([name, count]) => `<li><strong>${esc(count)}</strong><span>${esc(name.toLowerCase())}</span></li>`).join('')}
                <li><strong>${detection.seconds_to_first_detection === null ? '--' : `${esc(detection.seconds_to_first_detection)} s`}</strong><span>to first detection</span></li>
                <li><strong>${esc(detection.attack_logs_detected)} of ${esc(detection.attack_logs)}</strong><span>attack logs detected</span></li>
                <li><strong>${esc(detection.normal_logs_flagged)} of ${esc(detection.normal_logs)}</strong><span>normal logs flagged</span></li>
            </ul>
            ${impact.cia_affected.length ? `<p><strong>Security properties affected:</strong> ${esc(impact.cia_affected.join(', '))}</p>` : ''}
            ${impact.data_out.length ? `<p><strong>Data sent out:</strong> ${esc(impact.data_out.map(item => `${item.mb} MB to ${item.destination}`).join(', '))}</p>` : ''}
            ${assets ? `<h4 class="section-title">Affected assets: before and after</h4><div class="table-wrap"><table>
                <thead><tr><th>Asset</th><th>Name</th><th>Before</th><th>After</th><th>What happened</th><th>Affects</th><th>Response</th></tr></thead><tbody>${assets}</tbody></table></div>` : ''}
            ${parameters ? `<h4 class="section-title">Why these logs count as a threat: the parameters that crossed their limits</h4><div class="table-wrap"><table>
                <thead><tr><th>Rule</th><th>Name</th><th>Measured</th><th class="num">Normal logs reached</th><th class="num">Attack logs reached</th><th class="num">Limit</th><th>Result</th></tr></thead><tbody>${parameters}</tbody></table></div>` : ''}
            <h4 class="section-title">How the logs changed</h4>
            <div class="table-wrap short"><table><thead><tr><th>Measure</th><th class="num">Normal logs</th><th class="num">Attack logs</th></tr></thead><tbody>${activity}</tbody></table></div>
            <p class="muted">${esc(impact.comparison_basis)} ${esc(impact.response.pending)} response actions await a decision, and ${esc(impact.response.executed)} have run in simulation. ${esc(impact.note)}</p>
            <p><button class="btn" data-action="nars-ask" data-question="What did ${impact.simulated ? 'simulation' : 'log analysis'} ${esc(impact.batch_id)} affect?"><i class="fa-solid fa-robot" aria-hidden="true"></i> Ask NARS about this impact</button></p>
        </section>`;
    }

    /* ---------- Threat parameters ---------- */

    async loadParameters() {
        const isLatest = this.latest('parameters');
        try {
            const [data, measured] = await Promise.all([api('/api/threat-parameters'), api('/api/ml')]);
            if (!isLatest()) return;
            this.renderModels(measured);
            document.getElementById('parameters-principle').textContent = data.principle;
            document.getElementById('parameters-classes').innerHTML = data.classes.map(item => `<div class="tile">${chip(item.name)}<p class="muted" style="margin-top:6px">${esc(item.means)}</p></div>`).join('');
            document.getElementById('parameters-rules').innerHTML = data.rules.map(rule => `<tr title="${esc(rule.definition)}">
                <td class="nowrap">${esc(rule.id)}</td><td>${esc(rule.name)}</td><td class="break">${esc(rule.logs_that_count)}</td><td>${esc(rule.grouped_by)}</td><td>${esc(rule.measure)}</td>
                <td class="num nowrap"><strong>${esc(rule.threshold_text)}</strong></td><td class="num nowrap">${esc(rule.window_seconds)} s</td><td>${chip(rule.severity)}</td>
                <td class="num nowrap">${esc(rule.confidence)}%${rule.max_confidence ? ` to ${esc(rule.max_confidence)}%` : ''}</td><td class="num">${formatNumber(rule.alerts)}</td></tr>`).join('');
            document.getElementById('parameters-indicators').innerHTML = `<h2>Threat intelligence match</h2><p class="muted">${esc(data.indicators.definition)}</p>
                <dl class="facts" style="margin-top:8px">${Object.entries(data.indicators.fields).map(([type, fields]) => `<dt>${esc(type)}</dt><dd>${esc(fields)}</dd>`).join('')}<dt>Severity</dt><dd>${esc(data.indicators.severity)}</dd></dl>`;
            const models = data.models;
            document.getElementById('parameters-models').innerHTML = `<h2>Machine learning signals</h2>
                <p><strong>${esc(models.anomaly.name)}.</strong> ${esc(models.anomaly.counts_as)} Flags a window scoring above the ${esc(models.anomaly.threshold_quantile * 100)}th percentile of normal, with at least ${esc(models.anomaly.minimum_events)} logs, measured on: ${esc(models.anomaly.features.join(', '))}.</p>
                <p><strong>${esc(models.network.name)}.</strong> ${esc(models.network.counts_as)} Needs ${esc(models.network.input)}.</p>`;
            document.getElementById('parameters-behavioral').innerHTML = data.behavioral.map(rule => `<tr><td class="nowrap">${esc(rule.id)}</td><td>${esc(rule.name)}</td><td class="break">${esc(rule.definition)}</td>
                <td class="num">${esc(rule.minimum_history ?? '--')}</td><td>${chip(rule.severity)}</td><td class="num">${formatNumber(rule.alerts)}</td></tr>`).join('');
            document.getElementById('parameters-risk').textContent = `${data.risk.note} Select any log in the Live Stream to see these parameters measured for that log.`;
        } catch (e) {
            this.showError('parameters-rules', e, 10);
        }
    }

    incidentTable(incidents) {
        if (!incidents.length) return '<p class="muted">No incident was created.</p>';
        return `<div class="table-wrap"><table>
            <thead><tr><th>Incident</th><th>Priority</th><th>Title</th><th>Severity</th><th class="num">Confidence</th><th class="num">Risk</th></tr></thead>
            <tbody>${incidents.map(incident => `<tr class="clickable" tabindex="0" data-action="open-incident" data-id="${esc(incident.id)}">
                <td class="nowrap">${esc(incident.incident_uid)}</td><td>${esc(incident.priority || '--')}</td><td class="break">${esc(incident.title)}</td><td>${chip(incident.severity)}</td>
                <td class="num">${esc(incident.confidence)}%</td><td class="num">${esc(incident.risk_score)} ${esc(incident.risk_level)}</td></tr>`).join('')}</tbody>
        </table></div>`;
    }

    metricsTable(metrics) {
        if (!metrics || !metrics.has_ground_truth) {
            return metrics && metrics.note ? `<p class="notice">${esc(metrics.note)}</p>` : '';
        }
        const show = (value) => (value === null || value === undefined ? '--' : esc(value));
        const row = (title, level) => `<tr><td>${title}</td><td class="num">${show(level.true_positives)}</td><td class="num">${show(level.false_positives)}</td><td class="num">${show(level.false_negatives)}</td><td class="num">${show(level.true_negatives)}</td><td class="num">${show(level.precision)}</td><td class="num">${show(level.recall)}</td><td class="num">${show(level.f1)}</td><td class="num">${show(level.false_positive_rate)}</td></tr>`;
        return `<h3 class="section-title">Measured against ground truth</h3>
            <div class="table-wrap"><table>
                <thead><tr><th>Level</th><th class="num">TP</th><th class="num">FP</th><th class="num">FN</th><th class="num">TN</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th><th class="num">FP rate</th></tr></thead>
                <tbody>${row('Events', metrics.event_level)}${row('Alerts', metrics.alert_level)}${row('Incidents', metrics.incident_level)}${metrics.ml_level ? row('Network model, flows', metrics.ml_level) : ''}${metrics.anomaly_level ? row('Anomaly model, events', metrics.anomaly_level) : ''}</tbody>
            </table></div>
            <p class="muted">Synthetic or supplied labels, not real-world performance. Risk scores play no part in these numbers.</p>`;
    }

    /* ---------- Threat intelligence ---------- */

    async loadIocs() {
        try {
            const [iocs, feeds] = await Promise.all([api('/api/iocs?limit=10000'), api('/api/iocs/feeds')]);
            this.iocs = iocs;
            this.renderIocs();
            document.getElementById('ioc-feeds').innerHTML = feeds.length ? feeds.map(feed => `<tr>
                <td class="break">${esc(feed.source)}</td><td class="num">${formatNumber(feed.indicators)}</td>
                <td>${esc(Object.entries(feed.by_type).map(([type, count]) => `${type}: ${count}`).join(', '))}</td>
                <td class="num">${formatNumber(feed.alerts)}</td><td class="nowrap">${esc(formatTime(feed.added_at))}</td>
                <td class="status-control">${feed.has_analysis ? `<button class="btn btn-sm" data-action="view-feed-analysis" data-source="${esc(feed.source)}">Analysis</button>` : ''}
                    <button class="btn btn-sm" data-action="test-feed" data-source="${esc(feed.source)}">Test</button>
                    ${feed.removable ? `<button class="btn btn-sm" data-action="remove-feed" data-source="${esc(feed.source)}">Remove</button>` : '<span class="muted">Bundled</span>'}</td>
            </tr>`).join('') : emptyRow(6, 'No feeds are loaded.');
        } catch (e) {
            this.showError('ioc-body', e, 7);
        }
    }

    async removeFeed(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        button.disabled = true;
        try {
            const result = await api(`/api/iocs/feeds/${encodeURIComponent(button.dataset.source)}`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ analyst }),
            });
            this.toast(`Removed ${formatNumber(result.removed)} indicators from ${result.source}. Alerts they already produced stay on record.`);
            if (this.view === 'intel') this.loadIocs();
            else document.getElementById('upload-result').innerHTML = '';
        } catch (e) {
            this.toast(e.message, true);
            button.disabled = false;
        }
    }

    feedBars(title, items) {
        if (!items || !items.length) return '';
        const top = Math.max(...items.map(item => item.count));
        return `<div class="feed-bars"><h4>${esc(title)}</h4>${items.map(item => `<div class="feed-bar" title="${esc(item.name)}: ${formatNumber(item.count)}">
            <span class="feed-bar-name">${esc(item.name.replace(/_/g, ' '))}</span>
            <span class="feed-bar-track"><i style="width:${Math.max(item.count * 100 / top, 1.5)}%"></i></span>
            <span class="feed-bar-count">${formatNumber(item.count)}${item.percent === undefined ? '' : ` (${esc(item.percent)}%)`}</span></div>`).join('')}</div>`;
    }

    renderFeedAnalysis(analysis) {
        if (!analysis) return '';
        const days = analysis.first_seen_by_day || [];
        return `<section id="feed-analysis"><h4 class="section-title">What this feed contains</h4>
            <p class="impact-headline">${esc(analysis.headline)}</p>
            <div class="feed-grid">
                ${this.feedBars('Indicator types', analysis.by_type)}
                ${this.feedBars('What the feed says they are', analysis.themes)}
                ${this.feedBars('Malware named', analysis.top_malware)}
                ${this.feedBars('Campaigns named', analysis.top_campaigns)}
                ${this.feedBars('Confidence stated by the feed', analysis.confidence)}
                ${this.feedBars('How many sources report each', analysis.corroboration)}
                ${this.feedBars(`Top reporting sources (${formatNumber(analysis.reporters_total)} in total)`, analysis.top_reporters)}
                ${this.feedBars('Top domain endings', analysis.top_domain_endings)}
                ${this.feedBars('First seen, by day (latest 14)', days.map(item => ({ name: item.day, count: item.count })))}
            </div>
            ${analysis.most_corroborated.length ? `<h4 class="section-title">Most widely reported indicators</h4><div class="table-wrap short"><table>
                <thead><tr><th>Indicator</th><th>Type</th><th class="num">Sources</th><th>What the feed says</th><th></th></tr></thead>
                <tbody>${analysis.most_corroborated.map(item => `<tr><td class="break"><code>${esc(item.value)}</code></td><td>${esc(item.ioc_type)}</td><td class="num">${esc(item.sources)}</td><td class="break">${esc(item.reason)}</td>
                    <td><button class="btn btn-sm" data-action="nars-ask" data-question="What is stored about ${esc(item.value)}?">Ask NARS</button></td></tr>`).join('')}</tbody></table></div>` : ''}
            <p class="muted">${esc(analysis.note)}</p></section>`;
    }

    async viewFeedAnalysis(source) {
        this.openDrawer(`Feed analysis: ${source}`, '<p class="muted">Loading...</p>');
        try {
            document.getElementById('drawer-body').innerHTML = this.renderFeedAnalysis(await api(`/api/iocs/feeds/${encodeURIComponent(source)}/analysis`));
        } catch (e) {
            this.showError('drawer-body', e);
        }
    }

    async testFeed(button) {
        button.disabled = true;
        const source = button.dataset.source;
        try {
            const result = await postJson(`/api/iocs/feeds/${encodeURIComponent(source)}/test`, {});
            if (this.view !== 'upload') this.navigate('upload');
            document.getElementById('upload-result').innerHTML = '';
            this.trackDataset(result.dataset.dataset_id);
            document.getElementById('dataset-progress').scrollIntoView({ block: 'nearest' });
        } catch (e) {
            this.toast(e.message, true);
            button.disabled = false;
        }
    }

    renderFeed(feed, imported) {
        const skipped = Object.entries(feed.skipped || {});
        const hunt = feed.retro_hunt;
        const huntSection = !hunt ? '' : `<h4 class="section-title">Retro-hunt of stored events</h4>
            ${hunt.matches.length ? `<p><strong>${formatNumber(hunt.matching_events)} stored ${hunt.matching_events === 1 ? 'event contains' : 'events contain'} ${formatNumber(hunt.matched_indicators)} of these indicators.</strong> This search created no alerts. A match is evidence to check, not proof of compromise.</p>
            <div class="table-wrap short"><table>
                <thead><tr><th>Indicator</th><th>Type</th><th>Field</th><th class="num">Events</th><th>Origin</th><th>First seen</th><th>Last seen</th><th></th></tr></thead>
                <tbody>${hunt.matches.map(match => `<tr><td class="break"><code>${esc(match.indicator)}</code></td><td>${esc(match.ioc_type)}</td><td>${esc(match.field)}</td><td class="num">${formatNumber(match.events)}</td>
                    <td>${esc(Object.keys(match.origins).join(', '))}</td><td class="nowrap">${esc(formatTime(match.first_seen))}</td><td class="nowrap">${esc(formatTime(match.last_seen))}</td>
                    <td><button class="btn btn-sm" data-action="nars-ask" data-question="What is stored about ${esc(match.indicator)}?">Ask NARS</button></td></tr>`).join('')}</tbody>
            </table></div>`
            : `<p>None of these indicators appear in the ${formatNumber(hunt.events_searched)} stored events. That is expected if the stored data is synthetic, because it never contacted these real-world addresses. It says nothing about activity that was never collected. Use <strong>Test this feed</strong> below to see detection work.</p>`}
            <p class="muted">New events are checked against these indicators automatically, and a match opens an alert.</p>`;
        return `<article class="card" id="feed-result">
            <div class="verdict verdict-IOC_FEED" role="status">
                <strong class="verdict-headline">THREAT INTELLIGENCE FEED ${imported ? 'IMPORTED' : 'RECOGNISED'}</strong>
                <p>${esc(feed.name)} lists indicators rather than events, so its own contents are analyzed below. ${imported ? (feed.added ? 'Its indicators are now in Threat Intelligence.' : `All ${formatNumber(feed.updated)} were already loaded, so this upload added nothing new. A different file gives different results.`) : 'Nothing has been stored. Use Analyze log to import it.'}</p>
            </div>
            <ul class="flow">
                <li><strong>${formatNumber(feed.total_rows)}</strong><span>rows</span></li>
                <li><strong>${formatNumber(feed.usable)}</strong><span>usable indicators</span></li>
                ${imported ? `<li><strong>${formatNumber(feed.added)}</strong><span>new</span></li><li><strong>${formatNumber(feed.updated)}</strong><span>already known</span></li>` : ''}
                <li><strong>${formatNumber(skipped.reduce((total, [, count]) => total + count, 0))}</strong><span>left out</span></li>
            </ul>
            <dl class="facts">
                <dt>Types</dt><dd>${esc(Object.entries(feed.by_type).map(([type, count]) => `${type}: ${count}`).join(', ') || 'none usable')}</dd>
                ${skipped.length ? `<dt>Left out</dt><dd>${esc(skipped.map(([reason, count]) => `${reason}: ${count}`).join('; '))}</dd>` : ''}
            </dl>
            ${this.renderFeedAnalysis(feed.analysis)}
            ${huntSection}
            ${imported ? `<h4 class="section-title">Test this feed through the detection pipeline</h4>
            <p class="muted">Plants a sample of these indicators in synthetic normal logs, labelled so that the result can be scored, then runs every engine and produces a verdict, incidents and a report. These are synthetic logs: nothing contacts these addresses.</p>
            <div class="status-control">
                <button class="btn btn-primary" data-action="test-feed" data-source="${esc(feed.name)}"><i class="fa-solid fa-play" aria-hidden="true"></i> Test this feed</button>
                <button class="btn" data-action="nav" data-view="intel">View in Threat Intelligence</button>
                <button class="btn" data-action="remove-feed" data-source="${esc(feed.name)}">Remove this feed</button>
            </div>` : ''}
        </article>`;
    }

    renderIocs() {
        const text = document.getElementById('ioc-search').value.trim().toLowerCase();
        const shown = this.iocs.filter(ioc => !text || `${ioc.value} ${ioc.source} ${ioc.description}`.toLowerCase().includes(text));
        document.getElementById('ioc-count').textContent = `${formatNumber(shown.length)} of ${formatNumber(this.iocs.length)} indicators`;
        document.getElementById('ioc-body').innerHTML = shown.length ? shown.map(ioc => `<tr>
            <td>${esc(ioc.ioc_type)}</td><td class="break"><code>${esc(ioc.value)}</code></td><td>${chip(ioc.severity)}</td>
            <td class="num">${esc(ioc.confidence)}%</td><td>${esc(ioc.source)}</td><td class="break">${esc(ioc.description)}</td><td class="num">${esc(ioc.alerts)}</td>
        </tr>`).join('') : emptyRow(7, 'No indicators match.');
    }

    reportIocImport(report) {
        const errors = (report.errors || []).map(e => `Entry ${e.index + 1}: ${e.error}`).join('; ');
        const summary = `${report.added} added, ${report.updated} updated, ${report.rejected} rejected.${errors ? ` ${errors}` : ''}`;
        this.toast(summary, report.rejected > 0);
        return summary;
    }

    async submitIoc(event) {
        event.preventDefault();
        const form = event.target;
        const values = Object.fromEntries(new FormData(form));
        values.source = values.source || 'manual-entry';
        try {
            const report = await postJson('/api/iocs', [values]);
            this.reportIocImport(report);
            if (!report.rejected) form.elements.value.value = '';
            this.loadIocs();
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    async submitIocImport(event) {
        event.preventDefault();
        const output = document.getElementById('ioc-result');
        let items;
        try {
            items = JSON.parse(event.target.elements.json.value);
        } catch (e) {
            output.innerHTML = '<div class="notice notice-error">That is not valid JSON.</div>';
            return;
        }
        try {
            output.innerHTML = `<div class="notice">${esc(this.reportIocImport(await postJson('/api/iocs', items)))}</div>`;
            this.loadIocs();
        } catch (e) {
            output.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
        }
    }

    /* ---------- Dataset analysis ---------- */

    async loadDatasets() {
        const body = document.getElementById('datasets-body');
        const isLatest = this.latest('datasets');
        try {
            const data = await api('/api/datasets');
            if (!isLatest()) return;
            const profiles = document.querySelector('#generate-form [name="profile"]');
            if (!profiles.options.length) {
                profiles.innerHTML = data.profiles.map(profile => `<option value="${esc(profile.id)}">${esc(profile.name)}</option>`).join('');
                profiles.value = 'mixed';
            }
            document.getElementById('upload-limit').textContent = `Any log type, up to ${data.max_upload_mb} MB`;
            if (data.active_dataset && !this.activeDataset) this.trackDataset(data.active_dataset);
            // Coming back to this page shows the latest result, rather than an empty form
            const output = document.getElementById('upload-result');
            if (!this.latestShown && !output.innerHTML.trim() && !data.active_dataset && !this.activeDataset && data.datasets[0]) {
                this.latestShown = true;
                this.viewDataset(data.datasets[0].dataset_id, false);
            }
            body.innerHTML = data.datasets.length ? data.datasets.map(dataset => {
                const metrics = dataset.metrics || {};
                return `<tr class="clickable" tabindex="0" data-action="view-dataset" data-id="${esc(dataset.dataset_id)}">
                    <td class="nowrap">${esc(formatTime(dataset.created_at))}</td><td class="break">${esc(dataset.name)}</td><td>${esc(DATASET_KINDS[dataset.kind] || dataset.kind)}</td><td>${chip(dataset.verdict || dataset.status)}</td>
                    <td class="num">${formatNumber(dataset.total_events)}</td><td class="num">${formatNumber(metrics.alerts)}</td><td class="num">${formatNumber(metrics.incidents)}</td></tr>`;
            }).join('') : emptyRow(7, 'No logs analyzed yet. Add a log file, or generate one above.');
        } catch (e) {
            this.showError('datasets-body', e, 7);
        }
    }

    validationSummary(summary, invalid) {
        const file = summary.file || {};
        const listed = (values) => Object.entries(values || {}).map(([name, count]) => `${name}: ${count}`).join(', ');
        const columns = summary.columns || [];
        const warnings = summary.warnings || [];
        return `<ul class="flow">
                <li><strong>${formatNumber(summary.total_rows)}</strong><span>total rows</span></li>
                <li><strong>${formatNumber(summary.valid_records)}</strong><span>valid records</span></li>
                <li><strong>${formatNumber(summary.invalid_records)}</strong><span>invalid records</span></li>
                <li><strong>${formatNumber(summary.skipped_duplicates)}</strong><span>duplicates skipped</span></li>
            </ul>
            <dl class="facts">
                <dt>Log type</dt><dd>${esc(summary.dataset_type || 'Not identified')}</dd>
                ${listed(summary.log_types) ? `<dt>Log types found</dt><dd>${esc(listed(summary.log_types))}</dd>` : ''}
                ${file.size_bytes === undefined ? '' : `<dt>File</dt><dd>${esc(file.name)}, ${formatNumber(file.size_bytes)} bytes, ${esc(file.encoding)}, read as ${esc(String(file.structure || '').toUpperCase())}</dd>`}
                ${(summary.timestamp_fields || []).length ? `<dt>Timestamp fields</dt><dd>${esc(summary.timestamp_fields.join(', '))}</dd>` : ''}
                <dt>Ground truth</dt><dd>${esc(listed(summary.labels) || 'none in this data')}</dd>
                <dt>Bad timestamps</dt><dd>${formatNumber(summary.invalid_timestamps || 0)} invalid, ${formatNumber(summary.missing_timestamps || 0)} missing</dd>
                <dt>Malformed lines</dt><dd>${formatNumber(summary.malformed_records || 0)}</dd>
                <dt>Missing values</dt><dd>${esc(listed(summary.missing_values) || 'none')}</dd>
            </dl>
            ${warnings.length ? `<ul class="warnings">${warnings.map(warning => `<li>${esc(warning)}</li>`).join('')}</ul>` : ''}
            ${columns.length ? `<details class="block"><summary>Columns (${esc(columns.length)})</summary><div class="table-wrap short"><table>
                <thead><tr><th>Column</th><th>Type</th><th class="num">Missing</th><th>In the common schema</th></tr></thead>
                <tbody>${columns.map(column => `<tr><td>${esc(column.name)}</td><td>${esc(column.type)}</td><td class="num">${formatNumber(column.missing)}</td><td>${column.mapped ? 'Yes' : 'No: kept with the event, read by no detection'}</td></tr>`).join('')}</tbody>
            </table></div></details>` : ''}
            ${invalid && invalid.length ? `<details class="block" open><summary>Invalid records (showing ${esc(invalid.length)})</summary><ul>
                ${invalid.map(row => `<li>Row ${esc(row.row)}: ${esc(row.errors.join('; '))}</li>`).join('')}</ul></details>` : ''}`;
    }

    async validateDataset() {
        const form = document.getElementById('upload-form');
        const output = document.getElementById('upload-result');
        if (!form.elements.file.files.length) {
            output.innerHTML = '<div class="notice notice-error">Choose a file first.</div>';
            return;
        }
        output.innerHTML = '<p class="notice">Validating...</p>';
        try {
            const result = await api('/api/datasets/validate', { method: 'POST', body: new FormData(form) });
            output.innerHTML = result.ioc_feed
                ? this.renderFeed(result.ioc_feed, false)
                : `<article class="card"><h3>Validation result. Nothing has been stored.</h3>${this.validationSummary(result.summary, result.invalid)}</article>`;
        } catch (e) {
            output.innerHTML = this.validationFailure(e);
        }
    }

    async submitUpload(event, reanalyze = false) {
        if (event) event.preventDefault();
        const form = document.getElementById('upload-form');
        const output = document.getElementById('upload-result');
        const data = new FormData(form);
        if (reanalyze) data.set('reanalyze', '1');
        data.set('analyst', document.getElementById('analyst-name').value.trim());
        const chosen = form.elements.file.files[0];
        output.innerHTML = `<p class="notice"><i class="fa-solid fa-circle-notch fa-spin" aria-hidden="true"></i> Reading ${esc(chosen ? chosen.name : 'the file')}${chosen && chosen.size > 5000000 ? `, ${esc(Math.round(chosen.size / 1048576))} MB. Large files take a little while` : ''}...</p>`;
        output.scrollIntoView({ block: 'nearest' });
        try {
            const result = await api('/api/datasets/upload', { method: 'POST', body: data });
            if (result.ioc_feed) {
                output.innerHTML = this.renderFeed(result.ioc_feed, true);
                this.loadDatasets();
            } else if (result.duplicate_of) {
                await this.viewDataset(result.duplicate_of);
                output.insertAdjacentHTML('afterbegin', `<div class="notice">This exact file was already analyzed, so its events were not processed again.
                    <button class="btn btn-sm" data-action="reanalyze-dataset">Analyze it again</button></div>`);
            } else {
                output.innerHTML = '';
                this.trackDataset(result.dataset.dataset_id);
            }
        } catch (e) {
            output.innerHTML = this.validationFailure(e);
            this.loadDatasets();
        }
    }

    validationFailure(error) {
        const validation = error.body && error.body.validation;
        return `<article class="card"><div class="verdict verdict-VALIDATION_FAILED" role="status">
                <strong class="verdict-headline">VALIDATION FAILED</strong><p>${esc(error.message)}</p>
            </div>${validation ? this.validationSummary(validation, null) : ''}</article>`;
    }

    async submitGenerate(event) {
        event.preventDefault();
        const output = document.getElementById('upload-result');
        output.innerHTML = '';
        try {
            const result = await postJson('/api/datasets/generate', Object.fromEntries(new FormData(event.target)));
            this.trackDataset(result.dataset.dataset_id);
        } catch (e) {
            output.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
        }
    }

    trackDataset(datasetId) {
        this.activeDataset = datasetId;
        clearInterval(this.datasetTimer);
        this.datasetTimer = setInterval(() => this.refreshDataset(), 1000);
        this.refreshDataset();
    }

    async refreshDataset() {
        const datasetId = this.activeDataset;
        if (!datasetId) return;
        const isLatest = this.latest('dataset');
        try {
            const dataset = await api(`/api/datasets/${datasetId}`);
            if (!isLatest() || this.activeDataset !== datasetId) return;
            const box = document.getElementById('dataset-progress');
            if (dataset.active || dataset.status === 'PROCESSING') {
                const percent = dataset.total_events ? Math.round(dataset.processed_events / dataset.total_events * 100) : 0;
                box.hidden = false;
                box.innerHTML = `<h3>${esc(dataset.name)}: processing</h3>
                    <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}"><span style="width:${percent}%"></span></div>
                    <p class="muted">${formatNumber(dataset.processed_events)} of ${formatNumber(dataset.total_events)} events stored, then detection runs over them.</p>`;
                return;
            }
            this.activeDataset = null;
            clearInterval(this.datasetTimer);
            box.hidden = true;
            document.getElementById('upload-result').innerHTML = this.renderDataset(dataset);
            this.loadDatasetImpact(dataset);
            if (this.view === 'upload') this.loadDatasets();
            else this.toast(`Dataset ${dataset.name} ended: ${dataset.status}.`);
            this.refreshStats();
        } catch (e) {
            this.toast(`Could not read this result: ${e.message}`, true);
        }
    }

    async loadDatasetImpact(dataset) {
        const holder = () => document.getElementById('dataset-impact');
        if (!holder() || dataset.kind === 'feed') return;
        try {
            const impact = await api(`/api/datasets/${encodeURIComponent(dataset.dataset_id)}/impact`);
            if (holder() && impact.assets.length) holder().innerHTML = this.renderImpact(impact);
        } catch (e) {
            if (holder()) holder().innerHTML = '';
        }
    }

    async viewDataset(datasetId, scroll = true) {
        const output = document.getElementById('upload-result');
        try {
            const dataset = await api(`/api/datasets/${datasetId}`);
            output.innerHTML = this.renderDataset(dataset);
            this.loadDatasetImpact(dataset);
            if (scroll) output.scrollIntoView({ block: 'nearest' });
        } catch (e) {
            output.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
        }
    }

    verdictBanner(dataset) {
        const stored = (dataset.analysis || {}).verdict;
        const verdict = stored || {
            status: dataset.verdict || dataset.status,
            headline: { VALIDATION_FAILED: 'VALIDATION FAILED', ANALYSIS_INCOMPLETE: 'ANALYSIS INCOMPLETE' }[dataset.verdict] || dataset.status,
            statement: dataset.error || '',
            reasons: [],
        };
        return `<div class="verdict verdict-${esc(verdict.status)}" role="status">
            <strong class="verdict-headline">${esc(verdict.headline)}</strong>
            <p>${esc(verdict.statement)}</p>
            ${verdict.reasons.length ? `<ul>${verdict.reasons.map(reason => `<li>${esc(reason)}</li>`).join('')}</ul>` : ''}
            ${dataset.dataset_id && stored ? `<button class="btn btn-sm" data-action="nars-ask" data-question="Explain log analysis ${esc(dataset.dataset_id)}"><i class="fa-solid fa-robot" aria-hidden="true"></i> Ask NARS about this result</button>` : ''}
        </div>`;
    }

    engineTable(engines) {
        return `<div class="table-wrap"><table>
            <thead><tr><th>Detection engine</th><th>Status</th><th class="num">Events evaluated</th><th class="num">Findings</th><th>Detail</th></tr></thead>
            <tbody>${engines.map(engine => `<tr><td class="nowrap">${esc(engine.name)}</td><td>${chip(engine.status)}</td>
                <td class="num">${formatNumber(engine.evaluated)}</td><td class="num">${formatNumber(engine.findings)}</td><td class="break">${esc(engine.reason || '')}</td></tr>`).join('')}</tbody>
        </table></div>`;
    }

    findingTable(title, alerts, empty) {
        return `<h4 class="finding-title">${esc(title)} (${esc(alerts.length)})</h4>
            ${alerts.length ? `<div class="table-wrap"><table>
                <thead><tr><th>Severity</th><th>Class</th><th>Rule</th><th class="num">Confidence</th><th class="num">Risk</th><th class="num">Events</th><th>Why it was flagged</th></tr></thead>
                <tbody>${alerts.map(alert => `<tr class="clickable" tabindex="0" data-action="open-alert" data-id="${esc(alert.id)}">
                    <td>${chip(alert.severity)}</td><td class="nowrap">${alert.confirmed ? 'Confirmed' : 'Suspicious'}</td><td><strong>${esc(alert.rule_id)}</strong><br>${esc(alert.rule_name)}</td>
                    <td class="num">${esc(alert.confidence)}%</td><td class="num">${esc(alert.risk_score)}</td><td class="num">${esc(alert.event_count)}</td><td class="break">${esc(alert.explanation)}</td></tr>`).join('')}</tbody>
            </table></div>` : `<p class="muted">${esc(empty)}</p>`}`;
    }

    renderDataset(dataset) {
        if (dataset.kind === 'feed' && dataset.analysis) return this.renderFeed(dataset.analysis, true);
        const metrics = dataset.metrics || {};
        const analysis = dataset.analysis;
        const counts = (values) => Object.entries(values || {}).map(([name, count]) => `${name}: ${count}`).join(', ') || 'None';
        const labels = (dataset.summary || {}).labels || {};
        const alerts = dataset.alerts || [];
        const ofType = (type) => alerts.filter(alert => alert.detection_type === type);
        const head = `<div class="card-head"><h3>${esc(dataset.name)}</h3>${dataset.status === 'COMPLETED' ? '' : chip(dataset.status)}</div>
            ${this.verdictBanner(dataset)}
            ${dataset.error && analysis ? `<div class="notice notice-error">${esc(dataset.error)}</div>` : ''}
            <p class="muted">Analysis ${esc(dataset.dataset_id)}, ${esc(formatTime(dataset.created_at))} to ${esc(formatTime(dataset.completed_at))}${metrics.processing_seconds === undefined ? '' : `, ${esc(metrics.processing_seconds)} seconds of processing`}.</p>`;
        const validation = `<h3 class="section-title">What was read</h3>${this.validationSummary(dataset.summary || {}, dataset.invalid_records)}`;
        if (!analysis) return `<article class="card">${head}${dataset.summary ? validation : ''}</article>`;

        const classes = analysis.classification;
        const ml = analysis.ml;
        const anomalies = analysis.anomalies;
        const incidents = dataset.incidents || [];
        return `<article class="card">
            ${head}
            ${validation}
            <h3 class="section-title">Detection engine status</h3>
            ${this.engineTable(analysis.engines)}
            <h3 class="section-title">Analysis overview</h3>
            <ul class="flow">
                <li><strong>${formatNumber(dataset.processed_events)}</strong><span>events stored</span></li>
                <li><strong>${formatNumber(classes.confirmed_detections.events)}</strong><span>events in confirmed detections</span></li>
                <li><strong>${formatNumber(classes.suspicious_activity.events)}</strong><span>suspicious events</span></li>
                <li><strong>${formatNumber(classes.benign_activity.events)}</strong><span>benign events</span></li>
                <li><strong>${formatNumber(analysis.counts.not_evaluated_events)}</strong><span>events not evaluated</span></li>
                <li><strong>${formatNumber(metrics.alerts)}</strong><span>alerts</span></li>
                <li><strong>${esc(incidents.length)}</strong><span>incidents</span></li>
            </ul>
            <p class="muted">${esc(classes.benign_activity.note)}</p>
            <div id="dataset-impact"></div>
            ${dataset.summary && dataset.summary.has_ground_truth ? `<p><strong>Ground truth in this data:</strong> ${formatNumber(labels.normal || 0)} normal, ${formatNumber(labels.suspicious || 0)} suspicious, ${formatNumber(labels.malicious || 0)} malicious. ${metrics.event_level ? `${formatNumber(metrics.event_level.false_negatives)} truly bad event(s) were missed.` : ''}</p>` : ''}
            ${classes.detection_limitations.length ? `<h4 class="finding-title">Detection limitations</h4><ul>${classes.detection_limitations.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : ''}
            <h3 class="section-title">Threat detection results</h3>
            <p><strong>Detections:</strong> ${esc(counts(dataset.detection_distribution))}</p>
            <p><strong>Alert severity:</strong> ${esc(counts(dataset.severity_distribution))}</p>
            ${this.findingTable('IOC matches', ofType('IOC'), analysis.ioc.note || 'None.')}
            ${this.findingTable('IOA rule matches', ofType('IOA'), 'No behavior rule fired.')}
            ${this.findingTable('UEBA findings', ofType('UEBA'), 'No account or host departed from its own baseline, or there was too little history to judge.')}
            ${this.findingTable('ML findings', ofType('ML'), 'The saved network model flagged no flow with a timestamp.')}
            <h4 class="finding-title">ML classification</h4>
            ${ml.flows_classified ? `<p>${formatNumber(ml.flows_classified)} flow(s) classified by model version <code>${esc(ml.model_version)}</code>. ${esc(counts(ml.distribution))}.</p><p class="muted">${esc(ml.note)} No prediction confidence is shown, because the model is not calibrated.</p>` : '<p class="muted">The saved network model classified nothing here. The engine status above says why.</p>'}
            <h4 class="finding-title">Anomaly findings (${esc(anomalies.windows)})</h4>
            ${anomalies.windows ? `<p class="muted">${esc(anomalies.note)}</p><div class="table-wrap short"><table>
                <thead><tr><th>Source or host</th><th class="num">Strength</th><th class="num">Events</th><th>Why it is unusual</th></tr></thead>
                <tbody>${anomalies.findings.map(item => `<tr><td class="nowrap">${esc(item.entity)}</td><td class="num">${esc(item.strength)}</td><td class="num">${esc(item.event_count)}</td><td class="break">${esc(item.explanation)}</td></tr>`).join('')}</tbody>
            </table></div>` : '<p class="muted">No activity window was statistically unusual.</p>'}
            <h3 class="section-title">Attack investigation and risk</h3>
            ${this.incidentTable(incidents)}
            ${incidents.map((incident, index) => `<details class="block"${index === 0 ? ' open' : ''}><summary><strong>${esc(incident.incident_uid)}</strong> ${esc(incident.title)}</summary>
                <p class="muted">Hosts: ${esc(incident.hosts.join(', ') || 'none named')}. Users: ${esc(incident.users.join(', ') || 'none named')}.</p>
                <ol class="timeline">${incident.timeline.map(entry => `<li><time>${esc(formatTime(entry.timestamp))}</time>
                    <span>${esc(entry.summary)}${entry.count > 1 ? ` <strong>x${esc(entry.count)}</strong>` : ''} ${tags(entry.rule_ids)}</span></li>`).join('')}</ol>
                <p><strong>Why this risk score:</strong></p>
                <ul>${incident.risk_reasons.map(reason => `<li>${esc(reason.factor.replace(/_/g, ' '))}: ${esc(reason.points)} points. ${esc(reason.reason)}</li>`).join('')}</ul>
            </details>`).join('')}
            ${analysis.mitre.length ? `<p><strong>MITRE ATT&amp;CK:</strong> ${analysis.mitre.map(t => `<span class="tag">${esc(t.id)} ${esc(t.tactic)}</span>`).join('')}</p>` : ''}
            ${analysis.affected.users.length || analysis.affected.hosts.length ? `<p><strong>Affected:</strong> users ${esc(analysis.affected.users.join(', ') || 'none named')}; hosts ${esc(analysis.affected.hosts.join(', ') || 'none named')}.</p>` : ''}
            <h3 class="section-title">Recommended response</h3>
            <p class="notice">Historical analysis is read-only. Nothing has been blocked, patched, stopped or isolated. High and critical risks wait for SOC approval. At small risk, safe steps run on their own and disruptive actions are held. All of it runs only in simulation.</p>
            ${analysis.remediation.length ? `<ul>${analysis.remediation.map(item => `<li><strong>${esc(item.rule_id)} ${esc(item.rule_name)}:</strong> ${esc(item.steps.join(' '))}</li>`).join('')}</ul>
                <p><button class="btn" data-action="nav" data-view="approvals">Review on the Response page</button></p>` : '<p class="muted">These findings call for no remediation.</p>'}
            ${this.metricsTable(metrics)}
            <h3 class="section-title">Security report</h3>
            ${dataset.report_id ? `<p class="report-links"><strong>Report ${esc(dataset.report_id)}:</strong> ${reportLinks(dataset.report_id)}</p>` : '<p class="muted">No report was generated.</p>'}
        </article>`;
    }

    /* ---------- Risk management ---------- */

    async loadRisk() {
        const isLatest = this.latest('risk');
        try {
            const [risk, notifications, health, stats, rules] = await Promise.all([api('/api/risk'), api('/api/notifications'), api('/api/health'), api('/api/stats'), api('/api/rules')]);
            if (!isLatest()) return;
            this.renderHealth(health, stats, rules.behavioral_rules.length);
            this.loadEmailStatus();
            document.getElementById('risk-tiles').innerHTML = LEVELS.map(level => `
                <div class="tile"><span class="tile-label">${esc(level)} risk incidents</span><span class="tile-value">${formatNumber(risk.incident_distribution[level] || 0)}</span></div>`).join('');
            if (!this.isEditing('risk-form')) this.renderRiskSettings(risk);
            document.getElementById('risk-approval').innerHTML = `<ul>${risk.approval_required_actions.map(action => `<li><strong>${esc(action.label)}:</strong> ${esc(action.expected_impact)}</li>`).join('')}</ul>`;
            document.getElementById('risk-policy').innerHTML = LEVELS.map((level, index) => {
                const policy = risk.policy[level];
                const top = index === 0 ? 100 : risk.levels[LEVELS[index - 1]] - 1;
                return `<tr><td>${chip(level)}</td><td class="nowrap">${esc(risk.levels[level])} to ${esc(top)}</td><td>${esc(policy.priority)}</td>
                    <td class="break"><ul class="plain">${policy.automatic.map(step => `<li>${esc(step.title)}</li>`).join('')}</ul></td>
                    <td>${esc(policy.notify || 'None')}</td><td class="break">${policy.response === 'automatic' ? 'Handled automatically. Disruptive actions are held.' : 'The SOC approves every response action.'}</td></tr>`;
            }).join('');
            document.getElementById('risk-notifications').innerHTML = notifications.length ? notifications.map(item => `<tr>
                <td class="nowrap">${esc(formatTime(item.created_at))}</td><td>${chip(item.level)}</td><td class="break">${item.read_at ? '' : '<strong>New:</strong> '}${esc(item.message)}</td>
                <td><button class="link" data-action="open-incident" data-id="${esc(item.incident_id)}">#${esc(item.incident_id)}</button></td></tr>`).join('') : emptyRow(4, 'No notifications. High and critical incidents appear here.');
            document.getElementById('risk-automation').innerHTML = risk.recent_automation.length ? risk.recent_automation.map(item => `<tr>
                <td class="nowrap">${esc(formatTime(item.created_at))}</td><td>${esc(item.subject)}</td><td>${chip(item.risk_level)}</td><td class="break">${esc((item.detail || {}).title || item.step)}</td></tr>`).join('') : emptyRow(4, 'No automatic steps have run yet.');
        } catch (e) {
            this.showError('risk-policy', e, 6);
        }
    }

    renderModels(models) {
        const anomaly = models.anomaly_model;
        const network = models.network_model;
        const measured = anomaly.evaluation;
        document.getElementById('risk-models').innerHTML = `
            <article class="card">
                <h2>${esc(anomaly.name)} ${chip(anomaly.available ? 'AVAILABLE' : 'UNAVAILABLE')}</h2>
                <p class="muted">${esc(anomaly.reason || anomaly.note)}</p>
                ${measured ? `<dl class="facts" style="margin-top:8px">
                    <dt>Trained on</dt><dd>${formatNumber(anomaly.trained_windows)} synthetic normal windows</dd>
                    <dt>False alarms</dt><dd>${formatNumber(measured.held_out_false_alarms)} of ${formatNumber(measured.held_out_normal_windows)} held-out normal windows (${esc((measured.false_alarm_rate * 100).toFixed(2))}%)</dd>
                    <dt>Attack windows flagged</dt><dd>${formatNumber(measured.attack_windows_flagged)} of ${formatNumber(measured.attack_windows)} (recall ${esc(measured.recall)})</dd>
                </dl><p class="muted" style="margin-top:8px">${esc(measured.note)}</p>` : ''}
            </article>
            <article class="card">
                <h2>${esc(network.name)} ${chip(network.available ? 'AVAILABLE' : 'UNAVAILABLE')}</h2>
                <p class="muted">${esc(network.reason || network.note)}</p>
                <dl class="facts" style="margin-top:8px">
                    <dt>Input</dt><dd>${esc(network.input)}</dd>
                    <dt>Version</dt><dd>${esc(network.version || 'Loads when flow data first arrives')}</dd>
                    <dt>Classes</dt><dd>${esc((network.classes || []).join(', ') || 'Known once loaded')}</dd>
                    <dt>Accuracy</dt><dd>Not claimed: not validated here</dd>
                    <dt>Confidence</dt><dd>Not reported: not calibrated</dd>
                </dl>
            </article>`;
    }

    renderRiskSettings(risk) {
        const field = (name, label, value, attributes = '') => `<label>${esc(label)} <input type="number" name="${esc(name)}" value="${esc(value)}" required ${attributes}></label>`;
        document.getElementById('risk-settings').innerHTML = `
            ${Object.entries(risk.weights).map(([name, value]) => field(`weight.${name}`, `Weight: ${name.replace(/_/g, ' ')}`, value, 'min="0" max="100" step="any"')).join('')}
            ${LEVELS.map(level => field(`level.${level}`, `${level} starts at`, risk.levels[level], `min="0" max="100"${level === 'LOW' ? ' readonly' : ''}`)).join('')}`;
    }

    async loadEmailStatus() {
        try {
            const email = await api('/api/email/status');
            document.getElementById('email-card').innerHTML = `<div class="card-head"><h2>Alert emails ${chip(email.configured ? 'AVAILABLE' : 'NOT_RUN')}</h2>
                    <div style="display:flex;gap:8px;align-items:center;">
                        <button class="btn btn-sm btn-ghost" data-action="toggle-smtp-settings"><i class="fa-solid fa-sliders"></i> SMTP Settings</button>
                        <button class="btn btn-sm" data-action="email-test" ${email.configured ? '' : 'disabled'}>Send a test email</button>
                    </div></div>
                <div id="smtp-config-container" class="smtp-config-box" hidden><form id="smtp-config-form"></form></div>
                ${email.configured
        ? `<p class="muted">Incidents at ${esc(email.minimum_risk)} risk or above are emailed through ${esc(email.server)} to ${esc(plural(email.recipients, 'recipient'))}, up to ${esc(email.max_per_hour)} an hour. Each incident is emailed once per risk level. Simulated incidents say so in the subject.</p>`
        : `<p class="muted">Not set up. ${esc(email.needs)} The settings are listed in <code>.env.example</code>.</p>`}
                ${email.recent.length ? `<div class="table-wrap short"><table><thead><tr><th>Time</th><th>Subject</th><th>Result</th></tr></thead><tbody>
                    ${email.recent.map(item => `<tr><td class="nowrap">${esc(formatTime(item.created_at))}</td><td class="break">${esc(item.subject)}</td><td>${chip(item.status)}${item.error ? ` <span class="muted">${esc(item.error)}</span>` : ''}</td></tr>`).join('')}
                </tbody></table></div>` : '<p class="muted">No emails have been sent.</p>'}`;
            
            const configForm = document.getElementById('smtp-config-form');
            if (configForm) {
                configForm.addEventListener('submit', (e) => {
                    e.preventDefault();
                    this.saveSmtpConfig(configForm);
                });
            }
        } catch (e) {
            this.showError('email-card', e);
        }
    }

    async toggleSmtpSettings() {
        const box = document.getElementById('smtp-config-container');
        if (!box) return;
        if (!box.hidden) {
            box.hidden = true;
            return;
        }
        try {
            const config = await api('/api/email/config');
            document.getElementById('smtp-config-form').innerHTML = `
                <div class="smtp-form-grid">
                    <label>SMTP Host <input name="smtp_host" value="${esc(config.host || 'smtp.gmail.com')}" required placeholder="smtp.gmail.com"></label>
                    <label>SMTP Port <input type="number" name="smtp_port" value="${esc(config.port || 587)}" required></label>
                    <label>Security 
                        <select name="smtp_security">
                            <option value="starttls" ${config.security === 'starttls' ? 'selected' : ''}>STARTTLS (Port 587)</option>
                            <option value="ssl" ${config.security === 'ssl' ? 'selected' : ''}>SSL/TLS (Port 465)</option>
                            <option value="none" ${config.security === 'none' ? 'selected' : ''}>None (Plaintext/Local)</option>
                        </select>
                    </label>
                    <label>Username / Email <input name="smtp_user" value="${esc(config.user || '')}" placeholder="alerts@domain.com"></label>
                    <label>Password / App Password <input type="password" name="smtp_password" placeholder="${config.has_password ? '•••••••• (unchanged)' : 'Enter password'}"></label>
                    <label>Sender Address <input name="smtp_from" value="${esc(config.from_email || '')}" placeholder="alerts@domain.com"></label>
                    <label>Alert Recipient(s) <input name="smtp_to" value="${esc(config.to_email || '')}" required placeholder="analyst@domain.com, soc@domain.com"></label>
                    <label>Minimum Alert Risk 
                        <select name="smtp_min_risk">
                            <option value="LOW" ${config.min_risk === 'LOW' ? 'selected' : ''}>LOW</option>
                            <option value="MEDIUM" ${config.min_risk === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                            <option value="HIGH" ${config.min_risk === 'HIGH' ? 'selected' : ''}>HIGH</option>
                            <option value="CRITICAL" ${config.min_risk === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                        </select>
                    </label>
                </div>
                <div class="smtp-form-actions">
                    <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-floppy-disk"></i> Save SMTP Configuration</button>
                    <button type="button" class="btn btn-ghost btn-sm" data-action="toggle-smtp-settings">Cancel</button>
                </div>`;
            box.hidden = false;
        } catch (e) {
            this.toast(`Failed to load SMTP config: ${e.message}`, true);
        }
    }

    async saveSmtpConfig(form) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        const body = {
            analyst,
            host: form.elements.smtp_host.value,
            port: form.elements.smtp_port.value,
            security: form.elements.smtp_security.value,
            user: form.elements.smtp_user.value,
            password: form.elements.smtp_password.value,
            from_email: form.elements.smtp_from.value,
            to_email: form.elements.smtp_to.value,
            min_risk: form.elements.smtp_min_risk.value,
        };
        try {
            await postJson('/api/email/config', body);
            this.toast('SMTP settings saved and integrated successfully.');
            const box = document.getElementById('smtp-config-container');
            if (box) box.hidden = true;
            this.loadEmailStatus();
        } catch (e) {
            this.toast(`Failed to save SMTP config: ${e.message}`, true);
        }
    }

    async sendTestEmail(button) {
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        button.disabled = true;
        try {
            await postJson('/api/email/test', { analyst });
            this.toast('Test email sent.');
        } catch (e) {
            this.toast(`Test email failed: ${e.message}`, true);
        }
        this.loadEmailStatus();
    }

    async submitRiskSettings(event) {
        event.preventDefault();
        const analyst = this.requireAnalyst();
        if (!analyst) return;
        const body = { analyst, weights: {}, levels: {} };
        new FormData(event.target).forEach((value, key) => {
            const [kind, name] = key.split('.');
            body[kind === 'weight' ? 'weights' : 'levels'][name] = Number(value);
        });
        try {
            const saved = await api('/api/risk/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            this.toast(`Saved. ${plural(saved.incidents_rescored, 'open incident')} scored again.`);
            document.activeElement.blur();
            this.loadRisk();
            this.refreshStats();
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    async readNotifications() {
        try {
            await postJson('/api/notifications/read', {});
            this.loadRisk();
            this.refreshStats();
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    /* ---------- Reports ---------- */

    async loadReports() {
        const body = document.getElementById('reports-body');
        const isLatest = this.latest('reports');
        try {
            const reports = await api('/api/reports');
            if (!isLatest()) return;
            body.innerHTML = reports.length ? reports.map(report => `<tr>
                <td class="nowrap">${esc(formatTime(report.generated_at))}</td><td class="break">${esc(report.title)}</td><td class="nowrap"><code>${esc(report.report_id)}</code></td>
                <td class="nowrap">${reportLinks(report.report_id)}</td>
                <td class="nowrap"><button class="btn btn-sm" data-action="view-report" data-id="${esc(report.report_id)}">View</button>
                    <button class="btn btn-sm" data-action="new-report" data-type="${esc(report.subject_type)}" data-id="${esc(report.subject_id)}">New version</button></td></tr>`).join('')
                : emptyRow(5, 'No reports yet. Each finished simulation or log analysis creates one.');
        } catch (e) {
            this.showError('reports-body', e, 5);
        }
    }

    async viewReport(reportId) {
        this.openDrawer('Report', '<p class="muted">Loading...</p>');
        try {
            const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}?format=md`);
            if (!response.ok) throw new Error(`Request failed (${response.status})`);
            document.getElementById('drawer-body').innerHTML = `<p class="report-links">${reportLinks(reportId)}</p><pre class="report-text">${esc(await response.text())}</pre>`;
        } catch (e) {
            this.showError('drawer-body', e);
        }
    }

    async newReport(button) {
        try {
            const report = await postJson('/api/reports', { subject_type: button.dataset.type, subject_id: button.dataset.id });
            this.toast(`Generated ${report.report_id} from the stored results.`);
            this.loadReports();
        } catch (e) {
            this.toast(e.message, true);
        }
    }

    /* ---------- Audit ---------- */

    auditTable(entries, includeIncident) {
        if (!entries.length) return '<p class="empty">No audit entries match.</p>';
        return `<div class="table-wrap" style="margin-top:8px"><table>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th>${includeIncident ? '<th>Incident</th>' : ''}<th>Details</th></tr></thead>
            <tbody>${entries.map(entry => this.auditRow(entry, includeIncident)).join('')}</tbody></table></div>`;
    }

    auditRow(entry, includeIncident) {
        return `<tr>
            <td class="nowrap">${esc(formatTime(entry.timestamp))}</td>
            <td>${esc(entry.actor)}</td>
            <td>${esc(entry.action)}</td>
            ${includeIncident ? `<td>${entry.incident_id ? `<button class="link" data-action="open-incident" data-id="${esc(entry.incident_id)}">#${esc(entry.incident_id)}</button>` : '--'}</td>` : ''}
            <td class="break"><code>${esc(entry.details ? JSON.stringify(entry.details) : '')}</code></td>
        </tr>`;
    }

    async loadAudit() {
        const body = document.getElementById('audit-body');
        const isLatest = this.latest('audit');
        try {
            const entries = await api(`/api/audit?limit=300&${queryFrom(document.getElementById('audit-filter'))}`);
            if (!isLatest()) return;
            body.innerHTML = entries.length ? entries.map(entry => this.auditRow(entry, true)).join('') : emptyRow(5, 'No audit entries match these filters.');
        } catch (e) {
            this.showError('audit-body', e, 5);
        }
    }

    /* ---------- Applying a tile's filter ---------- */

    /* ---------- ATT&CK coverage ---------- */

    async loadAttackMatrix() {
        const isLatest = this.latest('attack');
        try {
            const matrix = await api('/api/attack-matrix');
            if (!isLatest()) return;
            this.matrix = matrix;
            const totals = matrix.totals;
            document.getElementById('attack-tiles').innerHTML = [
                ['Tactics with a rule', `${totals.tactics_with_rules} of ${totals.tactics}`],
                ['Techniques looked for', totals.techniques],
                ['Tested by a scenario', totals.techniques_tested],
                ['Have fired on stored data', totals.techniques_with_alerts],
            ].map(([label, value]) => `<div class="tile"><span class="tile-label">${esc(label)}</span><span class="tile-value">${esc(value)}</span></div>`).join('');
            document.getElementById('attack-legend').innerHTML = HEAT_STEPS.map((step, index) => `<span class="attack-legend-item"><i class="heat-swatch heat-${HEAT_STEPS.length - 1 - index}"></i>${esc(step.label)}</span>`).join('');
            document.getElementById('attack-grid').innerHTML = matrix.tactics.map(tactic => `<div class="attack-column">
                <div class="attack-tactic"><strong>${esc(tactic.name)}</strong><span class="muted">${esc(plural(tactic.techniques.length, 'technique'))}</span></div>
                ${tactic.techniques.map(technique => `<button class="attack-cell heat-${this.heatStep(technique.alerts)}" data-action="open-technique" data-id="${esc(technique.id)}" data-tactic="${esc(tactic.name)}">
                    <strong>${esc(technique.id)}</strong><span>${esc(technique.name)}</span>
                    <span class="attack-cell-meta">${esc(plural(technique.alerts, 'alert'))}${technique.scenarios.length ? ', Tested' : ''}</span>
                </button>`).join('') || '<p class="attack-gap">No rule</p>'}
            </div>`).join('');
        } catch (e) {
            this.showError('attack-grid', e);
        }
    }

    heatStep(alerts) {
        return HEAT_STEPS.length - 1 - HEAT_STEPS.findIndex(step => alerts >= step.min);
    }

    openTechnique(id, tacticName) {
        const tactic = this.matrix.tactics.find(item => item.name === tacticName);
        const technique = tactic && tactic.techniques.find(item => item.id === id);
        if (!technique) return;
        this.openDrawer(`${technique.id} ${technique.name}`, `<dl class="facts"><dt>Tactic</dt><dd>${esc(tactic.name)}</dd><dt>Alerts</dt><dd>${formatNumber(technique.alerts)}</dd>
                <dt>Tested by</dt><dd>${esc(technique.scenarios.join(', ') || 'No scenario exercises these rules')}</dd></dl>
            <h3 class="section-title">Rules that look for it</h3>
            <div class="table-wrap"><table><thead><tr><th>Rule</th><th>Name</th><th class="num">Alerts</th><th>Last fired</th></tr></thead>
            <tbody>${technique.rules.map(rule => `<tr><td class="nowrap">${esc(rule.id)}</td><td>${esc(rule.name)}</td><td class="num">${formatNumber(rule.alerts)}</td><td class="nowrap">${esc(formatTime(rule.last_fired))}</td></tr>`).join('')}</tbody></table></div>
            <p style="margin-top:10px"><button class="btn" data-action="nars-ask" data-question="${esc(`Tell me about rule ${technique.rules[0].id}`)}"><i class="fa-solid fa-robot" aria-hidden="true"></i> Ask NARS about ${esc(technique.rules[0].id)}</button></p>`);
    }

    /* ---------- Accounts ---------- */

    async loadAccount() {
        try {
            const account = await api('/api/auth/me');
            if (!account.auth_enabled || !account.user) return;
            const input = document.getElementById('analyst-name');
            input.value = account.user.username;
            input.readOnly = true;
            input.title = `Signed in as ${account.user.username} (${account.user.role})`;
            document.getElementById('logout').hidden = false;
        } catch (e) { /* The analyst name field stays editable */ }
    }

    async logout() {
        try {
            await postJson('/api/auth/logout', {});
        } finally {
            window.location.assign('/login');
        }
    }

    /* ---------- NARS, the analyst assistant ---------- */

    async loadNars() {
        try {
            const status = await api('/api/nars/status');
            document.getElementById('nars-mode').textContent = status.label;
            document.getElementById('nars-note').textContent = status.note;
            this.renderNarsSuggestions();
        } catch (e) {
            document.getElementById('nars-note').textContent = `NARS could not start: ${e.message}`;
        }
    }

    toggleNars(open) {
        const panel = document.getElementById('nars-panel');
        const show = open === undefined ? panel.hidden : open;
        panel.hidden = !show;
        document.getElementById('nars-launcher').setAttribute('aria-expanded', String(show));
        document.getElementById('nars-launcher').hidden = show;
        document.body.classList.toggle('nars-open', show);
        if (show) document.getElementById('nars-input').focus();
    }

    narsContext() {
        const open = this.view === 'investigations' && this.incidentId ? this.incidentId : this.narsIncident;
        return { view: this.view, incident_id: open || null };
    }

    renderNarsSuggestions(suggestions) {
        const uidOf = (id) => `INC-${String(id).padStart(6, '0')}`;
        const viewing = this.view === 'investigations' && this.incidentId;
        const chosen = suggestions && suggestions.length ? suggestions : viewing
            ? [`Explain ${uidOf(viewing)}`, `What should I do next on ${uidOf(viewing)}?`, `Why is the risk of ${uidOf(viewing)} this high?`]
            : {
                attack: ['What can you detect?', 'Any lateral movement?', 'What are your limitations?'],
                parameters: ['What parameters define a threat?', 'Tell me about rule IOA-009', 'What did the latest simulation affect?'],
                events: ['What parameters define a threat?', 'What should I look at first?', 'Any lateral movement?'],
                upload: ['What was the latest log analysis result?', 'Which threat intelligence feeds are loaded?', 'Which ML models do you use?'],
                intel: ['Which threat intelligence feeds are loaded?', 'What should I look at first?'],
                approvals: ['What is waiting for my approval?', 'What should I look at first?'],
                simulation: ['What did the latest simulation affect?', 'How did the latest simulations go?', 'What parameters define a threat?'],
            }[this.view] || ['What should I look at first?', 'What is waiting for my approval?', 'Any lateral movement?'];
        document.getElementById('nars-suggestions').innerHTML = chosen.map(text => `<button class="nars-chip" data-action="nars-ask" data-question="${esc(text)}">${esc(text)}</button>`).join('');
    }

    narsAppend(html, className) {
        const log = document.getElementById('nars-log');
        const element = document.createElement('div');
        element.className = `nars-message ${className}`;
        element.innerHTML = html;
        log.appendChild(element);
        log.scrollTop = log.scrollHeight;
        return element;
    }

    narsSubmit() {
        const input = document.getElementById('nars-input');
        const question = input.value.trim();
        if (question && this.narsAsk(question)) input.value = '';
    }

    narsAsk(question) {
        if (this.narsBusy) {
            this.toast('NARS is still answering the last question.');
            return false;
        }
        this.toggleNars(true);
        this.narsSend(question);
        return true;
    }

    async narsSend(question) {
        this.narsBusy = true;
        const send = document.getElementById('nars-send');
        send.disabled = true;
        this.narsAppend(`<p>${esc(question)}</p>`, 'nars-user');
        const waiting = this.narsAppend('<p class="muted"><i class="fa-solid fa-circle-notch fa-spin" aria-hidden="true"></i> Checking stored data...</p>', 'nars-bot');
        try {
            const result = await postJson('/api/nars/ask', {
                question, context: this.narsContext(), history: this.narsHistory.slice(-NARS_HISTORY_MESSAGES),
                analyst: document.getElementById('analyst-name').value.trim(),
            });
            this.narsHistory.push({ role: 'user', content: question }, { role: 'assistant', content: result.answer });
            const firstIncident = result.citations.find(item => item.kind === 'incident' && result.answer.includes(item.label));
            if (firstIncident) this.narsIncident = firstIncident.id;
            waiting.innerHTML = this.narsAnswer(result);
            this.renderNarsSuggestions(result.suggestions);
        } catch (e) {
            waiting.innerHTML = `<div class="notice notice-error">${esc(e.message)}</div>`;
        } finally {
            this.narsBusy = false;
            send.disabled = false;
            const log = document.getElementById('nars-log');
            log.scrollTop = Math.max(0, waiting.offsetTop - log.offsetTop - 8);
        }
    }

    narsAnswer(result) {
        const open = { incident: 'open-incident', alert: 'open-alert', dataset: 'nars-open-dataset' };
        const links = result.citations.map(item => `<button class="nars-source" data-action="${open[item.kind]}" data-id="${esc(item.id)}">${esc(item.label)}</button>`).join('');
        const read = [...new Set(result.read.map(item => item.tool.replace(/_/g, ' ')))];
        return `${result.note ? `<div class="notice">${esc(result.note)}</div>` : ''}
            <div class="nars-text">${narsFormat(result.answer)}</div>
            ${links ? `<div class="nars-sources">${links}</div>` : ''}
            <p class="nars-trace">${result.model ? `Written by ${esc(result.model)}.` : 'Built directly from stored data.'}
                ${read.length ? `Read: ${esc(read.join(', '))}.` : 'No stored data was read for this answer.'}</p>`;
    }

    clearNars() {
        this.narsHistory = [];
        this.narsIncident = null;
        document.getElementById('nars-log').innerHTML = '';
        this.renderNarsSuggestions();
    }

    openTile(key) {
        const tile = TILES.find(item => item.key === key);
        const form = document.getElementById(FILTER_FORMS[tile.view]);
        if (form) {
            form.reset();
            Object.entries(tile.filter || {}).forEach(([name, value]) => { form.elements[name].value = value; });
        }
        this.navigate(tile.view);
    }
}

const ACTIONS = {
    nav(target) { this.navigate(target.dataset.view); },
    'open-tile'(target) { this.openTile(target.dataset.key); },
    'toggle-table'(target) {
        const name = target.dataset.chart;
        const table = document.getElementById(`table-${name}`);
        const box = document.getElementById(`chart-${name}`).parentElement;
        const showTable = table.hidden;
        const hasData = document.getElementById(`empty-${name}`).hidden;
        table.hidden = !showTable || !hasData;
        box.hidden = showTable || !hasData;
        target.textContent = showTable ? 'View chart' : 'View table';
    },
    'toggle-pause'() {
        this.paused = !this.paused;
        if (!this.paused) {
            this.missedWhilePaused = 0;
            this.loadEvents();
        }
        this.updatePauseButton();
    },
    'events-older'() { this.loadOlderEvents(); },
    'open-event'(target) { this.openEventDrawer(target.dataset.id); },
    'open-alert'(target) { this.openAlertDrawer(target.dataset.id); },
    'open-incident'(target, event) {
        event.stopPropagation();
        this.closeDrawer();
        this.navigate('investigations', target.dataset.id);
    },
    'close-drawer'() { this.closeDrawer(); },
    'filter-rule'(target) {
        const form = document.getElementById('alerts-filter');
        form.reset();
        form.elements.rule_id.value = target.dataset.rule;
        this.loadAlerts();
        form.scrollIntoView({ block: 'nearest' });
    },
    'set-status'(target) { this.setStatus(target); },
    decide(target) { this.decide(target); },
    execute(target) { this.execute(target); },
    'undo-real'(target) { this.undoReal(target); },
    'copy-text'(target) {
        navigator.clipboard.writeText(target.dataset.text)
            .then(() => this.toast('Copied. Read it before you run it.'), () => this.toast('Could not copy. Select the text and copy it by hand.', true));
    },
    'run-scenario'(target) { this.runScenario(target); },
    'sim-control'(target) { this.controlRun(target); },
    'view-run'(target) { this.viewRun(target.dataset.id); },
    'clear-sim-result'() { document.getElementById('sim-result').innerHTML = ''; },
    'open-portal'() { document.getElementById('solution-portal').scrollIntoView({ block: 'start' }); },
    'open-scenario-solution'(target) { this.openSolutionFor(target.dataset.id); },
    'portal-run'(target) {
        this.runScenario(target);
        document.getElementById('sim-controls').scrollIntoView({ block: 'start' });
    },
    'validate-dataset'() { this.validateDataset(); },
    'reanalyze-dataset'() { this.submitUpload(null, true); },
    'view-dataset'(target) { this.viewDataset(target.dataset.id); },
    'read-notifications'() { this.readNotifications(); },
    'view-report'(target) { this.viewReport(target.dataset.id); },
    'new-report'(target) { this.newReport(target); },
    'open-simulated-stream'() {
        this.streamOrigin = 'simulation';
        this.navigate('events');
    },
    'open-technique'(target) { this.openTechnique(target.dataset.id, target.dataset.tactic); },
    'remove-feed'(target) { this.removeFeed(target); },
    'test-feed'(target) { this.testFeed(target); },
    'view-feed-analysis'(target) { this.viewFeedAnalysis(target.dataset.source); },
    'toggle-smtp-settings'() { this.toggleSmtpSettings(); },
    'email-test'(target) { this.sendTestEmail(target); },
    'approvals-show'(target) {
        document.getElementById('approvals-filter').elements.status.value = target.dataset.status;
        this.loadApprovals();
    },
    logout() { this.logout(); },
    'nars-toggle'() { this.toggleNars(); },
    'nars-clear'() { this.clearNars(); },
    'nars-ask'(target) { this.narsAsk(target.dataset.question); },
    'nars-open-dataset'(target) {
        this.navigate('upload');
        this.viewDataset(target.dataset.id);
    },
};

document.addEventListener('DOMContentLoaded', () => { window.dashboard = new ALLSAFEDashboard(); });
