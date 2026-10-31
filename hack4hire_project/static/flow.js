/**
 * Live data flow: log type, then verdict, then outcome. Band sizes are counts from /api/flow, and each
 * moving dot is one real log that arrived on the socket. When no logs arrive, nothing moves.
 */
const FLOW_COLORS = { normal: '#3987e5', suspicious: '#fab219', threat: '#d03b3b' };
const FLOW_LABELS = { normal: 'No detection', suspicious: 'Suspicious', threat: 'Threat evidence' };
const FLOW_NODE_WIDTH = 14;
const FLOW_CAPTION_HEIGHT = 24;
const FLOW_GAP = 12;
const FLOW_MIN_NODE = 6;
const FLOW_TRAVEL_MS = 2600;
const FLOW_MAX_DOTS = 400;
const FLOW_REFRESH_MS = 5000;
const flowLogs = count => `${Number(count).toLocaleString()} ${Number(count) === 1 ? 'log' : 'logs'}`;

function flowEsc(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

class LiveFlow {
    constructor(root, { height = 460, compact = false } = {}) {
        this.root = root;
        this.baseHeight = height;
        this.compact = compact;
        this.minutes = 60;
        this.origin = '';
        this.data = null;
        this.dots = [];
        this.routes = {};
        this.arrivals = [];
        this.running = false;
        this.reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        root.innerHTML = `<div class="flow-stage"><svg class="flow-svg" role="img" aria-label="Flow of logs from log type, to verdict, to outcome"></svg><canvas class="flow-dots" aria-hidden="true"></canvas><div class="flow-tip" hidden></div></div>
            <p class="empty flow-empty" hidden>No logs in this time range.</p>`;
        this.stage = root.querySelector('.flow-stage');
        this.svg = root.querySelector('svg');
        this.canvas = root.querySelector('canvas');
        this.tip = root.querySelector('.flow-tip');
        this.emptyNote = root.querySelector('.flow-empty');
        this.stage.addEventListener('mousemove', event => this.moveTip(event));
        this.stage.addEventListener('mouseleave', () => { this.tip.hidden = true; });
        if (window.ResizeObserver) new ResizeObserver(() => { if (this.data) this.draw(); }).observe(root);
    }

    async refresh() {
        const params = new URLSearchParams({ minutes: this.minutes });
        if (this.origin) params.set('origin', this.origin);
        const token = (this.token = (this.token || 0) + 1);
        const response = await fetch(`/api/flow?${params}`);
        if (!response.ok) throw new Error(`Could not load the flow (${response.status})`);
        const data = await response.json();
        if (token !== this.token) return;
        this.data = data;
        this.lastRefresh = Date.now();
        this.draw();
        if (this.onData) this.onData(data);
    }

    setFilter({ minutes, origin }) {
        if (minutes !== undefined) this.minutes = minutes;
        if (origin !== undefined) this.origin = origin;
        this.dots = [];
        return this.refresh();
    }

    visible() {
        return this.root.offsetParent !== null && !document.hidden;
    }

    // Square-root widths keep a few threat logs visible beside thousands of normal ones. Labels and tooltips give true counts.
    layout() {
        const width = Math.max(this.root.clientWidth, this.compact ? 560 : 680);
        // Enough room for one readable label per log type, under the column captions
        const height = Math.max(this.baseHeight, FLOW_CAPTION_HEIGHT + this.data.nodes.filter(node => node.column === 0).length * 34);
        const left = this.compact ? 96 : 120;
        const right = this.compact ? 118 : 150;
        const xs = [left, (left + width - right - FLOW_NODE_WIDTH) / 2, width - right - FLOW_NODE_WIDTH];
        const nodes = this.data.nodes.map(node => ({ ...node, thickIn: 0, thickOut: 0, logs: Math.max(node.logs_in || 0, node.logs_out || 0) }));
        const byId = Object.fromEntries(nodes.map(node => [node.id, node]));
        const links = this.data.links.map(link => ({ ...link, thick: Math.sqrt(link.logs), from: byId[link.source], to: byId[link.target] }));
        links.forEach(link => { link.from.thickOut += link.thick; link.to.thickIn += link.thick; });
        const columns = [0, 1, 2].map(index => nodes.filter(node => node.column === index));
        const order = { normal: 0, suspicious: 1, threat: 2, stored: 0, alert: 1, incident: 2 };
        columns[0].sort((a, b) => b.logs - a.logs);
        columns[1].sort((a, b) => order[a.key] - order[b.key]);
        columns[2].sort((a, b) => order[a.key] - order[b.key]);
        const usable = column => height - FLOW_CAPTION_HEIGHT - FLOW_GAP * (column.length - 1) - column.length * 2;
        const raw = column => column.reduce((total, node) => total + Math.max(node.thickIn, node.thickOut), 0);
        const scale = Math.min(...columns.filter(column => column.length).map(column => usable(column) / Math.max(raw(column), 1)));
        columns.forEach((column, index) => {
            const total = column.reduce((sum, node) => sum + Math.max(Math.max(node.thickIn, node.thickOut) * scale, FLOW_MIN_NODE), 0) + FLOW_GAP * (column.length - 1);
            let y = FLOW_CAPTION_HEIGHT + Math.max((height - FLOW_CAPTION_HEIGHT - total) / 2, 0);
            column.forEach(node => {
                node.x = xs[index];
                node.y = y;
                node.h = Math.max(Math.max(node.thickIn, node.thickOut) * scale, FLOW_MIN_NODE);
                node.nextIn = y;
                node.nextOut = y;
                y += node.h + FLOW_GAP;
            });
        });
        const position = { [columns[1][0]?.id]: 0 };
        columns.flat().forEach((node, index) => { position[node.id] = index; });
        [...links].sort((a, b) => position[a.to.id] - position[b.to.id] || position[a.from.id] - position[b.from.id]).forEach(link => {
            link.width = Math.max(link.thick * scale, 1.5);
            link.y0 = link.from.nextOut + link.width / 2;
            link.from.nextOut += link.thick * scale;
        });
        [...links].sort((a, b) => position[a.from.id] - position[b.from.id] || position[a.to.id] - position[b.to.id]).forEach(link => {
            link.y1 = link.to.nextIn + link.width / 2;
            link.to.nextIn += link.thick * scale;
            link.x0 = link.from.x + FLOW_NODE_WIDTH;
            link.x1 = link.to.x;
        });
        return { width, height, nodes, links, xs };
    }

    draw() {
        if (!this.data.total) {
            this.stage.hidden = true;
            this.emptyNote.hidden = false;
            this.routes = {};
            return;
        }
        this.stage.hidden = false;
        this.emptyNote.hidden = true;
        const { width, height, nodes, links, xs } = this.layout();
        this.size = { width, height };
        this.stage.style.width = `${width}px`;
        this.svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        this.svg.setAttribute('width', width);
        this.svg.setAttribute('height', height);
        const ratio = window.devicePixelRatio || 1;
        this.canvas.width = width * ratio;
        this.canvas.height = height * ratio;
        this.canvas.style.width = `${width}px`;
        this.canvas.style.height = `${height}px`;

        const bands = links.map(link => {
            const middle = (link.x0 + link.x1) / 2;
            const path = `M${link.x0} ${link.y0} C${middle} ${link.y0} ${middle} ${link.y1} ${link.x1} ${link.y1}`;
            const text = `${link.from.label} to ${link.to.label}: ${flowLogs(link.logs)}`;
            return `<path class="flow-band" d="${path}" stroke="${FLOW_COLORS[link.verdict]}" stroke-width="${link.width}" data-tip="${flowEsc(text)}"><title>${flowEsc(text)}</title></path>`;
        }).join('');
        const bars = nodes.map(node => {
            const color = node.column === 1 ? FLOW_COLORS[node.key] : '#4a5f8c';
            const text = `${node.label}: ${flowLogs(node.logs)}`;
            const labelX = node.column === 0 ? node.x - 8 : node.x + FLOW_NODE_WIDTH + 8;
            const anchor = node.column === 0 ? 'end' : 'start';
            const middleY = node.y + node.h / 2;
            const count = node.column === 0 ? '' : `<text class="flow-count" x="${labelX}" y="${middleY + 15}" text-anchor="${anchor}">${flowLogs(node.logs)}</text>`;
            return `<g class="flow-node" data-tip="${flowEsc(text)}"><title>${flowEsc(text)}</title>
                <rect x="${node.x}" y="${node.y}" width="${FLOW_NODE_WIDTH}" height="${node.h}" rx="4" fill="${color}"></rect>
                <text class="flow-label" x="${labelX}" y="${middleY + (node.column === 0 ? 4 : 0)}" text-anchor="${anchor}">${flowEsc(node.label)}</text>${count}</g>`;
        }).join('');
        const captions = `<text class="flow-caption" x="${xs[0] + FLOW_NODE_WIDTH}" y="12" text-anchor="end">Log type</text>
            <text class="flow-caption" x="${xs[1]}" y="12">Verdict</text>
            <text class="flow-caption" x="${xs[2]}" y="12">Outcome</text>`;
        this.svg.innerHTML = captions + bands + bars;

        this.routes = {};
        links.forEach(link => { this.routes[`${link.source}|${link.target}`] = link; });
        this.nodeIds = new Set(nodes.map(node => node.id));
    }

    moveTip(event) {
        const holder = event.target.closest && event.target.closest('[data-tip]');
        if (!holder) {
            this.tip.hidden = true;
            return;
        }
        const box = this.stage.getBoundingClientRect();
        this.tip.textContent = holder.getAttribute('data-tip');
        this.tip.hidden = false;
        this.tip.style.left = `${Math.min(event.clientX - box.left + 12, box.width - 260)}px`;
        this.tip.style.top = `${event.clientY - box.top + 12}px`;
    }

    // Decides the same way as the server: the strongest detection the log supports
    classify(log) {
        const detections = log.detections || [];
        const minimum = this.data ? this.data.confirmed_min_confidence : 70;
        const verdict = detections.some(d => ['IOA', 'IOC'].includes(d.detection_type) && d.confidence >= minimum && d.severity !== 'LOW')
            ? 'threat' : detections.length ? 'suspicious' : 'normal';
        const outcome = verdict === 'normal' ? 'stored' : detections.some(d => d.incident_id) ? 'incident' : 'alert';
        return { category: log.event_category || log.source || 'other', verdict, outcome };
    }

    addEvent(log) {
        if (this.origin && log.origin !== this.origin) return;
        this.arrivals.push(Date.now());
        if (!this.data) return;
        const due = Date.now() - (this.lastRefresh || 0) > FLOW_REFRESH_MS;
        if (due && this.visible()) this.refresh().catch(() => {});
        if (this.reduced || !this.visible() || this.dots.length >= FLOW_MAX_DOTS) return;
        const { category, verdict, outcome } = this.classify(log);
        const first = this.routes[`type:${category}|verdict:${verdict}`];
        const second = this.routes[`verdict:${verdict}|outcome:${outcome}`];
        if (!first || !second) return;
        const spread = () => (Math.random() - 0.5) * 0.8;
        this.dots.push({ first, second, verdict, born: performance.now() + Math.random() * 500, offsetA: spread() * first.width, offsetB: spread() * second.width });
        if (!this.running) {
            this.running = true;
            requestAnimationFrame(time => this.tick(time));
        }
    }

    eventsLastMinute() {
        const cutoff = Date.now() - 60000;
        this.arrivals = this.arrivals.filter(time => time >= cutoff);
        return this.arrivals.length;
    }

    static curve(link, t, offset) {
        const middle = (link.x0 + link.x1) / 2;
        const u = 1 - t;
        const y0 = link.y0 + offset;
        const y1 = link.y1 + offset;
        return {
            x: u * u * u * link.x0 + 3 * u * u * t * middle + 3 * u * t * t * middle + t * t * t * link.x1,
            y: u * u * u * y0 + 3 * u * u * t * y0 + 3 * u * t * t * y1 + t * t * t * y1,
        };
    }

    tick(time) {
        const context = this.canvas.getContext('2d');
        const ratio = window.devicePixelRatio || 1;
        context.setTransform(ratio, 0, 0, ratio, 0, 0);
        context.clearRect(0, 0, this.size ? this.size.width : 0, this.size ? this.size.height : 0);
        this.dots = this.dots.filter(dot => time - dot.born < FLOW_TRAVEL_MS);
        this.dots.forEach(dot => {
            const progress = Math.max(time - dot.born, 0) / FLOW_TRAVEL_MS;
            const onFirst = progress < 0.5;
            const point = LiveFlow.curve(onFirst ? dot.first : dot.second, onFirst ? progress * 2 : (progress - 0.5) * 2, onFirst ? dot.offsetA : dot.offsetB);
            context.beginPath();
            context.arc(point.x, point.y, dot.verdict === 'normal' ? 1.8 : 3, 0, Math.PI * 2);
            context.fillStyle = dot.verdict === 'normal' ? '#a9cdf7' : FLOW_COLORS[dot.verdict];
            context.fill();
        });
        if (this.dots.length) {
            requestAnimationFrame(next => this.tick(next));
        } else {
            this.running = false;
        }
    }

    tableHtml() {
        if (!this.data) return '';
        const labels = Object.fromEntries(this.data.nodes.map(node => [node.id, node.label]));
        return `<table><thead><tr><th>From</th><th>To</th><th>Verdict</th><th class="num">Logs</th></tr></thead><tbody>
            ${this.data.links.map(link => `<tr><td>${flowEsc(labels[link.source])}</td><td>${flowEsc(labels[link.target])}</td><td>${flowEsc(FLOW_LABELS[link.verdict])}</td><td class="num">${Number(link.logs).toLocaleString()}</td></tr>`).join('')}
        </tbody></table>`;
    }
}
