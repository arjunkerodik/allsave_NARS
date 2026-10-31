/** The front page. Every number on it comes from the same APIs as the dashboard. */

// Old links such as /#upload pointed at the dashboard, which used to be here
function followOldLink() {
    if (window.location.hash.length > 1 && !document.getElementById(window.location.hash.slice(1))) {
        window.location.replace(`/dashboard${window.location.hash}`);
    }
}
followOldLink();
window.addEventListener('hashchange', followOldLink);

async function getJson(path) {
    const response = await fetch(path);
    if (response.status === 401) window.location.assign('/login');
    if (!response.ok) throw new Error(`${path} failed`);
    return response.json();
}

const landingNumber = value => Number(value || 0).toLocaleString();

async function loadLanding() {
    const flow = new LiveFlow(document.getElementById('landing-flow'), { height: 340, compact: true });
    const note = document.getElementById('landing-flow-note');
    const showRate = () => { note.textContent = `${landingNumber(flow.eventsLastMinute())} logs arrived in the last minute`; };
    flow.minutes = 0;
    flow.refresh().catch(() => { note.textContent = 'The flow could not be loaded.'; });
    showRate();
    setInterval(showRate, 2000);
    const socket = io({ transports: ['polling', 'websocket'] });
    socket.on('new_log', log => flow.addEvent(log));

    const [stats, matrix, nars, parameters] = await Promise.all([getJson('/api/stats'), getJson('/api/attack-matrix'), getJson('/api/nars/status'), getJson('/api/threat-parameters')]);
    document.getElementById('landing-tiles').innerHTML = [
        ['Logs processed', stats.total], ['Alerts raised', stats.alerts], ['Open incidents', stats.incidents_open], ['Waiting for SOC approval', stats.responses_pending],
    ].map(([label, value]) => `<div class="tile"><span class="tile-label">${flowEsc(label)}</span><span class="tile-value">${landingNumber(value)}</span></div>`).join('');
    const totals = matrix.totals;
    document.getElementById('landing-coverage').textContent = `${totals.rules} rules cover ${totals.techniques} ATT&CK techniques in ${totals.tactics_with_rules} of ${totals.tactics} tactics. A synthetic scenario tests ${totals.techniques_tested} of those techniques. That shows the rules work as designed, not how they do on real attacks.`;
    document.getElementById('landing-nars').textContent = nars.note;
    const wanted = ['IOA-001', 'IOA-003', 'IOA-009', 'IOA-007'];
    const rules = wanted.map(id => parameters.rules.find(rule => rule.id === id)).filter(Boolean);
    document.getElementById('landing-rules').innerHTML = `<div class="table-wrap"><table><thead><tr><th>Threat</th><th>Measured</th><th>Limit</th><th>Window</th></tr></thead><tbody>
        ${rules.map(rule => `<tr><td>${flowEsc(rule.name)}</td><td>${flowEsc(rule.measure)}</td><td class="nowrap">${flowEsc(rule.threshold_text)}</td><td class="nowrap">${flowEsc(rule.window_seconds)} s</td></tr>`).join('')}
    </tbody></table></div>`;
}

loadLanding().catch(error => {
    document.getElementById('landing-tiles').innerHTML = `<div class="notice notice-error">Could not load current data: ${flowEsc(error.message)}</div>`;
});
