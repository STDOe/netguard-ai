import {action, api, badge, byId, click, disclosure, displayDate, el, label, list, notice, option, pathId} from './common.js';
import {mapPanel} from './topology.js';
import {workflows} from './workflows.js';

const shell = document.querySelector('.app-shell');
const page = shell.dataset.page;
const picker = byId('network');
const map = byId('network-map') ? mapPanel(refreshNetwork) : null;
const workflow = byId('task-list') ? workflows(page, shell) : null;

function score(report) {
  if (report.evidence_status === 'corrupt') return 'Report evidence is corrupt · Score unavailable';
  return `${report.score.value === null ? 'Score unavailable' : `${report.score.value} / 100`} · ${report.score.coverage}% coverage`;
}

function showReport(report) {
  const section = byId('audit-detail');
  section.hidden = false;
  section.replaceChildren(el('div', undefined, 'panel-heading'));
  section.firstChild.append(el('h2', `Revision ${report.revision} · ${report.current ? 'Current' : 'Historical'}`),
    badge(report.current ? 'current' : 'stale'));
  section.append(el('p', `${score(report)} · Policy ${report.policy_version ?? 'unknown'} · ${displayDate(report.created_at)}`, 'section-note'));
  section.append(list(report.findings.map(finding => [
    label(finding.check_id.replaceAll('_',' '), `${finding.severity} · ${finding.reason}`),
    badge(finding.status),
    disclosure('Evidence and limitations', [...finding.evidence, finding.limitations].join('\n'))
  ]), 'No checks.'));
}
async function reports() {
  const rows = await api(`/api/v1/networks/${pathId(picker.value)}/audits`);
  if (page === 'overview') {
    byId('audit-overview').textContent = rows.length
      ? `${score(rows[0])} · Revision ${rows[0].revision} · ${rows[0].current ? 'Current report' : 'Historical report'}`
      : 'No saved audit for this network.';
    return;
  }
  byId('audit-list').replaceChildren(list(rows.map(report => {
    const button = el('button', 'Show findings');
    click(button, async () => showReport(await api(`/api/v1/networks/${pathId(report.network_id)}/audits/${pathId(report.id)}`)));
    return [label(`Revision ${report.revision} · ${score(report)}`, displayDate(report.created_at)),
      badge(report.current ? 'current' : 'stale'), button];
  }), 'No saved audit reports.'));
}
async function refreshNetwork() {
  if (!picker.value) return;
  if (map) {
    const snapshot = await map(picker.value);
    if (page === 'overview') {
      byId('device-count').textContent = snapshot.network.devices.length;
      byId('zone-count').textContent = snapshot.network.zones.length;
      byId('revision-count').textContent = snapshot.revision;
      if (shell.dataset.canApprove === 'true') {
        const {length} = await api('/api/v1/approvals');
        byId('approval-count').textContent = length === 50 ? '50+' : length;
      } else byId('approval-count').textContent = 'Restricted';
    }
  }
  if (page === 'audit') {
    byId('audit-detail').hidden = true;
    byId('snapshot-warning').hidden = picker.selectedOptions[0]?.dataset.integrity !== 'failed';
  }
  if (page === 'audit' || page === 'overview') await reports();
  await workflow?.network(picker.value);
}

async function events() {
  const events = await api('/api/v1/honeypot/events');
  byId('honeypot-list').replaceChildren(list(events.map(event => [
    label(`${event.service.toUpperCase()} · ${event.sensor}`, `${event.source_ip} → ${event.destination_ip}:${event.destination_port}`),
    badge(event.demo ? 'fixture / demo' : 'sensor observation'),
    badge(event.correlation),
    label(displayDate(event.occurred_at), event.inventory_device ?
      `Destination device ${event.inventory_device} · revision ${event.inventory_revision}` : 'Unverified inventory relation')
  ]), 'No authenticated sensor events have been received.'));
}

click(byId('logout'), async () => {
  await api('/session', {method:'DELETE'});
  location.assign('/');
});
click(byId('run-audit'), async () => {
  if (!picker.value) throw new Error('Select a network first.');
  const result = await api(`/api/v1/networks/${pathId(picker.value)}/audits`, {method: 'POST'});
  await reports();
  showReport(result);
});
click(byId('refresh-events'), events);
picker?.addEventListener('change', () => action(refreshNetwork, picker));
document.body.addEventListener('htmx:responseError', () => notice('Recent activity could not load.', true));
document.body.addEventListener('htmx:sendError', () => notice('Unable to reach NetGuard.', true));

action(async () => {
  if (picker) {
    const networks = await api(page === 'audit' ? '/api/v1/audit/networks' : '/api/v1/networks');
    picker.replaceChildren(...networks.map(net => {
      const item = option(net.id, net.name ?? net.id);
      if (net.snapshot_integrity) item.dataset.integrity = net.snapshot_integrity;
      return item;
    }));
    if (!networks.length) picker.replaceChildren(option('', 'No mock network available'));
    else await refreshNetwork();
  }
  if (page === 'honeypot') await events();
  await workflow?.load();
});
// Reload the saved revision only while the topology is visible.
if (page === 'topology') {
  setInterval(() => {
    if (!document.hidden && picker.value) map(picker.value).catch(() => notice('Unable to refresh the stored revision.', true));
  }, 15000);
}
