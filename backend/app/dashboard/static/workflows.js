import {action, api, badge, byId, click, disclosure, displayDate, el, label, list, option, pathId} from './common.js';
import {generatedMermaid, mountGraph} from './topology.js';

const empty = 'No workflow tasks for this role.';
const validId = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i;

export function workflows(page, shell) {
  let current;
  let networkId;
  let graph;
  const canApprove = shell.dataset.canApprove === 'true';
  const taskList = byId('task-list');
  const detail = byId('task-detail');
  const input = byId('send-input');
  const inbox = byId('inbox');

  async function renderTasks() {
    const tasks = await api('/api/v1/tasks');
    const rows = tasks.filter(task => page !== 'greenfield' || task.kind === 'greenfield')
      .map(task => {
        const button = el('button', 'Open');
        if (detail) click(button, () => open(task.id));
        else {
          const link = el('a', 'Open');
          link.href = `/dashboard/${task.kind === 'greenfield' ? 'greenfield' : 'workspace'}?task=${pathId(task.id)}`;
          return [label(task.kind, task.id), badge(task.status), link];
        }
        return [label(task.kind, task.id), badge(task.status), button];
      });
    taskList.replaceChildren(list(rows, empty));
  }

  async function approvals() {
    if (!inbox || !canApprove) return;
    const pending = await api('/api/v1/approvals');
    inbox.replaceChildren(list(pending.map(task => {
      const button = el('button', 'Review plan');
      click(button, () => open(task.id));
      return [label(`Mock revision ${task.plan.base_revision}`, task.plan.plan_hash), badge(task.status), button];
    }), 'No plans awaiting approval.'));
  }

  async function open(id) {
    if (!validId.test(id)) throw new Error('Enter a valid task UUID.');
    await show(await api(`/api/v1/tasks/${id}`));
  }

  async function show(task) {
    graph?.destroy();
    graph = undefined;
    current = task;
    byId('task-id').value = task.id;
    if (input) input.hidden = task.status !== 'awaiting_input' || task.kind !== 'greenfield';
    const title = el('div', undefined, 'flex gap-2 items-center');
    title.append(el('h3', task.kind === 'greenfield' ? 'Greenfield design' : 'Brownfield change'), badge(task.status));
    detail.replaceChildren(title);
    if (task.code) detail.append(el('p', task.code.replaceAll('_', ' '), 'muted'));
    if (task.missing.length) detail.append(el('p', `Required or inconsistent: ${task.missing.join(', ').replaceAll('_', ' ')}`));
    const base = `/api/v1/tasks/${task.id}`;
    if (task.plan) {
      const plan = task.plan;
      detail.append(el('p', `Target ${plan.diff.target_id} · Revision ${plan.base_revision} · Risk ${plan.risk} · Expires ${displayDate(plan.expires_at)}`),
        el('p', `SHA-256 ${plan.plan_hash}`, 'muted section-note'),
        disclosure('Plan and diff', JSON.stringify(plan, null, 2)));
      if (canApprove && task.status === 'awaiting_approval') {
        const decisions = el('div', undefined, 'flex gap-2');
        for (const decision of ['approve','reject']) {
          const button = el('button', decision === 'approve' ? 'Approve mock change' : 'Reject');
          click(button, async () => {
            await show(await api(`${base}/plan/${plan.plan_id}/decision`, {method:'POST', data: {decision, plan_hash:plan.plan_hash}}));
            await Promise.all([approvals(), renderTasks()]);
          });
          decisions.append(button);
        }
        detail.append(decisions);
      }
    }
    if (task.approval) detail.append(disclosure('Recorded decision', JSON.stringify(task.approval, null, 2)));
    if (task.result) detail.append(disclosure('Execution evidence', JSON.stringify(task.result, null, 2)));
    if (!task.approval && ['awaiting_input','awaiting_approval'].includes(task.status)) {
      const cancel = el('button', 'Cancel task');
      click(cancel, async () => {
        await show(await api(`${base}/cancel`, {method:'POST'}));
        await Promise.all([approvals(), renderTasks()]);
      });
      detail.append(cancel);
    }
    for (const artifact of task.artifacts) {
      const panel = disclosure(artifact.name, artifact.content);
      detail.append(panel);
      if (artifact.name === 'topology.mmd') {
        const elements = generatedMermaid(artifact.content);
        if (elements) {
          const canvas = el('div', undefined, 'map');
          canvas.setAttribute('aria-label', 'Generated Greenfield diagram');
          detail.append(canvas);
          graph = mountGraph(canvas, elements);
        }
      }
    }
    const events = await api(`${base}/events`);
    if (current.id !== task.id) return;
    detail.append(disclosure('Agent steps', events.slice(-50).map(event =>
      `${displayDate(event.at)}  ${event.step}${event.code ? ` · ${event.code}` : ''}`).join('\n')));
  }

  function submit(form, run) {
    form?.addEventListener('submit', event => {
      event.preventDefault();
      action(() => run(event.submitter), event.submitter);
    });
  }

  submit(byId('open-task'), () => open(byId('task-id').value.trim()));
  click(byId('refresh-inbox'), approvals);
  const greenfield = byId('greenfield');
  submit(greenfield, async button => {
    const fields = new FormData(greenfield);
    const requirements = {};
    for (const field of greenfield.querySelectorAll('input:not([type=checkbox]), select')) {
      if (field.value) requirements[field.name] = field.type === 'number' ? Number(field.value) : field.value.trim();
    }
    if (button?.value !== 'input' || fields.has('vendors') && fields.get('vendors').trim()) {
      requirements.vendors = String(fields.get('vendors')).split(',').map(value => value.trim()).filter(Boolean);
    }
    for (const key of ['security','services']) {
      const values = fields.getAll(key);
      if (button?.value !== 'input' || values.length) requirements[key] = values;
    }
    const task = button?.value === 'input'
      ? await api(`/api/v1/tasks/${current.id}/input`, {method: 'POST', data: requirements})
      : await api('/api/v1/tasks', {method:'POST', data: {kind: 'greenfield', idempotency_key: crypto.randomUUID(), requirements}});
    await show(task);
    await renderTasks();
  });
  submit(byId('brownfield'), async () => {
    if (!networkId) throw new Error('Select a network first.');
    const custom = byId('custom-goal').value.trim();
    let goal;
    try {
      goal = custom ? JSON.parse(custom) : {kind:'find_static_route', device_id: byId('route-device').value, destination: byId('route-subnet').value};
    } catch {
      throw new Error('Typed goal must be valid JSON.');
    }
    await show(await api('/api/v1/tasks', {method:'POST', data: {kind:'brownfield', network_id:networkId,
      dry_run: shell.dataset.canChange !== 'true' || byId('dry-run').checked, idempotency_key:crypto.randomUUID(), goal}}));
    await renderTasks();
  });

  return {
    async load() {
      await Promise.all([renderTasks(), approvals()]);
      const target = new URLSearchParams(location.search).get('task');
      if (target && detail) await open(target);
    },
    async network(id) {
      if (page !== 'workspace') return;
      const {network} = await api(`/api/v1/networks/${pathId(id)}/topology`);
      networkId = id;
      byId('route-device').replaceChildren(...network.devices.map(item => option(item.id, item.name)));
      byId('route-subnet').replaceChildren(...network.subnets.filter(item => item.vlan_id).map(item => option(item.prefix, `${item.name} · ${item.prefix}`)));
    }
  };
}
