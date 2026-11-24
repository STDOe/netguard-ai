export const byId = id => document.getElementById(id);
export const displayDate = time => new Date(time).toLocaleString();
export const pathId = value => encodeURIComponent(value);

export function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (cls) node.className = cls;
  return node;
}

export function badge(status) {
  const node = el('span', status.replaceAll('_', ' '), 'badge');
  node.dataset.status = status;
  return node;
}

export function notice(message, error = false) {
  const node = byId('status');
  node.hidden = !message;
  node.textContent = message;
  node.classList.toggle('error', error);
}

export async function api(path, {method = 'GET', data} = {}) {
  const headers = {'Accept': 'application/json'};
  if (method !== 'GET') headers['X-CSRF-Token'] = document.querySelector('meta[name=csrf-token]').content;
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, {method, headers, body: data === undefined ? undefined : JSON.stringify(data)});
  if (!response.ok) {
    if (response.status === 401) {
      location.reload();
      throw new Error('Sign in again to continue.');
    }
    const result = await response.json().catch(() => ({}));
    const code = result.error?.code ?? `HTTP ${response.status}`;
    const messages = {
      invalid_request: 'Check the input fields and submit again.',
      forbidden: 'Your role cannot perform this action.',
      plan_hash_mismatch: 'The exact plan has changed. Refresh before deciding.',
      approval_expired: 'The approval window has closed.',
      workflow_busy: 'This task is busy. Refresh in a few seconds.',
      task_not_awaiting_input: 'This task is no longer waiting for input.'
    };
    throw new Error(messages[code] ?? `Request failed (${code}).`);
  }
  return response.status === 204 ? undefined : response.json();
}

export function click(button, run) {
  button?.addEventListener('click', () => action(run, button));
}

export async function action(run, control) {
  if (control?.disabled) return;
  if (control) control.disabled = true;
  notice('Loading…');
  try {
    await run();
    notice('');
  } catch (error) {
    notice(error instanceof Error ? error.message : 'Request failed.', true);
  } finally {
    if (control) control.disabled = false;
  }
}

export function list(rows, none) {
  const result = el('ul', undefined, 'data-list');
  if (!rows.length) result.append(el('li', none, 'muted'));
  for (const row of rows) {
    const item = el('li');
    item.append(...row);
    result.append(item);
  }
  return result;
}

export function label(title, detail) {
  const result = el('span');
  result.append(el('strong', title), el('small', detail));
  return result;
}

export function disclosure(title, content) {
  const result = el('details');
  result.append(el('summary', title), el('pre', content));
  return result;
}

export function option(value, text) {
  const result = el('option', text);
  result.value = value;
  return result;
}
