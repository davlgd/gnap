'use strict';
const error = document.querySelector('#error');
function render(data) {
  if (data.error) { error.textContent = data.error; return; }
  error.textContent = '';
  document.querySelector('#state').textContent = data.state || 'unknown';
  document.querySelector('#requested-rights').textContent = (data.requested_rights || []).join(', ') || 'Start a request to choose rights.';
  document.querySelector('#current-rights').textContent = (data.rights || []).join(', ') || 'No live token.';
  const events = document.querySelector('#events'); events.replaceChildren();
  for (const event of data.events || []) { const item = document.createElement('li'); item.textContent = event; events.append(item); }
  document.querySelector('#resource').textContent = data.folder ? JSON.stringify(data.folder, null, 2) : 'No resource has been read with the current token.';
  const wait = data.continuation_wait_seconds || 0;
  const continuable = data.continuation_open && ['ready', 'approved', 'revoked'].includes(data.state);
  document.querySelector('[data-action="continue"]').textContent = continuable && wait > 0 ? `Continue in ${wait}s` : data.state === 'approved' ? 'Poll without reissuing tokens' : 'Continue after callback';
  const changeable = ['approved', 'revoked'].includes(data.state) && data.continuation_open && wait === 0;
  const enabled = {start: true, approve: data.state === 'pending', deny: data.state === 'pending', continue: continuable && wait === 0, read: data.token_present, 'read-archive': data.token_present, rotate: data.token_present, revoke: data.token_present, 'revoke-grant': data.continuation_open && wait === 0, downscope: changeable && (data.rights || []).length > 1, expand: changeable && !(data.rights || []).includes('synthetic-archive:read'), 'check-retired':data.retired_token_present};
  for (const button of document.querySelectorAll('[data-action]')) button.disabled = !enabled[button.dataset.action];
  if (data.continuation_open && wait > 0) setTimeout(() => fetch('/api/status').then(r => r.json()).then(render).catch(e => {error.textContent = e.message;}), 1000);
}
for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', async () => {
  button.disabled = true;
  try {
    const response = await fetch(`/api/${button.dataset.action}`, {method: 'POST', credentials: 'same-origin'});
    const data = await response.json();
    if (['start', 'expand', 'downscope'].includes(button.dataset.action) && data.state === 'pending' && data.interaction_uri) { const target = new URL(data.interaction_uri); if (target.origin !== location.origin) throw new Error('Unexpected interaction origin'); location.assign(target.href); return; }
    if (data.redirect) { const target = new URL(data.redirect); if (target.origin !== location.origin) throw new Error('Unexpected callback origin'); location.assign(target.href); return; }
    render(data);
  } catch (e) { error.textContent = e.message; }
  finally { if (error.textContent) button.disabled = false; }
});
fetch('/api/status', {credentials: 'same-origin'}).then(r => r.json()).then(render).catch(e => {error.textContent = e.message;});
