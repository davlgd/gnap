'use strict';
const error = document.querySelector('#error');
function render(data) {
  if (data.error) { error.textContent = data.error; return; }
  error.textContent = '';
  document.querySelector('#state').textContent = data.state || 'unknown';
  const events = document.querySelector('#events'); events.replaceChildren();
  for (const event of data.events || []) { const item = document.createElement('li'); item.textContent = event; events.append(item); }
  document.querySelector('#resource').textContent = data.folder ? JSON.stringify(data.folder, null, 2) : 'No resource has been read with the current token.';
  const wait = data.continuation_wait_seconds || 0;
  document.querySelector('[data-action="continue"]').textContent = wait > 0 && data.state === 'ready' ? `Continue in ${wait}s` : 'Continue after callback';
  const enabled = {start: true, approve: data.state === 'pending', deny: data.state === 'pending', continue: data.state === 'ready' && wait === 0, read: data.state === 'approved', rotate: data.state === 'approved', revoke: data.state === 'approved', 'check-retired':data.retired_token_present};
  for (const button of document.querySelectorAll('[data-action]')) button.disabled = !enabled[button.dataset.action];
  if (data.state === 'ready' && wait > 0) setTimeout(() => fetch('/api/status').then(r => r.json()).then(render).catch(e => {error.textContent = e.message;}), 1000);
}
for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', async () => {
  button.disabled = true;
  try {
    const response = await fetch(`/api/${button.dataset.action}`, {method: 'POST', credentials: 'same-origin'});
    const data = await response.json();
    if (button.dataset.action === 'start' && data.interaction_uri) { const target = new URL(data.interaction_uri); if (target.origin !== location.origin) throw new Error('Unexpected interaction origin'); location.assign(target.href); return; }
    if (data.redirect) { const target = new URL(data.redirect); if (target.origin !== location.origin) throw new Error('Unexpected callback origin'); location.assign(target.href); return; }
    render(data);
  } catch (e) { error.textContent = e.message; }
  finally { if (error.textContent) button.disabled = false; }
});
fetch('/api/status', {credentials: 'same-origin'}).then(r => r.json()).then(render).catch(e => {error.textContent = e.message;});
