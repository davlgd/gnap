'use strict';
const error = document.querySelector('#error');
let identityExpiryTimer;
let statusTimer;
function render(data) {
  if (data.error) { error.textContent = data.error; return; }
  error.textContent = '';
  if (identityExpiryTimer !== undefined) clearTimeout(identityExpiryTimer);
  if (statusTimer !== undefined) clearTimeout(statusTimer);
  const push = data.push_finish;
  document.querySelector('#push-finish').hidden = !push;
  document.querySelector('#push-status').textContent = !push ? '' : push.received
    ? `The client validated the HTTP callback. Sender delivery status: ${push.delivery}.`
    : push.expired ? 'The callback window expired. Start a fresh request; polling the AS cannot replace a missing callback.'
    : push.delivery === 'waiting_for_consent' ? 'Waiting for consent. The AS will send the callback directly to the client.'
    : `Waiting for a valid callback. Sender delivery status: ${push.delivery}. An uncertain delivery does not undo consent or prove that the callback was lost.`;
  document.querySelector('#state').textContent = data.state || 'unknown';
  document.querySelector('#identity-consent').hidden = !data.identity_requested;
  const identityLive = data.identity?.status === 'verified' && data.identity.expires_at * 1000 > Date.now();
  document.querySelector('#identity').textContent = identityLive
    ? `Fictional identity ${data.identity.subject}, stated by ${data.identity.issuer} through ${data.identity.as_endpoint}. Assertion expires at ${new Date(data.identity.expires_at * 1000).toISOString()}. Not a login or a resource token.`
    : data.identity_requested ? 'No currently verified identity. Consent, a bound callback and signed continuation are required; expired assertions are not displayed.' : 'Identity was not requested.';
  const slots = (data.requested_tokens || []).map(t => `${t.label || 'token'}: ${(t.rights || []).join(', ')}`);
  document.querySelector('#requested-rights').textContent = (data.mode === 'multiple' || slots.length > 1 ? slots.join(' | ') : (data.requested_rights || []).join(', ')) || 'Start a request to choose rights.';
  document.querySelector('[data-action="check-retired"]').textContent = data.retired_token_label ? `Prove the retired ${data.retired_token_label} token is refused` : 'Prove the retired token is refused';
  document.querySelector('#current-rights').textContent = (data.rights || []).join(', ') || 'No live token.';
  document.querySelector('#tokens').textContent = (data.tokens || []).map(t => `${t.label || 'unlabelled'}: ${(t.rights || []).join(', ')}`).join(' | ') || 'None';
  const events = document.querySelector('#events'); events.replaceChildren();
  for (const event of data.events || []) { const item = document.createElement('li'); item.textContent = event; events.append(item); }
  document.querySelector('#resource').textContent = data.folder ? JSON.stringify(data.folder, null, 2) : 'No resource has been read with the current token.';
  const codes = Boolean(data.user_code_uri);
  document.querySelector('#device-code').hidden = !codes;
  document.querySelector('#code-uri').textContent = data.user_code_uri?.uri || '';
  document.querySelector('#user-code').textContent = data.user_code_uri?.code || '';
  const wait = data.continuation_wait_seconds || 0;
  const continuable = data.continuation_open && (['ready', 'approved', 'revoked'].includes(data.state) || (codes && data.state === 'pending'));
  document.querySelector('[data-action="continue"]').textContent = continuable && wait > 0 ? `Continue in ${wait}s` : data.state === 'approved' ? 'Poll without reissuing tokens' : codes ? 'Poll for the owner’s decision' : 'Continue after callback';
  const changeable = ['approved', 'revoked'].includes(data.state) && data.continuation_open && wait === 0;
  // Cancellation also applies before approval; unlike changing rights, it only needs live continuation and an elapsed wait.
  const lot = data.mode === 'multiple';
  const has = label => (data.tokens || []).some(t => t.label === label);
  const documents = lot ? has('documents') : data.token_present;
  const reports = lot && has('reports');
  const complete = lot ? has('documents') && has('reports') && (data.rights || []).includes('synthetic-archive:read') : (data.rights || []).includes('synthetic-archive:read');
  const startable = !['starting', 'failed'].includes(data.state);
  const enabled = {start: startable, 'start-identity': startable, 'start-multiple': startable, 'start-code': startable, approve: data.state === 'pending' && !codes, 'approve-reports': data.state === 'pending' && !codes && lot && (data.requested_tokens || []).some(t => t.label === 'reports'), deny: data.state === 'pending' && !codes, continue: continuable && wait === 0, read: documents, 'read-archive': documents, 'read-metadata': documents, 'read-reports': reports, rotate: documents, revoke: documents, 'rotate-reports': reports, 'revoke-reports': reports, 'revoke-grant': data.continuation_open && wait === 0, downscope: changeable && (lot ? (reports || (data.rights || []).includes('synthetic-archive:read')) : (data.rights || []).length > 1), expand: changeable && !complete, 'check-retired':data.retired_token_present};
  for (const button of document.querySelectorAll('[data-action]')) button.disabled = !enabled[button.dataset.action];
  document.querySelector('[data-action="start-push"]').disabled = !startable;
  if (push?.expired) for (const action of ['approve', 'deny']) document.querySelector(`[data-action="${action}"]`).disabled = true;
  if (identityLive) identityExpiryTimer = setTimeout(() => { document.querySelector('#identity').textContent = 'The displayed assertion has expired. Refresh the status to verify again.'; }, data.identity.expires_at * 1000 - Date.now());
  // This refreshes only this client's view. It never polls GNAP continuation.
  if (data.state === 'starting' || (data.continuation_open && wait > 0) || (push && !push.expired && (data.state === 'awaiting_push' || push.delivery === 'queued'))) statusTimer = setTimeout(() => fetch('/api/status').then(r => r.json()).then(render).catch(e => {error.textContent = e.message;}), 1000);
}
for (const button of document.querySelectorAll('[data-action]')) button.addEventListener('click', async () => {
  button.disabled = true;
  try {
    const response = await fetch(`/api/${button.dataset.action}`, {method: 'POST', credentials: 'same-origin'});
    const data = await response.json();
    if (['start', 'start-identity', 'start-push', 'start-multiple', 'expand', 'downscope'].includes(button.dataset.action) && data.state === 'pending' && data.interaction_uri) { const target = new URL(data.interaction_uri); if (target.origin !== location.origin) throw new Error('Unexpected interaction origin'); location.assign(target.href); return; }
    if (data.redirect) { const target = new URL(data.redirect); if (target.origin !== location.origin) throw new Error('Unexpected callback origin'); location.assign(target.href); return; }
    render(data);
  } catch (e) { error.textContent = e.message; }
  finally { if (error.textContent) button.disabled = false; }
});
fetch('/api/status', {credentials: 'same-origin'}).then(r => r.json()).then(render).catch(e => {error.textContent = e.message;});
