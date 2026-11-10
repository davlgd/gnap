'use strict';
const error = document.querySelector('#error');
let identityExpiryTimer;
let statusTimer;
// One action runs at a time: the commands are locked until it settles, so two
// starts can never race their session cookies. A status read, from a timer,
// the first load or a refused action, applies only while no action runs and
// if none settled since it left: otherwise it may carry the old session, and
// its answer and its failure are both dropped.
let busy = false;
let generation = 0;
function refreshStatus(apply) {
  const mine = generation;
  const current = () => !busy && mine === generation;
  fetch('/api/status', {credentials: 'same-origin'})
    .then(r => r.json())
    .then(view => { if (current()) apply(view); }, e => { if (current()) error.textContent = e.message; });
}
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
  document.querySelector('#state').dataset.state = data.state || 'unknown';
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
  renderTrace(data.trace);
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
  lastStartable = startable;
  lockHttpsigOnly();
  const proof = data.proof && Object.hasOwn(PROOF_NAMES, data.proof.method) ? data.proof : null;
  document.querySelector('#proof').textContent = proof ? `${PROOF_NAMES[proof.method]}, ${Object.hasOwn(PROOF_ALGS, proof.alg) ? PROOF_ALGS[proof.alg] : 'Unknown'}` : 'None yet';
  if (push?.expired) for (const action of ['approve', 'deny']) document.querySelector(`[data-action="${action}"]`).disabled = true;
  if (identityLive) identityExpiryTimer = setTimeout(() => { document.querySelector('#identity').textContent = 'The displayed assertion has expired. Refresh the status to verify again.'; }, data.identity.expires_at * 1000 - Date.now());
  // This refreshes only this client's view. It never polls GNAP continuation.
  if (data.state === 'starting' || (data.continuation_open && wait > 0) || (push && !push.expired && (data.state === 'awaiting_push' || push.delivery === 'queued'))) statusTimer = setTimeout(() => refreshStatus(render), 1000);
}
const actionButtons = [...document.querySelectorAll('[data-action]')];
for (const button of actionButtons) button.addEventListener('click', async () => {
  if (busy) return;
  busy = true;
  const before = actionButtons.map(item => item.disabled);
  for (const item of actionButtons) item.disabled = true;
  // The buttons as they were, for an action that renders no new state.
  const unlock = () => {
    actionButtons.forEach((item, i) => { item.disabled = before[i]; });
    lockHttpsigOnly();
  };
  // A new grant starts a new record.
  if (button.dataset.action.startsWith('start')) { shownAttempts = []; document.querySelector('#trace').replaceChildren(); }
  try {
    // A start carries the proof method chosen for its grant.
    const start = button.dataset.action.startsWith('start');
    const response = await fetch(`/api/${button.dataset.action}`, start
      ? {method: 'POST', credentials: 'same-origin', headers: {'content-type': 'application/json'}, body: JSON.stringify({proof: chosenProof()})}
      : {method: 'POST', credentials: 'same-origin'});
    const data = await response.json();
    busy = false;
    generation += 1;
    if (['start', 'start-identity', 'start-push', 'start-multiple', 'expand', 'downscope'].includes(button.dataset.action) && data.state === 'pending' && data.interaction_uri) { const target = new URL(data.interaction_uri); if (target.origin !== location.origin) throw new Error('Unexpected interaction origin'); location.assign(target.href); return; }
    if (data.redirect) { const target = new URL(data.redirect); if (target.origin !== location.origin) throw new Error('Unexpected callback origin'); location.assign(target.href); return; }
    render(data);
    if (data.error) {
      unlock();
      recover(data.error);
    }
  } catch (e) {
    busy = false;
    generation += 1;
    unlock();
    error.textContent = e.message;
    recover(e.message);
  }
});
// A failed action answers with its error only, and the status read it may
// have overlapped was dropped: read the whole state again, without sending
// the action twice, so the attempt it made shows and a countdown it stopped
// starts again. The action's error stays shown.
function recover(message) {
  refreshStatus(view => { render(view); error.textContent = message; });
}
refreshStatus(render);

// The exchange inspector. Every label comes from these tables: the trace holds
// only closed values, and anything unexpected reads as Unknown.
// The registered GNAP error codes, which a Rust test compares with the registry.
const ERROR_CODES = ['invalid_request', 'invalid_client', 'invalid_interaction', 'invalid_flag', 'invalid_rotation', 'key_rotation_not_supported', 'invalid_continuation', 'user_denied', 'request_denied', 'unknown_interaction', 'unknown_user', 'too_fast', 'too_many_attempts'];
const LABELS = {
  party: { authorization_server: 'Authorization server', documents_server: 'Documents server', reports_server: 'Reports server' },
  lane: { authorization_server: 'to-as', documents_server: 'to-documents', reports_server: 'to-reports' },
  route: { grant: '/gnap', continue: '/continue', token_management: '/token/…', folder: '/resource/folder', archive: '/resource/archive', folder_metadata: '/resource/folder-metadata', reports: '/resource/reports' },
  method: { GET: 'GET', POST: 'POST', PATCH: 'PATCH', DELETE: 'DELETE', OPTIONS: 'OPTIONS' },
  proof: { httpsig: 'HTTP message signature', jws: 'JWS in the body', jwsd: 'Detached-JWS field', ambiguous: 'Ambiguous: several proof fields', unparsable: 'Present but unparsable', none: 'None' },
  covered: { '@method': '@method', '@target-uri': '@target-uri', 'content-digest': 'content-digest', 'content-type': 'content-type', 'content-length': 'content-length', authorization: 'authorization' },
  alg: { 'rsa-pss-sha512': 'rsa-pss-sha512', 'ecdsa-p256-sha256': 'ecdsa-p256-sha256', ed25519: 'ed25519' },
  digest: { 'sha-256': 'sha-256', 'sha-512': 'sha-512' },
  media: { json: 'JSON', jose: 'JOSE', other: 'other type', ambiguous: 'several types' },
  kind: { empty: 'no body', object: 'JSON object', array: 'JSON array', scalar: 'JSON value', jose: 'JOSE, not decoded', not_json: 'not JSON', too_large: 'too large to read', too_deep: 'nested too deeply to read' },
  json: { object: 'object', array: 'array', string: 'string', number: 'number', bool: 'boolean', null: 'null' },
  field: { access_token: 'access_token', client: 'client', continue: 'continue', error: 'error', instance_id: 'instance_id', interact: 'interact', interact_ref: 'interact_ref', subject: 'subject', user: 'user' },
  label: { documents: 'documents', reports: 'reports' },
  right: { 'synthetic-folder:read': 'synthetic-folder:read', 'synthetic-archive:read': 'synthetic-archive:read', 'synthetic-reports:read': 'synthetic-reports:read', 'archive-metadata:read': 'archive-metadata:read' },
};
const label = (table, value) => (Object.hasOwn(LABELS[table], value) ? LABELS[table][value] : 'Unknown');
const count = value => (Number.isInteger(value) && value > 0 ? value : 0);

function textNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = text;
  return node;
}

function describeBody(body) {
  if (!body || typeof body !== 'object') return 'Unknown';
  const parts = [label('kind', body.kind)];
  const fields = (Array.isArray(body.fields) ? body.fields : []).map(field => `${label('field', field.name)} (${label('json', field.kind)})`);
  if (fields.length) parts.push(`fields: ${fields.join(', ')}`);
  if (count(body.other_fields)) parts.push(`${count(body.other_fields)} other field(s)`);
  for (const token of Array.isArray(body.tokens) ? body.tokens : []) {
    const name = token.label ? label('label', token.label) : token.other_label ? 'another label' : 'unlabelled';
    const rights = (Array.isArray(token.rights) ? token.rights : []).map(right => label('right', right));
    const others = count(token.other_rights) ? ` and ${count(token.other_rights)} other right(s)` : '';
    parts.push(`token ${name}: ${rights.join(', ') || 'no named right'}${others}`);
  }
  if (count(body.more_tokens)) parts.push(`${count(body.more_tokens)} more token(s)`);
  if (body.error !== null && body.error !== undefined) parts.push(`error ${ERROR_CODES.includes(body.error) ? body.error : 'Unknown'}`);
  return parts.join('; ');
}

function exchangeRow(attempt) {
  const request = attempt.request || {};
  const outcome = attempt.outcome || {};
  const known = Object.hasOwn(LABELS.party, request.to);
  const row = document.createElement('li');
  row.className = `exchange ${known ? LABELS.lane[request.to] : 'to-unknown'}`;
  const summary = document.createElement('details');
  const head = document.createElement('summary');
  head.append(
    textNode('span', 'call', `${label('method', request.method)} ${label('route', request.route)}`),
    textNode('span', 'reply', outcome.kind === 'response'
      ? `${Number.isInteger(outcome.status) ? outcome.status : '?'}${outcome.media ? ` ${label('media', outcome.media)}` : ''}`
      : 'no response observed'),
  );
  head.dataset.outcome = outcome.kind === 'response' ? 'response' : 'none';
  const facts = document.createElement('dl');
  facts.className = 'facts';
  const fact = (term, value) => facts.append(textNode('dt', '', term), textNode('dd', '', value));
  fact('To', known ? label('party', request.to) : 'Unknown destination');
  fact('Proof announced', `${label('proof', request.proof)}, not verified here`);
  const covered = (Array.isArray(request.covered) ? request.covered : []).map(item => label('covered', item));
  if (covered.length) fact('Signature covers', covered.join(', ') + (count(request.other_components) ? `, and ${count(request.other_components)} other(s)` : ''));
  if (request.alg) fact('Signature algorithm', label('alg', request.alg));
  fact('Authorization', request.gnap_authorization ? 'GNAP token presented' : 'none');
  const digests = (Array.isArray(request.digests) ? request.digests : []).map(item => label('digest', item));
  if (request.digest_unparsable === true) fact('Content digest', 'Present but unparsable');
  else if (digests.length) fact('Content digest', digests.join(', '));
  fact('Request body', describeBody(request.body));
  fact('Response', outcome.kind === 'response' ? describeBody(outcome.body) : 'None observed: whether the request even left isn\'t known here');
  summary.append(head, facts);
  row.append(summary);
  return row;
}

// The status refreshes while a grant waits. Attempts already shown keep their
// rows, so an open row stays open and keeps the focus, and new attempts are
// appended; a trace that doesn't extend the one shown, as after a new start,
// replaces it.
let shownAttempts = [];
function renderTrace(trace) {
  const list = document.querySelector('#trace');
  const attempts = trace && Array.isArray(trace.attempts) ? trace.attempts : [];
  const keys = attempts.map(attempt => JSON.stringify(attempt));
  const extending = shownAttempts.length <= keys.length && shownAttempts.every((key, i) => key === keys[i]);
  if (extending) list.append(...attempts.slice(shownAttempts.length).map(exchangeRow));
  else list.replaceChildren(...attempts.map(exchangeRow));
  shownAttempts = keys;
  const dropped = document.querySelector('#trace-dropped');
  dropped.hidden = !(trace && count(trace.dropped));
  dropped.textContent = dropped.hidden ? '' : `${count(trace.dropped)} later exchange(s) not kept: the record keeps the first 64.`;
}

// The proof the next start uses. HTTP message signatures unless a JOSE
// method is checked; the identity and push scenarios use them only.
const PROOF_NAMES = { httpsig: 'HTTP message signatures', jwsd: 'Detached JWS', jws: 'JWS in the body' };
const PROOF_ALGS = { PS256: 'PS256', EdDSA: 'EdDSA' };
let lastStartable = false;
function chosenProof() {
  if (document.querySelector('#proof-jwsd').checked === true) return 'jwsd';
  if (document.querySelector('#proof-jws').checked === true) return 'jws';
  return 'httpsig';
}
// While an action runs, every command stays locked, whatever the choice.
function lockHttpsigOnly() {
  if (busy) return;
  for (const action of ['start-identity', 'start-push']) {
    document.querySelector(`[data-action="${action}"]`).disabled = !lastStartable || chosenProof() !== 'httpsig';
  }
}
for (const id of ['#proof-httpsig', '#proof-jwsd', '#proof-jws']) document.querySelector(id).addEventListener('change', lockHttpsigOnly);
