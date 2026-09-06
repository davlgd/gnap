'use strict';
const byId = id => document.getElementById(id);
let currentReport = null;
let reportGeneration = 0;
const kindHelp = {
  as_discovery: 'Captured RFC 9635 section 9 discovery document. Declared endpoint and HTTP status are compared, never fetched. Announced capabilities are not tested in operation.',
  rs_discovery: 'AS metadata for resource servers at /.well-known/gnap-as-rs, not metadata about an RS itself. Announced capabilities are not tested in operation.',
  introspection_request: 'Shape only. The RS signs with its own key; proof describes the client proof and is recommended, not required. Never paste a private key or production token.',
  introspection_response: 'An active response requires access (possibly empty) and iss. Inactive responses contain active: false only. Neither state nor cryptographic binding is verified.',
  rs_error_response: 'RS-facing errors use RFC 9767 section 3.5 and its separate error registry. The specified HTTP 400 can only be compared with a declared status.',
  resource_registration_request: 'Requires access and resource_server. Optional formats and introspection requirements are declarations: no AS compatibility or RS signature is verified, including for an empty format list. No comparison context is accepted.',
  resource_registration_response: 'Requires a resource_reference string, not an access token. Optional instance_id and introspection_endpoint are checked as strings only. No reference resolution, URL fetch or actual registration is verified. No comparison context is accepted.',
  derivation_request: 'Selected token request: existing_access_token, client and access_token are required. RS1 must sign with its own key; JSON cannot prove that or the parent token validity. Interaction and extensions are not forbidden. No comparison context is accepted.',
  derivation_response: 'Selected grant-response fields only. A missing token, continuation, interaction or error does not prove issuance. Token value checks are string-shape only, not token68 encoding. No effective rights, audience or revocation linkage is verified. No comparison context is accepted.'
};
const contextHelp = {
  rs_discovery: 'Allowed: grant_request_endpoint (expected exact client endpoint), discovery_url (declared publication URL). Example: {"grant_request_endpoint":"https://as.example/gnap","discovery_url":"https://as.example/.well-known/gnap-as-rs"}',
  introspection_response: 'Allowed: token_binding, either "bound" or "bearer". Example: {"token_binding":"bound"}. An absent context leaves unobservable conditions not tested.',
  rs_error_response: 'Allowed: http_status, integer 100..599. Example: {"http_status":400}. This is not an observed HTTP response.'
};
function updateKind() {
  const kind = byId('kind').value;
  const discovery = kind === 'as_discovery';
  byId('kind-help').textContent = kindHelp[kind] || 'Select the message actually captured. Request and response checks are distinct.';
  byId('discovery-context').hidden = !discovery;
  byId('digest-context').hidden = discovery;
  byId('context-section').hidden = !contextHelp[kind];
  byId('context-help').textContent = contextHelp[kind] || '';
  byId('rs-context').value = '';
}
byId('kind').addEventListener('change', () => { clearReport(); updateKind(); });
updateKind();
// Clearing invalidates late results, not requests already sent to the server.
const clearReport = () => { reportGeneration += 1; currentReport = null; byId('report').replaceChildren(); byId('summary').textContent = ''; byId('download').disabled = true; };
function renderReport(report) {
  currentReport = report;
  const counts = { pass: 0, fail: 0, not_tested: 0 };
  for (const check of currentReport.checks) {
    counts[check.status] += 1;
    const article = document.createElement('article');
    const heading = document.createElement('h3');
    heading.textContent = `${check.status.toUpperCase()} — ${check.id}`;
    const detail = document.createElement('p'); detail.textContent = check.detail;
    const ref = document.createElement('a');
    // Imported values never become HTML or executable URLs.
    if (/^https:\/\/www\.rfc-editor\.org\/rfc\/rfc[0-9]+\.html(?:#[a-zA-Z0-9.-]+)?$/.test(check.reference)) ref.href = check.reference;
    ref.textContent = check.reference; ref.rel = 'noreferrer';
    article.append(heading, detail, ref);
    if (check.remediation) { const advice = document.createElement('p'); advice.textContent = `Next action: ${check.remediation}`; article.append(advice); }
    byId('report').append(article);
  }
  const provenance = currentReport.observation;
  byId('summary').textContent = `${counts.pass} passed checks; ${counts.fail} failed checks; ${counts.not_tested} not tested. No overall conformance verdict. Source: ${provenance.source}; version ${provenance.harness_version}; revision ${provenance.revision}; ${new Date(provenance.observed_at_unix_seconds_utc * 1000).toISOString()}.`;
  byId('download').disabled = false;
}
byId('analyze').addEventListener('click', async () => {
  clearReport();
  const generation = reportGeneration;
  byId('analyze').disabled = true;
  try {
    const body = byId('body').value;
    if (new TextEncoder().encode(body).length > 32768) throw new Error('Body exceeds 32 KiB.');
    let headers = null;
    if (byId('headers').value.trim()) {
      try { headers = JSON.parse(byId('headers').value); } catch { throw new Error('Headers must be valid JSON pairs.'); }
    }
    const kind = byId('kind').value;
    const discovery = kind === 'as_discovery';
    const envelope = { kind, body, headers, content_digest: discovery ? null : byId('digest').value || null };
    if (contextHelp[kind] && byId('rs-context').value.trim()) {
      try { envelope.rs_context = JSON.parse(byId('rs-context').value); } catch { throw new Error('Context must be a JSON object with fields appropriate to this message type.'); }
    }
    if (discovery) {
      const httpStatus = byId('http-status').value !== '' ? Number(byId('http-status').value) : null;
      if (httpStatus !== null && (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599)) throw new Error('HTTP status must be an integer from 100 to 599.');
      envelope.queried_endpoint = byId('queried-endpoint').value || null;
      envelope.http_status = httpStatus;
    }
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', credentials: 'omit', body: JSON.stringify(envelope), signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`Import rejected (HTTP ${response.status}). Check JSON, field and size limits.`);
    const report = await response.json();
    if (generation === reportGeneration) renderReport(report);
  } catch (error) { if (generation === reportGeneration) byId('summary').textContent = error.name === 'TimeoutError' ? 'Request timed out.' : error.message; }
  finally { byId('analyze').disabled = false; }
});
async function loadTargets() {
  try {
    const response = await fetch('/api/targets', { cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(10000) });
    if (!response.ok) return;
    const targets = await response.json();
    if (!targets.length) return;
    byId('target').replaceChildren();
    for (const target of targets) { const option = document.createElement('option'); option.value = String(target.id); option.dataset.role = target.role; option.textContent = `${target.role.toUpperCase()} — ${target.url}`; byId('target').append(option); }
    byId('target').disabled = false; byId('probe').disabled = false;
  } catch { /* Import analysis remains available when targets cannot load. */ }
}
byId('probe').addEventListener('click', async () => {
  clearReport();
  const generation = reportGeneration;
  if (!byId('consent').checked) { byId('summary').textContent = 'Explicit consent is required.'; return; }
  if (byId('operation').value === 'as_discovery' && byId('target').selectedOptions[0]?.dataset.role !== 'as') { byId('summary').textContent = 'Choose an AS target for discovery; RS discovery is not tested.'; return; }
  byId('probe').disabled = true;
  try {
    const response = await fetch('/api/probe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', credentials: 'omit', body: JSON.stringify({ target_id: Number(byId('target').value), consent: true, operation: byId('operation').value }), signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(response.status === 429 ? 'Global cooldown: wait 60 seconds before retrying.' : 'Probe inconclusive or unavailable. No protocol verdict; check target configuration, public DNS, TLS, deadline and size limits.');
    const report = await response.json();
    if (generation === reportGeneration) renderReport(report);
  } catch (error) { if (generation === reportGeneration) byId('summary').textContent = error.name === 'TimeoutError' ? 'Probe timed out; result inconclusive.' : error.message; }
  finally { byId('probe').disabled = false; byId('consent').checked = false; }
});
loadTargets();
byId('fixture').addEventListener('click', () => { clearReport(); byId('kind').value = 'continue_request'; updateKind(); byId('body').value = '{"client":"must-not-be-repeated"}'; byId('headers').value = ''; byId('digest').value = ''; });
byId('discovery-fixture').addEventListener('click', () => { clearReport(); byId('kind').value = 'as_discovery'; updateKind(); byId('body').value = '{"grant_request_endpoint":"https://test-as.example/gnap","key_proofs_supported":["httpsig"],"key_rotation_supported":false}'; byId('headers').value = '[["Content-Type","application/json"]]'; byId('queried-endpoint').value = 'https://test-as.example/gnap'; byId('http-status').value = '200'; byId('digest').value = ''; });
byId('clear').addEventListener('click', () => { clearReport(); for (const id of ['body', 'headers', 'digest', 'rs-context', 'queried-endpoint', 'http-status']) byId(id).value = ''; byId('consent').checked = false; });
byId('download').addEventListener('click', () => {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'gnap-diagnostics.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
