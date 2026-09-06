'use strict';
const byId = id => document.getElementById(id);
let currentReport = null;
function updateKind() { const discovery = byId('kind').value === 'as_discovery'; byId('discovery-context').hidden = !discovery; byId('digest-context').hidden = discovery; }
byId('kind').addEventListener('change', updateKind);
updateKind();
const clearReport = () => { currentReport = null; byId('report').replaceChildren(); byId('summary').textContent = ''; byId('download').disabled = true; };
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
  byId('analyze').disabled = true;
  try {
    const body = byId('body').value;
    if (new TextEncoder().encode(body).length > 32768) throw new Error('Body exceeds 32 KiB.');
    let headers = null;
    if (byId('headers').value.trim()) {
      try { headers = JSON.parse(byId('headers').value); } catch { throw new Error('Headers must be valid JSON pairs.'); }
    }
    const discovery = byId('kind').value === 'as_discovery';
    const httpStatus = discovery && byId('http-status').value !== '' ? Number(byId('http-status').value) : null;
    if (httpStatus !== null && (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599)) throw new Error('HTTP status must be an integer from 100 to 599.');
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', credentials: 'omit', body: JSON.stringify({ kind: byId('kind').value, body, headers, content_digest: discovery ? null : byId('digest').value || null, queried_endpoint: discovery ? byId('queried-endpoint').value || null : null, http_status: httpStatus }), signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(`Import rejected (HTTP ${response.status}). Check JSON, field and size limits.`);
    renderReport(await response.json());
  } catch (error) { byId('summary').textContent = error.name === 'TimeoutError' ? 'Request timed out.' : error.message; }
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
  if (!byId('consent').checked) { byId('summary').textContent = 'Explicit consent is required.'; return; }
  if (byId('operation').value === 'as_discovery' && byId('target').selectedOptions[0]?.dataset.role !== 'as') { byId('summary').textContent = 'Choose an AS target for discovery; RS discovery is not tested.'; return; }
  byId('probe').disabled = true;
  try {
    const response = await fetch('/api/probe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, cache: 'no-store', credentials: 'omit', body: JSON.stringify({ target_id: Number(byId('target').value), consent: true, operation: byId('operation').value }), signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error(response.status === 429 ? 'Global cooldown: wait 60 seconds before retrying.' : 'Probe inconclusive or unavailable. No protocol verdict; check target configuration, public DNS, TLS, deadline and size limits.');
    renderReport(await response.json());
  } catch (error) { byId('summary').textContent = error.name === 'TimeoutError' ? 'Probe timed out; result inconclusive.' : error.message; }
  finally { byId('probe').disabled = false; byId('consent').checked = false; }
});
loadTargets();
byId('fixture').addEventListener('click', () => { clearReport(); byId('kind').value = 'continue_request'; byId('body').value = '{"client":"must-not-be-repeated"}'; byId('headers').value = ''; byId('digest').value = ''; updateKind(); });
byId('discovery-fixture').addEventListener('click', () => { clearReport(); byId('kind').value = 'as_discovery'; byId('body').value = '{"grant_request_endpoint":"https://test-as.example/gnap","key_proofs_supported":["httpsig"],"key_rotation_supported":false}'; byId('headers').value = '[["Content-Type","application/json"]]'; byId('queried-endpoint').value = 'https://test-as.example/gnap'; byId('http-status').value = '200'; byId('digest').value = ''; updateKind(); });
byId('clear').addEventListener('click', () => { clearReport(); for (const id of ['body', 'headers', 'digest', 'queried-endpoint', 'http-status']) byId(id).value = ''; byId('consent').checked = false; });
byId('download').addEventListener('click', () => {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'gnap-diagnostics.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
