'use strict';
const element = id => document.getElementById(id);
let report = null;
let polling = false;
let generation = 0;
async function refresh() {
  if (polling) return;
  polling = true;
  const requestedGeneration = generation;
  try {
    const response = await fetch('/api/lifecycle/status', { cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(5000) });
    if (response.status === 404) return;
    if (!response.ok) throw new Error(`Status unavailable (HTTP ${response.status}).`);
    const state = await response.json();
    if (requestedGeneration !== generation) return;
    element('lifecycle-status').textContent = `Scenario: ${state.status}. A completed scenario can still contain failed checks.`;
    element('lifecycle-start').disabled = ['pending', 'running'].includes(state.status);
    const link = element('lifecycle-redirect');
    link.hidden = true;
    if (state.status === 'pending' && typeof state.redirect === 'string') {
      const url = new URL(state.redirect);
      if (url.protocol === 'https:' || (location.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) && url.protocol === 'http:')) {
        link.href = url.href;
        link.hidden = false;
      }
    }
    report = state.report;
    element('lifecycle-report').replaceChildren();
    for (const check of report.checks) {
      const item = document.createElement('article');
      const heading = document.createElement('h3');
      heading.textContent = `${check.status.toUpperCase()} — ${check.id}`;
      const detail = document.createElement('p'); detail.textContent = check.detail;
      item.append(heading, detail);
      element('lifecycle-report').append(item);
    }
    element('lifecycle-download').disabled = false;
    if (['pending', 'running'].includes(state.status)) setTimeout(refresh, 1000);
  } catch (error) {
    if (requestedGeneration === generation) element('lifecycle-status').textContent = error.name === 'TimeoutError' ? 'Status request timed out. Reload to check the existing scenario.' : error.message;
  } finally {
    polling = false;
    if (requestedGeneration !== generation) setTimeout(refresh, 0);
  }
}
element('lifecycle-start').addEventListener('click', async () => {
  if (!element('lifecycle-consent').checked) {
    element('lifecycle-status').textContent = 'Explicit consent is required.'; return;
  }
  element('lifecycle-start').disabled = true;
  generation += 1;
  report = null;
  element('lifecycle-report').replaceChildren();
  element('lifecycle-download').disabled = true;
  element('lifecycle-redirect').hidden = true;
  try {
    const response = await fetch('/api/lifecycle/start', { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_id: Number(element('lifecycle-target').value), consent: true }), signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`Start refused (HTTP ${response.status}). Check operator key approval, shared cooldown and capacity.`);
    await refresh();
  } catch (error) { element('lifecycle-status').textContent = error.message; element('lifecycle-start').disabled = false; }
});
element('lifecycle-download').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'gnap-lifecycle-report.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
(async () => {
  try {
    const response = await fetch('/api/lifecycle/targets', { cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(5000) });
    if (!response.ok) return;
    const targets = await response.json();
    if (targets.length) {
      element('lifecycle-target').replaceChildren();
      for (const target of targets) {
        const option = document.createElement('option'); option.value = String(target.id); option.textContent = `${target.name} — ${target.grant} → ${target.resource}`;
        element('lifecycle-target').append(option);
      }
      element('lifecycle-target').disabled = false;
      element('lifecycle-start').disabled = false;
    }
    await refresh();
  } catch { element('lifecycle-status').textContent = 'Lifecycle configuration unavailable.'; }
})();
