// Behavioral regression for the shared result panel of the workbench UI.
//
// This is NOT a browser rendering test. It loads the real static/index.html
// and static/app.js into a deliberately strict, minimal DOM double: any DOM
// property or method that app.js touches but this double does not implement
// throws, so drift between the stub and the real page fails loudly instead of
// passing vacuously. No npm dependency; run with `node --test`.
//
// Protected behavior: a response that arrives after the panel was cleared
// (Clear button, message-type change) must not be rendered, must not
// overwrite the summary and must not re-enable Download. Nothing here claims
// that the network request is cancelled; only that a stale response is not
// displayed. Synthetic data only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../static/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/app.js', import.meta.url), 'utf8');

const WRITABLE = new Set(['value', 'checked', 'hidden', 'disabled', 'textContent', 'href', 'rel', 'download']);

function element(tagName, id, attrs = '') {
  const state = {
    tagName, id,
    value: '', checked: false,
    hidden: /\bhidden\b/.test(attrs),
    disabled: /\bdisabled\b/.test(attrs),
    textContent: '', href: '', rel: '', download: '',
    dataset: {}, children: [], listeners: new Map(), clicks: 0,
    selectedIndex: -1,
  };
  const label = () => (id ? `#${id}` : `<${tagName}>`);
  const isSelect = state.tagName === 'select';
  // A single, non-multiple select with no selected option selects its first
  // option when options are inserted (HTML "selectedness setting algorithm").
  const resetSelection = () => { if (isSelect && state.selectedIndex === -1 && state.children.length) state.selectedIndex = 0; };
  const api = {
    get id() { return state.id; },
    get tagName() { return state.tagName.toUpperCase(); },
    get dataset() { return state.dataset; },
    get children() { return state.children; },
    get value() {
      if (!isSelect) return state.value;
      return state.selectedIndex === -1 ? '' : state.children[state.selectedIndex].value;
    },
    set value(v) {
      if (!isSelect) { state.value = String(v); return; }
      // Unknown value: no option selected, value reads back as ''.
      state.selectedIndex = state.children.findIndex(o => o.value === String(v));
    },
    get selectedOptions() {
      if (!isSelect) throw new Error(`stub: selectedOptions on ${label()}`);
      return state.selectedIndex === -1 ? [] : [state.children[state.selectedIndex]];
    },
    append(...nodes) { state.children.push(...nodes); resetSelection(); },
    replaceChildren(...nodes) { state.children = [...nodes]; state.selectedIndex = -1; resetSelection(); },
    addEventListener(type, fn) {
      if (!state.listeners.has(type)) state.listeners.set(type, []);
      state.listeners.get(type).push(fn);
    },
    click() { state.clicks += 1; },
    // Test-only helper (not a DOM API): run the registered handlers and return
    // their promise so a test can observe the in-flight request.
    async emit(type) {
      const handlers = state.listeners.get(type) || [];
      assert.ok(handlers.length, `no ${type} handler registered on ${label()}`);
      return Promise.all(handlers.map(fn => fn({ type })));
    },
  };
  return new Proxy(api, {
    get(target, prop) {
      if (typeof prop === 'symbol' || prop === 'then') return undefined;
      if (prop in target) return target[prop];
      if (WRITABLE.has(prop)) return state[prop];
      throw new Error(`stub: unsupported property "${String(prop)}" read on ${label()}`);
    },
    set(target, prop, v) {
      if (prop === 'value') { target.value = v; return true; }
      if (WRITABLE.has(prop)) { state[prop] = v; return true; }
      throw new Error(`stub: unsupported property "${String(prop)}" written on ${label()}`);
    },
  });
}

function buildDocument() {
  const byId = new Map();
  for (const m of html.matchAll(/<(\w+)([^>]*?)\sid="([^"]+)"([^>]*)>/g)) {
    const [, tag, before, id, after] = m;
    assert.ok(!byId.has(id), `duplicate id="${id}" in index.html`);
    byId.set(id, element(tag, id, `${before} ${after}`));
  }
  for (const m of html.matchAll(/<select id="([^"]+)"[^>]*>(.*?)<\/select>/gs)) {
    const select = byId.get(m[1]);
    for (const o of m[2].matchAll(/<option(?: value="([^"]*)")?>([^<]*)<\/option>/g)) {
      const option = element('option', '');
      option.value = o[1] ?? o[2];
      option.textContent = o[2];
      select.append(option);
    }
  }
  for (const m of html.matchAll(/<textarea id="([^"]+)"[^>]*>([^<]*)<\/textarea>/g)) byId.get(m[1]).value = m[2];
  const doc = {
    getElementById(id) {
      if (!byId.has(id)) throw new Error(`stub: index.html has no id="${id}" but app.js asked for it`);
      return byId.get(id);
    },
    createElement(tag) { return element(tag, ''); },
  };
  return new Proxy(doc, {
    get(target, prop) {
      if (typeof prop === 'symbol' || prop === 'then') return undefined;
      if (prop in target) return target[prop];
      throw new Error(`stub: unsupported document.${String(prop)} read`);
    },
    set(_target, prop) { throw new Error(`stub: unsupported document.${String(prop)} write`); },
  });
}

const report = {
  checks: [{ id: 'message-shape', status: 'pass', detail: 'synthetic', reference: 'https://www.rfc-editor.org/rfc/rfc9635.html#section-2', remediation: null }],
  observation: { source: 'import', harness_version: '0.0.0-test', revision: 'unknown', observed_at_unix_seconds_utc: 0 },
};
const response = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
const flush = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve, reject; const promise = new Promise((res, rej) => { resolve = res; reject = rej; }); return { promise, resolve, reject }; };

async function loadApp() {
  const document = buildDocument();
  const pending = [];
  const fetch = (url, options) => {
    if (url === '/api/targets') return Promise.resolve(response(200, [{ id: 0, role: 'as', url: 'https://as.example/gnap' }]));
    return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject }));
  };
  // app.js declares only top-level const/let/function; evaluating it inside a
  // Function body keeps every load isolated. globalThis is not mutated.
  new Function('document', 'fetch', script)(document, fetch);
  await flush(); // let loadTargets() settle
  const el = id => document.getElementById(id);
  assert.equal(el('probe').disabled, false, 'targets loaded');
  assert.equal(el('target').value, '0', 'first loaded target is selected');
  const take = expectedUrl => {
    const request = pending.shift();
    assert.ok(request, `no in-flight request to ${expectedUrl}`);
    assert.equal(request.url, expectedUrl);
    return request;
  };
  return { el, take };
}

function assertPanelCleared(el, button) {
  assert.equal(el('report').children.length, 0, 'stale report must not be rendered');
  assert.equal(el('summary').textContent, '', 'stale summary must not be written');
  assert.equal(el('download').disabled, true, 'Download must stay disabled');
  assert.equal(el(button).disabled, false, `${button} button must be re-enabled`);
}

// One button = one handler under test. The probe needs single-use consent.
const BUTTONS = {
  analyze: { url: '/api/analyze', start: el => el('analyze').emit('click') },
  probe: { url: '/api/probe', start: el => { el('consent').checked = true; return el('probe').emit('click'); } },
};

// How the panel gets cleared while the request is in flight.
const INTERRUPTIONS = {
  'Clear button': async el => { await el('clear').emit('click'); },
  'message-type change': async el => { el('kind').value = 'grant_response'; await el('kind').emit('change'); },
};

// How the late request settles after the interruption. `late json` resolves
// fetch() first, then interrupts while response.json() is still pending: a
// guard placed only before the second await would miss it.
const SETTLEMENTS = {
  'HTTP 200 report': { settle: request => request.resolve(response(200, report)) },
  'HTTP 400': { settle: request => request.resolve(response(400, null)) },
  'TimeoutError': { settle: request => request.reject(Object.assign(new Error('timed out'), { name: 'TimeoutError' })) },
  'late json': {
    prepare: request => { const body = deferred(); request.resolve({ ok: true, status: 200, json: () => body.promise }); return body; },
    settle: body => body.resolve(report),
  },
};

for (const [button, { url, start }] of Object.entries(BUTTONS)) {
  for (const [interruption, interrupt] of Object.entries(INTERRUPTIONS)) {
    for (const [settlement, { prepare, settle }] of Object.entries(SETTLEMENTS)) {
      test(`${button}: ${interruption} during an in-flight request, then ${settlement}, is not displayed`, async () => {
        const { el, take } = await loadApp();
        const inFlight = start(el);
        let handle = take(url);
        if (prepare) { handle = prepare(handle); await flush(); }
        await interrupt(el);
        settle(handle);
        await inFlight;
        assertPanelCleared(el, button);
        if (button === 'probe') assert.equal(el('consent').checked, false, 'consent is single-use');
        if (interruption === 'message-type change') assert.equal(el('kind').value, 'grant_response');
      });
    }
  }
}

test('an uninterrupted analysis and probe still render normally', async () => {
  const { el, take } = await loadApp();
  let inFlight = el('analyze').emit('click');
  take('/api/analyze').resolve(response(200, report));
  await inFlight;
  assert.equal(el('report').children.length, 1);
  assert.match(el('summary').textContent, /^1 passed checks; 0 failed checks; 0 not tested\./);
  assert.equal(el('download').disabled, false);

  el('consent').checked = true;
  inFlight = el('probe').emit('click');
  take('/api/probe').resolve(response(200, report));
  await inFlight;
  assert.equal(el('report').children.length, 1, 'a new run replaces the previous report');
  assert.equal(el('download').disabled, false);
  assert.equal(el('consent').checked, false);
});

test('a rejected request after a completed one keeps the panel consistent', async () => {
  const { el, take } = await loadApp();
  let inFlight = el('analyze').emit('click');
  take('/api/analyze').resolve(response(200, report));
  await inFlight;
  inFlight = el('analyze').emit('click');
  take('/api/analyze').resolve(response(400, null));
  await inFlight;
  assert.equal(el('report').children.length, 0);
  assert.match(el('summary').textContent, /^Import rejected \(HTTP 400\)/);
  assert.equal(el('download').disabled, true);
});

test('the stub select follows DOM value semantics', async () => {
  const { el } = await loadApp();
  assert.equal(el('kind').value, 'grant_request');
  el('kind').value = 'not-an-option';
  assert.equal(el('kind').value, '');
  assert.deepEqual(el('kind').selectedOptions, []);
  el('kind').value = 'as_discovery';
  assert.equal(el('kind').selectedOptions[0].value, 'as_discovery');
});

test('discovery and token-pair fixtures keep their controls and request contexts separate', async () => {
  const { el, take } = await loadApp();
  await el('discovery-fixture').emit('click');
  assert.equal(el('kind').value, 'as_discovery');
  assert.equal(el('discovery-context').hidden, false);
  assert.equal(el('digest-context').hidden, true);
  assert.equal(el('headers').disabled, false);
  let inFlight = el('analyze').emit('click');
  let request = take('/api/analyze');
  const discovery = JSON.parse(request.options.body);
  assert.equal(discovery.queried_endpoint, 'https://test-as.example/gnap');
  assert.equal(discovery.http_status, 200);
  assert.deepEqual(discovery.headers, [['Content-Type', 'application/json']]);
  assert.equal(discovery.content_digest, null);
  assert.equal(Object.hasOwn(discovery, 'rs_context'), false);
  request.resolve(response(200, report));
  await inFlight;

  await el('token-fixture').emit('click');
  assert.equal(el('kind').value, 'token_exchange');
  assertPanelCleared(el, 'analyze');
  assert.equal(el('discovery-context').hidden, true);
  assert.equal(el('context-section').hidden, true);
  assert.equal(el('digest-context').hidden, true);
  for (const id of ['headers', 'digest']) {
    assert.equal(el(id).disabled, true);
    assert.equal(el(id).value, '');
  }
  // Disabled or hidden controls do not belong to the pair's envelope, even
  // when they retain unrelated values. These values must not be parsed.
  for (const id of ['headers', 'digest', 'rs-context', 'queried-endpoint', 'http-status']) el(id).value = 'stale';
  inFlight = el('analyze').emit('click');
  request = take('/api/analyze');
  const pair = JSON.parse(request.options.body);
  assert.deepEqual(Object.keys(pair).sort(), ['body', 'content_digest', 'headers', 'kind']);
  assert.equal(pair.kind, 'token_exchange');
  assert.equal(pair.headers, null);
  assert.equal(pair.content_digest, null);
  assert.deepEqual(JSON.parse(pair.body).response.access_token.map(token => token.label), ['reports']);
  request.resolve(response(200, report));
  await inFlight;

  await el('fixture').emit('click');
  assert.equal(el('kind').value, 'continue_request');
  assert.equal(el('digest-context').hidden, false);
  assert.equal(el('discovery-context').hidden, true);
  assert.equal(el('headers').disabled, false);
  assert.equal(el('digest').disabled, false);
  el('consent').checked = true;
  await el('clear').emit('click');
  for (const id of ['body', 'headers', 'digest', 'rs-context', 'queried-endpoint', 'http-status']) assert.equal(el(id).value, '');
  assert.equal(el('consent').checked, false);
  assertPanelCleared(el, 'analyze');
});
