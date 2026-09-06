// Behavioral tests of the real lifecycle script with a strict DOM double.
// These check state, request and rendering decisions, not browser layout.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../static/lifecycle.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/lifecycle.js', import.meta.url), 'utf8');
const response = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body });
const flush = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const sampleReport = {
  certification: false,
  checks: [{ id: 'synthetic-check', status: 'pass', detail: '<img src=x onerror=alert(1)>' }],
};
const state = (status, extra = {}) => ({ status, report: sampleReport, ...extra });

function node(tag, attributes = '') {
  const data = {
    value: '', checked: false, hidden: /\bhidden\b/.test(attributes),
    disabled: /\bdisabled\b/.test(attributes), textContent: '', href: '', download: '',
    children: [], clicks: 0,
  };
  const listeners = new Map();
  const api = {
    append(...children) {
      data.children.push(...children);
      if (tag === 'select' && !data.value && data.children.length) data.value = data.children[0].value;
    },
    replaceChildren(...children) { data.children = []; if (tag === 'select') data.value = ''; api.append(...children); },
    addEventListener(type, handler) { assert.ok(!listeners.has(type)); listeners.set(type, handler); },
    click() { data.clicks += 1; },
    emit(type) { assert.ok(listeners.has(type)); return listeners.get(type)(); },
  };
  return new Proxy(api, {
    get(target, property) {
      if (property === 'then' || typeof property === 'symbol') return undefined;
      if (Object.hasOwn(target, property)) return target[property];
      if (Object.hasOwn(data, property)) return data[property];
      throw new Error(`Unsupported <${tag}>.${String(property)} read`);
    },
    set(_target, property, value) {
      if (!Object.hasOwn(data, property)) throw new Error(`Unsupported <${tag}>.${String(property)} write`);
      data[property] = value; return true;
    },
  });
}

async function loadApp({ protocol = 'https:', targets = [{ id: 2, name: '<b>Test AS</b>', grant: 'https://as.example/gnap', resource: 'https://rs.example/resource' }] } = {}) {
  const elements = new Map();
  for (const match of html.matchAll(/<(\w+)([^>]*?)\sid="([^"]+)"([^>]*)>/g)) {
    assert.ok(!elements.has(match[3]), `Duplicate page id: ${match[3]}`);
    elements.set(match[3], node(match[1], `${match[2]} ${match[4]}`));
  }
  const created = [], pending = [], timers = [], blobs = [], revoked = [];
  const document = {
    getElementById(id) { assert.ok(elements.has(id), `Missing page element: ${id}`); return elements.get(id); },
    createElement(tag) { const result = node(tag); created.push(result); return result; },
  };
  const fetch = (url, options) => {
    if (url === '/api/lifecycle/targets') {
      assert.equal(options.credentials, 'omit');
      return Promise.resolve(response(200, targets));
    }
    return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject }));
  };
  class TestURL extends URL {
    static createObjectURL(blob) { blobs.push(blob); return 'blob:synthetic-report'; }
    static revokeObjectURL(url) { revoked.push(url); }
  }
  new Function('document', 'fetch', 'location', 'setTimeout', 'URL', script)(
    document, fetch, { protocol }, (callback, delay) => timers.push({ callback, delay }), TestURL,
  );
  await flush();
  const take = expected => {
    const request = pending.shift();
    assert.ok(request, `Missing request: ${expected}`);
    assert.equal(request.url, expected);
    assert.equal(request.options.cache, 'no-store');
    assert.equal(request.options.credentials, 'same-origin');
    return request;
  };
  return { el: id => document.getElementById(`lifecycle-${id}`), take, pending, timers, blobs, revoked, created };
}

async function ready(options) {
  const app = await loadApp(options);
  app.take('/api/lifecycle/status').resolve(response(404));
  await flush();
  return app;
}

test('only an explicit consent starts the selected operator-approved target', async () => {
  const { el, take, pending } = await ready();
  assert.equal(el('target').value, '2');
  assert.match(el('target').children[0].textContent, /^<b>Test AS<\/b>/);
  await el('start').emit('click');
  assert.equal(pending.length, 0);
  assert.equal(el('status').textContent, 'Explicit consent is required.');
  el('consent').checked = true;
  const start = el('start').emit('click');
  const request = take('/api/lifecycle/start');
  assert.equal(request.options.method, 'POST');
  assert.deepEqual(request.options.headers, { 'Content-Type': 'application/json' });
  assert.deepEqual(JSON.parse(request.options.body), { target_id: 2, consent: true });
  request.resolve(response(202));
  await flush();
  take('/api/lifecycle/status').resolve(response(200, state('running')));
  await start;
  assert.equal(el('start').disabled, true);
});

test('an unavailable target list leaves start disabled', async () => {
  const { el } = await ready({ targets: [] });
  assert.equal(el('target').disabled, true);
  assert.equal(el('start').disabled, true);
});

for (const [label, redirect, protocol, visible] of [
  ['HTTPS AS', 'https://as.example/interact/synthetic', 'https:', true],
  ['local development AS', 'http://127.0.0.1:18083/interact/synthetic', 'http:', true],
  ['remote HTTP AS', 'http://as.example/interact/synthetic', 'http:', false],
  ['HTTP downgrade', 'http://127.0.0.1:18083/interact/synthetic', 'https:', false],
  ['script URL', 'javascript:alert(1)', 'https:', false],
]) {
  test(`pending consent offers a manual link only for ${label}: ${visible}`, async () => {
    const { el, take, timers, pending } = await loadApp({ protocol });
    take('/api/lifecycle/status').resolve(response(200, state('pending', { redirect })));
    await flush();
    assert.equal(el('redirect').hidden, !visible);
    if (visible) assert.equal(el('redirect').href, redirect);
    assert.equal(el('start').disabled, true);
    assert.equal(pending.length, 0, 'the UI never requests the owner page or submits consent');
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 1000);
  });
}

test('checks render as text and download contains only the report, not the redirect', async () => {
  const { el, take, blobs, created, timers, revoked } = await loadApp();
  take('/api/lifecycle/status').resolve(response(200, state('pending', { redirect: 'https://as.example/interact/private-handle' })));
  await flush();
  assert.equal(el('report').children[0].children[1].textContent, sampleReport.checks[0].detail);
  await el('download').emit('click');
  assert.equal(blobs.length, 1);
  assert.equal(blobs[0].type, 'application/json');
  assert.deepEqual(JSON.parse(await blobs[0].text()), sampleReport);
  const link = created.find(item => item.download === 'gnap-lifecycle-report.json');
  assert.equal(link.clicks, 1);
  assert.equal(link.href, 'blob:synthetic-report');
  timers.find(timer => timer.delay === 1000 && timer !== timers[0]).callback();
  assert.deepEqual(revoked, ['blob:synthetic-report']);
});

test('a terminal result retains failed checks and does not advertise certification', async () => {
  const { el, take, timers } = await loadApp();
  take('/api/lifecycle/status').resolve(response(200, state('complete', { report: { ...sampleReport, checks: [{ id: 'negative-control', status: 'fail', detail: 'Synthetic failure' }] } })));
  await flush();
  assert.match(el('status').textContent, /completed scenario can still contain failed checks/);
  assert.match(el('report').children[0].children[0].textContent, /^FAIL/);
  assert.equal(el('start').disabled, false);
  assert.equal(el('download').disabled, false);
  assert.equal(el('redirect').hidden, true);
  assert.equal(timers.length, 0);
});

for (const settlement of ['response', 'late JSON', 'HTTP error', 'timeout']) {
  test(`a stale status ${settlement} cannot replace a newly started scenario`, async () => {
    const { el, take, timers } = await loadApp();
    const oldRequest = take('/api/lifecycle/status');
    let body;
    if (settlement === 'late JSON') {
      body = deferred(); oldRequest.resolve({ ok: true, status: 200, json: () => body.promise });
      await flush();
    }
    el('consent').checked = true;
    const start = el('start').emit('click');
    take('/api/lifecycle/start').resolve(response(202));
    await start;
    const oldState = state('complete', { redirect: 'https://as.example/interact/old' });
    if (settlement === 'response') oldRequest.resolve(response(200, oldState));
    if (settlement === 'late JSON') body.resolve(oldState);
    if (settlement === 'HTTP error') oldRequest.resolve(response(503));
    if (settlement === 'timeout') oldRequest.reject(Object.assign(new Error('old timeout'), { name: 'TimeoutError' }));
    await flush();
    assert.equal(el('report').children.length, 0);
    assert.equal(el('download').disabled, true);
    assert.equal(el('redirect').hidden, true);
    assert.equal(el('start').disabled, true);
    assert.equal(el('status').textContent, '');
    const next = timers.find(timer => timer.delay === 0);
    assert.ok(next, 'the new scenario must be polled after the old request settles');
    const refreshed = next.callback();
    take('/api/lifecycle/status').resolve(response(200, state('denied')));
    await refreshed;
    assert.match(el('status').textContent, /^Scenario: denied\./);
    assert.equal(el('download').disabled, false);
  });
}

test('a refused start keeps any earlier report and redirect cleared', async () => {
  const { el, take } = await loadApp();
  take('/api/lifecycle/status').resolve(response(200, state('complete')));
  await flush();
  el('consent').checked = true;
  const start = el('start').emit('click');
  take('/api/lifecycle/start').resolve(response(429));
  await start;
  assert.match(el('status').textContent, /^Start refused \(HTTP 429\)/);
  assert.equal(el('start').disabled, false);
  assert.equal(el('report').children.length, 0);
  assert.equal(el('download').disabled, true);
  assert.equal(el('redirect').hidden, true);
});
