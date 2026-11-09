// The exchange inspector, run on the real page script with a small DOM double:
// what it shows comes from the script's own tables, never from the trace.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('../../static/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/app.js', import.meta.url), 'utf8');
const CANARY = 'canary7XQ';

function element(tag) {
  return {
    tag, textContent: '', className: '', hidden: false, dataset: {}, children: [],
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; },
    addEventListener(type, handler) { this[type] = handler; },
  };
}

function render(trace) {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element('')]));
  const context = {
    document: {
      querySelector(selector) {
        assert.ok(nodes.has(selector), `unknown selector: ${selector}`);
        return nodes.get(selector);
      },
      querySelectorAll: () => [],
      createElement: element,
    },
    fetch: () => new Promise(() => {}),
    setTimeout: () => {},
    trace,
  };
  runInNewContext(`${script}\nrenderTrace(trace);`, context, { timeout: 1000 });
  return nodes;
}

const text = node => [node.textContent, node.className, ...Object.values(node.dataset), ...node.children.map(text)].join(' | ');

const known = {
  seq: 0,
  request: {
    to: 'authorization_server', route: 'grant', method: 'POST', proof: 'httpsig',
    covered: ['@method', '@target-uri', 'content-digest'], other_components: 1, alg: 'ed25519',
    gnap_authorization: false, digests: ['sha-256'],
    body: { kind: 'object', fields: [{ name: 'access_token', kind: 'array' }], other_fields: 0,
      tokens: [{ label: 'documents', other_label: false, rights: ['synthetic-folder:read'], other_rights: 1 }], more_tokens: 0, error: null },
  },
  outcome: { kind: 'response', status: 400, media: 'json',
    body: { kind: 'object', fields: [{ name: 'error', kind: 'object' }], other_fields: 0, tokens: [], more_tokens: 0, error: 'invalid_request' } },
};

test('known values render with the page labels, arrow to their server', () => {
  const nodes = render({ attempts: [known], dropped: 0 });
  const row = nodes.get('#trace').children[0];
  assert.match(row.className, /\bto-as\b/);
  const shown = text(row);
  for (const expected of ['POST /gnap', '400 JSON', 'HTTP message signature, not verified here', '@method, @target-uri, content-digest, and 1 other(s)',
    'ed25519', 'sha-256', 'fields: access_token (array)', 'token documents: synthetic-folder:read and 1 other right(s)', 'error invalid_request']) {
    assert.ok(shown.includes(expected), `${expected} in ${shown}`);
  }
  assert.equal(nodes.get('#trace-dropped').hidden, true);
});

test('a value the tables do not know reads as Unknown, and never as itself', () => {
  const odd = JSON.parse(JSON.stringify(known).replaceAll('"authorization_server"', `"${CANARY}"`)
    .replaceAll('"grant"', `"${CANARY}"`).replaceAll('"POST"', `"${CANARY}"`).replaceAll('"httpsig"', `"${CANARY}"`)
    .replaceAll('"@method"', `"${CANARY}"`).replaceAll('"ed25519"', `"${CANARY}"`).replaceAll('"sha-256"', `"${CANARY}"`)
    .replaceAll('"json"', `"${CANARY}"`).replaceAll('"object"', `"${CANARY}"`).replaceAll('"access_token"', `"${CANARY}"`)
    .replaceAll('"documents"', `"${CANARY}"`).replaceAll('"synthetic-folder:read"', `"${CANARY}"`).replaceAll('"invalid_request"', `"${CANARY}"`));
  odd.outcome.status = CANARY;
  const nodes = render({ attempts: [odd], dropped: CANARY });
  assert.ok(!text(nodes.get('#trace-dropped')).includes(CANARY));
  assert.equal(nodes.get('#trace-dropped').hidden, true, 'a count that is not a count shows nothing');
  const shown = text(nodes.get('#trace').children[0]);
  assert.ok(!shown.includes(CANARY), shown);
  assert.ok(shown.includes('Unknown'));
  assert.match(render({ attempts: [odd], dropped: 0 }).get('#trace').children[0].className, /\bto-unknown\b/);
});

test('no response observed draws no reply and claims nothing about sending', () => {
  const nodes = render({ attempts: [{ ...known, outcome: { kind: 'no_response' } }], dropped: 3 });
  const row = nodes.get('#trace').children[0];
  const shown = text(row);
  assert.ok(shown.includes('no response observed'));
  assert.ok(shown.includes("whether the request even left isn't known here"));
  assert.ok(!/\b400\b/.test(shown));
  const summary = row.children[0].children[0];
  assert.equal(summary.dataset.outcome, 'none');
  assert.equal(nodes.get('#trace-dropped').hidden, false);
  assert.match(nodes.get('#trace-dropped').textContent, /^3 later exchange/);
});

test('an absent or malformed trace renders an empty list', () => {
  for (const trace of [null, undefined, {}, { attempts: 'x' }]) {
    const nodes = render(trace);
    assert.equal(nodes.get('#trace').children.length, 0);
    assert.equal(nodes.get('#trace-dropped').hidden, true);
  }
});

test('a refresh keeps the rows shown, appends new attempts, and a new trace replaces them', () => {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element('')]));
  const context = {
    document: { querySelector: selector => nodes.get(selector), querySelectorAll: () => [], createElement: element },
    fetch: () => new Promise(() => {}), setTimeout: () => {},
  };
  runInNewContext(script, context, { timeout: 1000 });
  const trace = { attempts: [known], dropped: 0 };
  context.renderTrace(trace);
  const first = nodes.get('#trace').children[0];
  first.children[0].open = true;
  context.renderTrace(JSON.parse(JSON.stringify(trace)));
  assert.equal(nodes.get('#trace').children[0], first, 'an unchanged trace keeps its rows');
  context.renderTrace({ attempts: [known, { ...known, seq: 1 }], dropped: 0 });
  const rows = nodes.get('#trace').children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0], first, 'a longer trace keeps the rows already shown');
  assert.equal(rows[0].children[0].open, true);
  context.renderTrace({ attempts: [{ ...known, request: { ...known.request, route: 'continue' } }], dropped: 0 });
  assert.equal(nodes.get('#trace').children.length, 1);
  assert.notEqual(nodes.get('#trace').children[0], first, 'another trace replaces the rows');
  const replaced = nodes.get('#trace').children[0];
  context.renderTrace({ attempts: [known, { ...known, seq: 1 }], dropped: 0 });
  assert.notEqual(nodes.get('#trace').children[0], replaced, 'a longer trace that differs from the shown one replaces it');
  assert.equal(nodes.get('#trace').children.length, 2);
});

/// The page with its buttons, a fetch whose answers the test gives, and the
/// timers it schedules.
function page() {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element('')]));
  const buttons = [...html.matchAll(/data-action="([^"]+)"/g)].map(([, action]) => {
    const button = element('button');
    button.dataset.action = action;
    button.addEventListener = (type, handler) => { button[type] = handler; };
    nodes.set(`[data-action="${action}"]`, button);
    return button;
  });
  const requests = [];
  const timers = [];
  const context = {
    document: {
      querySelector: selector => nodes.get(selector),
      querySelectorAll: () => buttons,
      createElement: element,
    },
    fetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
    setTimeout: callback => { timers.push(callback); return timers.length; },
    clearTimeout: () => {},
    location: { origin: 'https://demo.example', assign() {} },
  };
  runInNewContext(script, context, { timeout: 1000 });
  const answer = (index, data) => requests[index].resolve({ json: async () => data });
  const routes = () => text(nodes.get('#trace'));
  return { nodes, requests, timers, answer, routes };
}

const attempt = route => ({ ...known, request: { ...known.request, route } });
const settle = () => new Promise(resolve => setImmediate(resolve));

test('a late status read from before a new start never shows the old grant', async () => {
  const lab = page();
  assert.equal(lab.requests[0].url, '/api/status');
  const failed = lab.nodes.get('[data-action="read"]').click();
  assert.equal(lab.requests[1].url, '/api/read');
  lab.answer(1, { error: 'synthetic failure' });
  await failed;
  assert.equal(lab.requests[2].url, '/api/status', 'the refused action reads the record again');
  const started = lab.nodes.get('[data-action="start-code"]').click();
  lab.answer(3, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  assert.ok(lab.routes().includes('/gnap'));
  lab.answer(2, { trace: { attempts: [attempt('folder')], dropped: 0 } });
  lab.answer(0, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.ok(!lab.routes().includes('/resource/folder'), 'an older read is dropped');
  assert.ok(lab.routes().includes('/gnap'));
});

test('a status read a timer started before an action never renders over it', async () => {
  const lab = page();
  lab.answer(0, { state: 'starting', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.equal(lab.timers.length, 1, 'a starting grant schedules a refresh');
  lab.timers[0]();
  const inFlight = lab.requests.length - 1;
  assert.equal(lab.requests[inFlight].url, '/api/status');
  const started = lab.nodes.get('[data-action="start"]').click();
  lab.answer(inFlight + 1, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  lab.answer(inFlight, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.ok(!lab.routes().includes('/resource/folder'), 'the read that left before the action is dropped');
  assert.ok(lab.routes().includes('/gnap'));
});

test('one action runs at a time: a click while one is in flight sends nothing', async () => {
  const lab = page();
  lab.answer(0, { state: 'approved', token_present: true, trace: { attempts: [attempt('grant')], dropped: 0 } });
  await settle();
  const read = lab.nodes.get('[data-action="read"]');
  const start = lab.nodes.get('[data-action="start-code"]');
  assert.equal(read.disabled, false);
  const reading = read.click();
  assert.ok([...lab.nodes.values()].filter(node => node.dataset.action).every(node => node.disabled), 'every command is locked');
  const sent = lab.requests.length;
  await start.click();
  assert.equal(lab.requests.length, sent, 'the second click sent nothing');
  lab.answer(sent - 1, { state: 'approved', token_present: true, trace: { attempts: [attempt('grant'), attempt('folder')], dropped: 0 } });
  await reading;
  assert.equal(read.disabled, false, 'the state after the action sets the commands again');
  assert.ok(lab.routes().includes('/resource/folder'));
});

test('a new start clears the record before the new grant answers', async () => {
  const lab = page();
  lab.answer(0, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.ok(lab.routes().includes('/resource/folder'));
  const started = lab.nodes.get('[data-action="start"]').click();
  assert.equal(lab.nodes.get('#trace').children.length, 0, 'the old record is gone at once');
  lab.answer(1, { state: 'pending', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await started;
  assert.equal(lab.nodes.get('#trace').children.length, 1, 'the new record is drawn, even when it looks the same');
});

test('a status read that overlaps an action never renders after it', async () => {
  const lab = page();
  lab.answer(0, { state: 'starting', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  const started = lab.nodes.get('[data-action="start-code"]').click();
  const action = lab.requests.length - 1;
  lab.timers[0]();
  const overlapping = lab.requests.length - 1;
  assert.equal(lab.requests[overlapping].url, '/api/status', 'the timer read leaves while the action is in flight');
  lab.answer(action, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  lab.answer(overlapping, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.ok(!lab.routes().includes('/resource/folder'));
  assert.ok(lab.routes().includes('/gnap'));
});

test('a failure that predates an action never shows as its error', async () => {
  const lab = page();
  const started = lab.nodes.get('[data-action="start"]').click();
  lab.answer(1, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  lab.requests[0].resolve({ json: async () => { throw new Error('obsolete status failure'); } });
  await settle();
  assert.equal(lab.nodes.get('#error').textContent, '', 'the first load failed before the start');

  // An action whose answer can't be read shows why, and gives the commands back.
  const read = lab.nodes.get('[data-action="read"]');
  read.disabled = false;
  const failing = read.click();
  lab.requests[lab.requests.length - 1].resolve({ json: async () => { throw new Error('unreadable answer'); } });
  await failing;
  assert.equal(lab.nodes.get('#error').textContent, 'unreadable answer');
  assert.equal(read.disabled, false);
});

test('a status read answered while an action is in flight is dropped too', async () => {
  const lab = page();
  const started = lab.nodes.get('[data-action="start"]').click();
  lab.answer(0, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.equal(lab.nodes.get('#trace').children.length, 0, 'the cleared record stays clear');
  lab.answer(1, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  assert.ok(lab.routes().includes('/gnap'));
});

test('a status read that leaves and answers while an action runs is dropped', async () => {
  const lab = page();
  lab.answer(0, { state: 'starting', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  const started = lab.nodes.get('[data-action="start"]').click();
  const action = lab.requests.length - 1;
  lab.timers[0]();
  const read = lab.requests.length - 1;
  lab.answer(read, { state: 'approved', trace: { attempts: [attempt('folder')], dropped: 0 } });
  await settle();
  assert.equal(lab.nodes.get('#trace').children.length, 0, 'nothing renders while the start runs');
  lab.answer(action, { state: 'pending', trace: { attempts: [attempt('grant')], dropped: 0 } });
  await started;
  assert.ok(lab.routes().includes('/gnap'));
  assert.ok(!lab.routes().includes('/resource/folder'));
});

test('a start sends the proof chosen for its grant, and a JOSE choice keeps identity and push off', async () => {
  const lab = page();
  lab.answer(0, { state: 'new', trace: { attempts: [], dropped: 0 } });
  await settle();
  assert.equal(lab.nodes.get('[data-action="start-identity"]').disabled, false);
  lab.nodes.get('#proof-jwsd').checked = true;
  const started = lab.nodes.get('[data-action="start"]').click();
  const request = lab.requests[lab.requests.length - 1];
  assert.equal(request.url, '/api/start');
  assert.deepEqual(JSON.parse(request.options.body), { proof: 'jwsd' });
  assert.equal(request.options.headers['content-type'], 'application/json');
  lab.answer(lab.requests.length - 1, { state: 'failed', proof: { method: 'jwsd', alg: 'EdDSA' }, trace: { attempts: [], dropped: 0 } });
  await started;
  assert.equal(lab.nodes.get('#proof').textContent, 'Detached JWS, EdDSA');
  assert.equal(lab.nodes.get('[data-action="start-identity"]').disabled, true, 'identity uses HTTP message signatures only');
  assert.equal(lab.nodes.get('[data-action="start-push"]').disabled, true);
});

test('the proof shown comes from the page tables, never from the answer', async () => {
  const lab = page();
  lab.answer(0, { state: 'approved', proof: { method: CANARY, alg: CANARY }, trace: { attempts: [], dropped: 0 } });
  await settle();
  assert.equal(lab.nodes.get('#proof').textContent, 'None yet');
  const other = page();
  other.answer(0, { state: 'approved', proof: { method: 'jws', alg: CANARY }, trace: { attempts: [], dropped: 0 } });
  await settle();
  assert.equal(other.nodes.get('#proof').textContent, 'JWS in the body, Unknown');
});

test('an algorithm the page does not know shows as unknown, even a prototype name', async () => {
  const lab = page();
  lab.answer(0, { state: 'approved', proof: { method: 'jwsd', alg: 'toString' }, trace: { attempts: [], dropped: 0 } });
  await settle();
  assert.equal(lab.nodes.get('#proof').textContent, 'Detached JWS, Unknown');
});

test('changing the proof while an action runs unlocks nothing, and its end keeps the choice', async () => {
  for (const ending of ['state', 'error']) {
    const lab = page();
    lab.answer(0, { state: 'new', trace: { attempts: [], dropped: 0 } });
    await settle();
    const identity = lab.nodes.get('[data-action="start-identity"]');
    const started = lab.nodes.get('[data-action="start"]').click();
    assert.equal(identity.disabled, true, 'locked while the start runs');
    lab.nodes.get('#proof-httpsig').checked = true;
    lab.nodes.get('#proof-httpsig').change();
    assert.equal(identity.disabled, true, `${ending}: a change of proof during the action`);
    lab.nodes.get('#proof-httpsig').checked = false;
    lab.nodes.get('#proof-jwsd').checked = true;
    lab.nodes.get('#proof-jwsd').change();
    assert.equal(identity.disabled, true, `${ending}: still locked`);
    const index = lab.requests.length - 1;
    lab.answer(index, ending === 'state' ? { state: 'new', trace: { attempts: [], dropped: 0 } } : { error: 'synthetic failure' });
    await started;
    assert.equal(identity.disabled, true, `${ending}: a JOSE choice keeps identity off after the action`);
  }
});

