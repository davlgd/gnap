// Execute the real rendering code with a small DOM double, not a browser engine.
// No network requests, timers or npm dependencies are needed for these labels.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('../../static/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/app.js', import.meta.url), 'utf8');

function renderSnapshot(data, timers) {
  const element = () => ({
    textContent: '', dataset: {},
    replaceChildren() {}, append() {}, addEventListener() {},
  });
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element()]));
  const buttons = [...html.matchAll(/data-action="([^"]+)"/g)].map(([, action]) => {
    const button = element();
    button.dataset.action = action;
    nodes.set(`[data-action="${action}"]`, button);
    return button;
  });
  const context = {
    document: {
      querySelector(selector) {
        assert.ok(nodes.has(selector), `unknown selector: ${selector}`);
        return nodes.get(selector);
      },
      querySelectorAll(selector) {
        assert.equal(selector, '[data-action]');
        return buttons;
      },
      createElement: element,
    },
    // Leave initial status loading pending; each case supplies its own snapshot.
    fetch: () => new Promise(() => {}),
    setTimeout: (callback, delay) => timers ? timers.push({callback, delay}) : assert.fail('unexpected polling in a pending consent snapshot'),
    data,
  };
  runInNewContext(`${script}\nrender(data);`, context, { timeout: 1000 });
  return nodes;
}

test('identity is opt-in and consent is explicit without opening grant modification', () => {
  const nodes = renderSnapshot({state: 'pending', identity_requested: true});
  assert.equal(nodes.get('#identity-consent').hidden, false);
  assert.equal(nodes.get('[data-action="approve"]').disabled, false);
  assert.equal(nodes.get('[data-action="start-identity"]').disabled, false);
  assert.match(nodes.get('#identity').textContent, /No currently verified identity/);
  assert.equal(renderSnapshot({state:'pending'}).get('#identity-consent').hidden, true);
});

test('verified identity display expires locally and never exposes a raw assertion', () => {
  const timers = [];
  const nodes = renderSnapshot({state:'approved', identity_requested:true, continuation_open:false,
    identity:{status:'verified', subject:'fictional-subject', issuer:'https://issuer.example', as_endpoint:'https://issuer.example/gnap', expires_at:Math.floor(Date.now()/1000)+300, assertion:'DO-NOT-DISPLAY'}}, timers);
  assert.match(nodes.get('#identity').textContent, /fictional-subject/);
  assert.doesNotMatch(nodes.get('#identity').textContent, /DO-NOT-DISPLAY/);
  for (const action of ['downscope', 'expand', 'continue', 'revoke-grant']) assert.equal(nodes.get(`[data-action="${action}"]`).disabled, true);
  assert.equal(timers.length, 1);
  assert.ok(timers[0].delay > 0 && timers[0].delay <= 300000);
  timers[0].callback();
  assert.match(nodes.get('#identity').textContent, /expired/);
  const expired = renderSnapshot({state:'approved', identity_requested:true, identity:{status:'verified', subject:'stale', expires_at:1}});
  assert.doesNotMatch(expired.get('#identity').textContent, /stale/);
});

for (const [name, mode, tokens, expected] of [
  ['single unlabelled token', 'single', [{ rights: ['folder:read'] }], 'folder:read'],
  ['two labelled tokens', 'multiple', [
    { label: 'documents', rights: ['folder:read'] },
    { label: 'reports', rights: ['reports:read'] },
  ], 'documents: folder:read | reports: reports:read'],
  ['one remaining labelled token', 'multiple', [
    { label: 'documents', rights: ['folder:read'] },
  ], 'documents: folder:read'],
]) {
  test(name, () => {
    assert.equal(renderSnapshot({
      state: 'pending', mode, requested_tokens: tokens,
      requested_rights: tokens.flatMap(token => token.rights),
    }).get('#requested-rights').textContent, expected);
  });
}

for (const codes of [false, true]) {
  test(`client consent controls ${codes ? 'refuse code interactions' : 'allow redirect interactions'}`, () => {
    // Include a reports slot to exercise every consent control, independently
    // of the current start-code action's single-token selection.
    const nodes = renderSnapshot({
      state: 'pending', mode: 'multiple', continuation_open: true,
      requested_tokens: [{ label: 'reports', rights: ['reports:read'] }],
      ...(codes ? { user_code_uri: { uri: 'https://example.test/code', code: 'ABCD2345' } } : {}),
    });
    for (const action of ['approve', 'approve-reports', 'deny']) {
      assert.equal(nodes.get(`[data-action="${action}"]`).disabled, codes, action);
    }
    assert.equal(nodes.get('[data-action="continue"]').disabled, !codes);
    assert.equal(nodes.get('[data-action="revoke-grant"]').disabled, false);
  });
}
