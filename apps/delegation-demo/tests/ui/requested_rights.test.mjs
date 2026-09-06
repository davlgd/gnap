// Execute the real rendering code with a small DOM double, not a browser engine.
// No network requests, timers or npm dependencies are needed for these labels.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('../../static/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/app.js', import.meta.url), 'utf8');

function renderSnapshot(data) {
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
    setTimeout: () => assert.fail('unexpected polling in a pending consent snapshot'),
    data,
  };
  runInNewContext(`${script}\nrender(data);`, context, { timeout: 1000 });
  return nodes;
}

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
