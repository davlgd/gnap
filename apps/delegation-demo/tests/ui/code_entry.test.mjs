// Exercise the real script with a DOM double and synthetic HTTP responses.
// This is not a browser-engine or hosted TLS test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('../../static/code.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../static/code.js', import.meta.url), 'utf8');
const failure = 'The request could not be completed. Reload before trying again.';

function entry(responses) {
  const element = () => ({
    textContent: '', hidden: false, dataset: {}, children: [],
    replaceChildren() { this.children = []; },
    append(child) { this.children.push(child); },
    addEventListener() {},
  });
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element()]));
  const buttons = [...html.matchAll(/<button\b[^>]*>/g)].map(() => element());
  const requests = [];
  const context = {
    document: {
      body: { dataset: { ticket: 'first-ticket' } },
      querySelector(selector) {
        assert.ok(nodes.has(selector), `unknown selector: ${selector}`);
        return nodes.get(selector);
      },
      querySelectorAll(selector) {
        assert.ok(['button', '[data-choice]'].includes(selector));
        return selector === 'button' ? buttons : buttons.slice(1);
      },
      createElement: element,
    },
    async fetch(path, options) {
      requests.push({ path, options, body: JSON.parse(options.body) });
      assert.ok(buttons.every(button => button.disabled));
      assert.ok(responses.length, 'unexpected request');
      return responses.shift();
    },
  };
  runInNewContext(script, context, { timeout: 1000 });
  return { nodes, buttons, requests, submit: context.submit };
}

for (const [name, response] of [
  ['empty 503', { ok: false, json: async () => { throw new SyntaxError('private response body'); } }],
  ['HTML 503', { ok: false, json: async () => { throw new SyntaxError('<html>private gateway detail</html>'); } }],
  ['malformed success', { ok: true, json: async () => { throw new SyntaxError('private response body'); } }],
  ['null JSON', { ok: false, json: async () => null }],
  ['array JSON', { ok: false, json: async () => [] }],
]) {
  test(`${name} hides stale consent and shows a fixed recovery message`, async () => {
    const ui = entry([response]);
    ui.nodes.get('#consent').hidden = false;
    await ui.submit('/code/lookup', { code: 'ABCD2345' });
    assert.equal(ui.nodes.get('#error').textContent, failure);
    assert.equal(ui.nodes.get('#consent').hidden, true);
    assert.ok(ui.buttons.every(button => !button.disabled));
    assert.equal(ui.requests.length, 1);
  });
}

test('valid lookup, JSON refusal and consent preserve ticket rotation and completion', async () => {
  const ui = entry([
    { ok: true, json: async () => ({ ticket: 'second-ticket', remaining: 4, rights: [{ rights: ['folder:read'] }] }) },
    { ok: false, json: async () => ({ ticket: 'third-ticket', remaining: 3, error: 'Code is unavailable.' }) },
    { ok: true, json: async () => ({ ticket: 'fourth-ticket', remaining: 2, complete: true }) },
  ]);
  await ui.submit('/code/lookup', { code: 'ABCD2345' });
  assert.equal(ui.nodes.get('#consent').hidden, false);
  assert.equal(ui.nodes.get('#rights').children[0].textContent, 'Access token: folder:read');
  await ui.submit('/code/lookup', { code: 'BAD' });
  assert.equal(ui.nodes.get('#consent').hidden, true);
  assert.equal(ui.nodes.get('#error').textContent, 'Code is unavailable.');
  await ui.submit('/code/consent', { choice: 'allow' });
  assert.deepEqual(ui.requests.map(request => request.body.ticket), ['first-ticket', 'second-ticket', 'third-ticket']);
  assert.equal(ui.nodes.get('#error').textContent, '');
  assert.equal(ui.nodes.get('#lookup').hidden, true);
  assert.match(ui.nodes.get('#result').textContent, /decision is recorded/);
  assert.match(ui.nodes.get('#remaining').textContent, /^2 attempts remain/);
  assert.ok(ui.buttons.every(button => !button.disabled));
});
