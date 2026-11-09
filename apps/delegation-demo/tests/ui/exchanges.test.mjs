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
    addEventListener() {},
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
