// Tests of the suite's shared presentation helpers, apps/ui/gnap.js, with a
// minimal DOM double: it records what the helpers build, and refuses any
// property they aren't expected to touch. Not a browser rendering test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../gnap.js', import.meta.url), 'utf8');
const FIELDS = ['className', 'textContent', 'href', 'rel', 'title', 'hidden', 'ariaHidden'];

function node(tag) {
  const state = { tag, children: [], dataset: {} };
  for (const field of FIELDS) state[field] = undefined;
  return new Proxy(state, {
    get(target, property) {
      if (property === 'append') return (...nodes) => target.children.push(...nodes);
      if (property in target) return target[property];
      throw new Error(`stub: <${tag}>.${String(property)} read`);
    },
    set(target, property, value) {
      if (!FIELDS.includes(property)) throw new Error(`stub: <${tag}>.${String(property)} written`);
      target[property] = value;
      return true;
    },
  });
}

const document = { createElement: tag => node(tag) };
const GNAP = new Function('document', `${source}\nreturn GNAP;`)(document);
const text = row => row.children.map(child => child.textContent);

test('a reference becomes a link only for an RFC section or an IANA registry', () => {
  assert.deepEqual(GNAP.citation('https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6'), {
    href: 'https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6', label: 'RFC 9635 §3.6',
  });
  assert.equal(GNAP.citation('https://www.rfc-editor.org/rfc/rfc9767.html').label, 'RFC 9767');
  assert.equal(GNAP.citation('https://www.iana.org/assignments/gnap/').label, 'IANA registry');
  for (const reference of [
    'javascript:alert(1)',
    'http://www.rfc-editor.org/rfc/rfc9635.html',
    'https://rfc-editor.org.example/rfc/rfc9635.html',
    'https://evil-rfc-editor.org/rfc/rfc9635.html',
    'https://rfc-editor.org/rfc/rfc9635.html',
    'https://www.iana.org.example/assignments/gnap/',
    'https://www.rfc-editor.org:8443/rfc/rfc9635.html',
    'https://user@www.rfc-editor.org/rfc/rfc9635.html',
    'https://www.rfc-editor.org/rfc/rfc9635.html?q=1',
    'https://www.rfc-editor.org/rfc/rfc9635.html#section-1"><b>',
    'https://www.rfc-editor.org/info/rfc9635',
    'https://www.iana.org/assignments/gnap/../../x',
    'not a URL',
  ]) assert.equal(GNAP.citation(reference), null, reference);
});

test('a check row shows its status in words, its detail as text, and a safe citation', () => {
  const row = GNAP.checkRow({
    id: 'error-response-json', status: 'fail', detail: '<img src=x onerror=alert(1)>',
    reference: 'https://www.rfc-editor.org/rfc/rfc9635.html#section-3', remediation: 'Send JSON.',
  });
  assert.equal(row.tag, 'article');
  assert.equal(row.dataset.status, 'fail');
  assert.ok(text(row).includes('Failed'), 'the status is a word, not only a color');
  assert.ok(text(row).includes('<img src=x onerror=alert(1)>'), 'the detail is text');
  assert.ok(text(row).includes('Next: Send JSON.'));
  const link = row.children.find(child => child.tag === 'a');
  assert.equal(link.href, 'https://www.rfc-editor.org/rfc/rfc9635.html#section-3');
  assert.equal(link.rel, 'noreferrer');
  assert.equal(link.textContent, 'RFC 9635 §3');
});

test('an unexpected reference stays text, and an unknown status reads as not tested', () => {
  const row = GNAP.checkRow({ id: 'x', status: 'certified', detail: 'd', reference: 'https://evil.example/' });
  assert.equal(row.dataset.status, 'not_tested');
  assert.ok(!row.children.some(child => child.tag === 'a'), 'no link');
  assert.ok(text(row).includes('https://evil.example/'));
});

test('the tally has one titled cell per check, in order, and the filter hides the others', () => {
  const checks = [
    { id: 'a', status: 'pass' }, { id: 'b', status: 'fail' }, { id: 'c', status: 'not_tested' },
  ];
  const cells = GNAP.tallyCells(checks);
  assert.deepEqual(cells.map(cell => cell.dataset.status), ['pass', 'fail', 'not_tested']);
  assert.equal(cells[1].title, 'b: Failed');
  const rows = checks.map(check => GNAP.checkRow({ ...check, detail: '' }));
  GNAP.filterRows(rows, 'fail');
  assert.deepEqual(rows.map(row => row.hidden), [true, false, true]);
  GNAP.filterRows(rows, 'all');
  assert.deepEqual(rows.map(row => row.hidden), [false, false, false]);
});

test('the helpers build only the elements they know', () => {
  assert.throws(() => GNAP.el('script', ''), /unsupported tag/);
  assert.throws(() => GNAP.el('iframe', ''), /unsupported tag/);
});
