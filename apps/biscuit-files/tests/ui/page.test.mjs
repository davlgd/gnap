// The Biscuit files page, run on its real script with a small DOM double:
// what it shows of a session comes from its own tables, it reads the state
// once, and a file server's refusal never reads as an access.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const html = readFileSync(new URL('../../src/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../../src/app.js', import.meta.url), 'utf8');
const CANARY = 'canary7XQ';

function element(tag) {
  const node = {
    tag, textContent: '', className: '', value: '', disabled: false, dataset: {}, children: [], parent: null,
    append(...nodes) { for (const child of nodes) { child.parent = this; this.children.push(child); } },
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); },
    addEventListener(type, handler) { this[type] = handler; },
  };
  return node;
}

function page() {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [`#${id}`, element('')]));
  nodes.get('#seconds').value = '120';
  nodes.get('#file').value = 'notes';
  const buttons = [...html.matchAll(/data-action="([^"]+)"[^>]*>([^<]*)</g)].map(([, action, label]) => {
    const button = element('button');
    button.dataset.action = action;
    button.textContent = label;
    nodes.set(action, button);
    return button;
  });
  const requests = [];
  const context = {
    document: {
      querySelector: selector => nodes.get(selector),
      querySelectorAll: () => buttons,
      createElement: element,
    },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  };
  runInNewContext(script, context, { timeout: 1000 });
  const reply = (index, status, data) => requests[index].resolve({
    status, json: async () => { if (data === undefined) throw new SyntaxError('not JSON'); return data; },
  });
  const all = () => [...nodes.values()].map(text).join(' | ');
  return { nodes, requests, reply, all, button: action => nodes.get(action) };
}

const text = node => [node.textContent, ...Object.values(node.dataset), ...node.children.map(text)].join(' ');
const settle = () => new Promise(resolve => setImmediate(resolve));
const VIEW = {
  restrictions: [], next_request_uses: 'issued', key_rotations: 0, key_attempts_left: 3,
  previous_key_testable: false, retired_token_testable: false,
};
const held = (extra = {}) => ({ event: 'Biscuit issued.', session: { ...VIEW, ...extra } });

test('the page reads the session state once, and sets no timer', async () => {
  const lab = page();
  assert.equal(lab.requests.length, 1);
  assert.equal(lab.requests[0].url, '/action/status');
  lab.reply(0, 401, null);
  await settle();
  assert.equal(lab.nodes.get('#state').textContent, 'No session');
  assert.equal(lab.nodes.get('#error').textContent, '', 'opening without a session is no error');
  assert.equal(lab.button('read').disabled, true);
  assert.equal(lab.button('start').disabled, false);
  assert.equal(lab.button('status').disabled, false);
  assert.equal(lab.requests.length, 1, 'no further read');
});

test('a late first read never overwrites what an action showed', async () => {
  const lab = page();
  const started = lab.button('start').click();
  lab.reply(1, 200, held());
  await started;
  assert.equal(lab.nodes.get('#state').textContent, 'Held by the client');
  lab.reply(0, 401, null);
  await settle();
  assert.equal(lab.nodes.get('#state').textContent, 'Held by the client');
  assert.equal(lab.button('read').disabled, false);
});

test('one action at a time: a second click while one runs sends nothing', async () => {
  const lab = page();
  const first = lab.button('start').click();
  lab.button('start').click();
  lab.button('read').click();
  assert.equal(lab.requests.length, 2, 'the first read and one start');
  assert.equal(lab.button('status').disabled, true, 'every command is locked meanwhile');
  lab.reply(1, 200, held());
  await first;
  assert.equal(lab.button('status').disabled, false);
});

test("the file server's refusal reads as a refusal, though the client answered 200", async () => {
  const lab = page();
  lab.reply(0, 200, held());
  await settle();
  const read = lab.button('read-draft').click();
  lab.reply(1, 200, { ...held(), event: 'A freshly signed request reached the RS.', status: 403, result: { error: 'request refused' } });
  await read;
  assert.equal(lab.nodes.get('#outcome').textContent, 'Read the draft: refused, the file server answered 403');
  assert.equal(lab.nodes.get('#outcome').dataset.outcome, 'refused');
  assert.match(lab.nodes.get('#result').textContent, /request refused/);
  const accepted = lab.button('read').click();
  lab.reply(2, 200, { ...held(), status: 200, result: { content: 'Synthetic notes' } });
  await accepted;
  assert.equal(lab.nodes.get('#outcome').textContent, 'Read the notes: accepted, the file server answered 200');
  assert.equal(lab.nodes.get('#outcome').dataset.outcome, 'accepted');
});

test('any answer but a session view leaves every fact unknown', async () => {
  const cases = [
    [400, { error: 'session missing or expired' }, 'The client refused: session missing or expired. Check the session state.'],
    [503, { error: 'request refused' }, 'The client gave no usable answer. Check the session state.'],
    [200, undefined, 'The client gave no usable answer. Check the session state.'],
    [200, [held()], 'The client gave no usable answer. Check the session state.'],
  ];
  for (const [status, data, message] of cases) {
    const lab = page();
    lab.reply(0, 200, held({ restrictions: [{ file: 'notes', until: 1 }], next_request_uses: 'restricted' }));
    await settle();
    assert.equal(lab.nodes.get('#next').textContent, 'The token with its restrictive blocks');
    const rotated = lab.button('rotate').click();
    lab.reply(1, status, data);
    await rotated;
    for (const id of ['#next', '#restrictions', '#rotations', '#retired', '#previous']) {
      assert.equal(lab.nodes.get(id).textContent, 'Unknown', `${status} ${id}`);
    }
    assert.equal(lab.nodes.get('#state').textContent, 'Unknown');
    assert.equal(lab.nodes.get('#error').textContent, message);
    assert.equal(lab.button('read').disabled, false, 'the server decides');
  }
  const lab = page();
  const started = lab.button('start').click();
  lab.requests[1].reject(new TypeError('network'));
  await started;
  assert.equal(lab.nodes.get('#state').textContent, 'Unknown');
  assert.match(lab.nodes.get('#error').textContent, /could not be reached/);
});

test('a value the page does not know shows as unknown, prototype names included', async () => {
  const lab = page();
  lab.reply(0, 200, held({
    next_request_uses: 'toString', key_rotations: '1', key_attempts_left: -1,
    retired_token_testable: 'yes', previous_key_testable: null,
    restrictions: [{ file: '__proto__', until: 1 }, { file: 'notes', until: 'soon' }, null],
  }));
  await settle();
  assert.equal(lab.nodes.get('#next').textContent, 'Unknown');
  assert.equal(lab.nodes.get('#rotations').textContent, 'Unknown');
  assert.equal(lab.nodes.get('#retired').textContent, 'Unknown');
  assert.equal(lab.nodes.get('#previous').textContent, 'Unknown');
  const blocks = lab.nodes.get('#restrictions').textContent;
  assert.match(blocks, /^3 of 8 at most: an unknown file until /);
  assert.match(blocks, /the notes until an unknown time/);
  assert.equal(blocks.split('; then ').length, 3);
});

test('the blocks show in order, eight at most, and the rest is counted', async () => {
  const lab = page();
  const restrictions = Array.from({ length: 10 }, (_, i) => ({ file: i % 2 ? 'draft' : 'notes', until: 1_800_000_000 + i }));
  lab.reply(0, 200, held({ restrictions }));
  await settle();
  const blocks = lab.nodes.get('#restrictions').textContent;
  assert.equal(blocks.split('; then ').length, 8);
  assert.ok(blocks.startsWith('10 of 8 at most: the notes until '));
  assert.ok(blocks.endsWith('; and 2 more'));
});

test('a restriction is sent only with a whole number of seconds from 1 to 600', async () => {
  for (const raw of ['', ' ', 'abc', '0', '601', '12.5', '1e2', '-5', '0x10', '1000']) {
    const lab = page();
    lab.nodes.get('#seconds').value = raw;
    await lab.button('attenuate').click();
    assert.equal(lab.requests.length, 1, `${JSON.stringify(raw)} is not sent`);
    assert.equal(lab.nodes.get('#error').textContent, 'Enter a whole number of seconds from 1 to 600.');
  }
  const lab = page();
  lab.nodes.get('#file').value = '__proto__';
  await lab.button('attenuate').click();
  assert.equal(lab.requests.length, 1);
  lab.nodes.get('#file').value = 'draft';
  lab.nodes.get('#seconds').value = ' 30 ';
  const sent = lab.button('attenuate').click();
  assert.deepEqual(JSON.parse(lab.requests[1].options.body), { file: 'draft', seconds: 30 });
  lab.reply(1, 200, held());
  await sent;
});

test("only the file server's body reaches the result block; the view's other members reach nothing", async () => {
  const lab = page();
  lab.reply(0, 200, { event: 'Private session present.', session: { ...VIEW, token: CANARY, restrictions: [{ file: 'notes', until: 1, key: CANARY }] } });
  await settle();
  assert.ok(!lab.all().includes(CANARY));
  const read = lab.button('read').click();
  lab.reply(1, 200, { ...held(), status: 200, result: { content: CANARY } });
  await read;
  assert.ok(lab.nodes.get('#result').textContent.includes(CANARY));
  lab.nodes.get('#result').textContent = '';
  assert.ok(!lab.all().includes(CANARY), 'nowhere else');
});

test('the events stay bounded', async () => {
  const lab = page();
  lab.reply(0, 200, held());
  await settle();
  for (let i = 1; i <= 25; i += 1) {
    const checked = lab.button('status').click();
    lab.reply(i, 200, { ...held(), event: `event ${i}` });
    await checked;
  }
  const events = lab.nodes.get('#events').children.map(item => item.textContent);
  assert.equal(events.length, 20);
  assert.equal(events[19], 'event 25');
});

test('the key line counts rotations and attempts in words', async () => {
  for (const [rotated, left, line] of [
    [0, 3, 'Never rotated; 3 key-generation attempts left'],
    [1, 1, 'Rotated once; 1 key-generation attempt left'],
    [2, 0, 'Rotated 2 times; 0 key-generation attempts left'],
  ]) {
    const lab = page();
    lab.reply(0, 200, held({ key_rotations: rotated, key_attempts_left: left }));
    await settle();
    assert.equal(lab.nodes.get('#rotations').textContent, line);
  }
});

test('the panel says how many blocks a token may still take', async () => {
  const lab = page();
  lab.reply(0, 200, held());
  await settle();
  assert.equal(lab.nodes.get('#restrictions').textContent, 'None yet, of 8 at most');
});

test('only 401 and 403 read as refusals; another status is the server failing to decide', async () => {
  for (const [status, line, kind] of [
    [403, 'Read the notes: refused, the file server answered 403', 'refused'],
    [401, 'Read the notes: refused, the file server answered 401', 'refused'],
    [503, 'Read the notes: not decided, the file server answered 503', 'failed'],
    [500, 'Read the notes: not decided, the file server answered 500', 'failed'],
    [204, 'Read the notes: accepted, the file server answered 204', 'accepted'],
    [42, 'Read the notes: the client relayed no valid status', undefined],
    [700, 'Read the notes: the client relayed no valid status', undefined],
    ['403', 'Read the notes: the client relayed no valid status', undefined],
  ]) {
    const lab = page();
    lab.reply(0, 200, held());
    await settle();
    const read = lab.button('read').click();
    lab.reply(1, 200, { ...held(), status, result: { error: 'request refused' } });
    await read;
    assert.equal(lab.nodes.get('#outcome').textContent, line, String(status));
    assert.equal(lab.nodes.get('#outcome').dataset.outcome, kind, String(status));
  }
});

