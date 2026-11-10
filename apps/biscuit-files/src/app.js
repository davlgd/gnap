'use strict';
// The Biscuit files page. It sends one action at a time and shows the client's
// closed description of the session it holds. Words for closed values come
// from the tables below; the server's own sentences go in as text only, and a
// file server's answer only goes in the result block.

const STATES = { held: 'Held by the client', none: 'No session', unknown: 'Unknown' };
const NEXT = {
  restricted: 'The token with its restrictive blocks',
  issued: 'The token as issued',
  none: 'No token to present',
};
const FILES = { notes: 'the notes', draft: 'the draft' };
// The client's own bound on the restrictive blocks of a token.
const MAX_BLOCKS_SHOWN = 8;
const MAX_EVENTS = 20;

const buttons = [...document.querySelectorAll('button[data-action]')];
const node = selector => document.querySelector(selector);
let known = 'unknown';
let busy = false;
let generation = 0;

const count = value => Number.isInteger(value) && value >= 0;
const label = (table, value) => (Object.hasOwn(table, value) ? table[value] : 'Unknown');

function setState(state) {
  known = Object.hasOwn(STATES, state) ? state : 'unknown';
  node('#state').textContent = STATES[known];
  node('#state').dataset.state = known;
}

// The facts of a session the client holds, or Unknown for each.
function renderView(view) {
  const valid = view !== null && typeof view === 'object' && !Array.isArray(view);
  setState(valid ? 'held' : 'unknown');
  const facts = valid ? view : {};
  node('#next').textContent = label(NEXT, facts.next_request_uses);
  node('#restrictions').textContent = blocks(facts.restrictions);
  node('#rotations').textContent = count(facts.key_rotations) && count(facts.key_attempts_left)
    ? `${rotations(facts.key_rotations)}; ${facts.key_attempts_left} key-generation ${facts.key_attempts_left === 1 ? 'attempt' : 'attempts'} left`
    : 'Unknown';
  node('#retired').textContent = facts.retired_token_testable === true ? 'Kept, and can be presented'
    : facts.retired_token_testable === false ? 'None yet' : 'Unknown';
  node('#previous').textContent = facts.previous_key_testable === true ? 'Can sign a request for the current token'
    : facts.previous_key_testable === false ? 'Nothing to test now' : 'Unknown';
}

const rotations = n => (n === 0 ? 'Never rotated' : n === 1 ? 'Rotated once' : `Rotated ${n} times`);

function blocks(list) {
  if (!Array.isArray(list)) return 'Unknown';
  if (list.length === 0) return `None yet, of ${MAX_BLOCKS_SHOWN} at most`;
  const shown = list.slice(0, MAX_BLOCKS_SHOWN).map(block => {
    const file = block !== null && typeof block === 'object' && Object.hasOwn(FILES, block.file) ? FILES[block.file] : 'an unknown file';
    const until = block !== null && typeof block === 'object' && count(block.until)
      ? new Date(block.until * 1000).toLocaleTimeString() : 'an unknown time';
    return `${file} until ${until}`;
  });
  const more = list.length > MAX_BLOCKS_SHOWN ? `; and ${list.length - MAX_BLOCKS_SHOWN} more` : '';
  return `${list.length} of ${MAX_BLOCKS_SHOWN} at most: ${shown.join('; then ')}${more}`;
}

// Nothing is known any more: the client may have acted before it failed.
function unknown(message) {
  renderView(null);
  node('#error').textContent = message;
}

function event(text) {
  if (typeof text !== 'string') return;
  const item = document.createElement('li');
  item.textContent = text;
  const list = node('#events');
  list.append(item);
  while (list.children.length > MAX_EVENTS) list.children[0].remove();
}

// Only 401 and 403 are refusals of access; another failure is the server's
// own, such as a 503 when it can't reach the authorization server.
const OUTCOMES = { accepted: 'accepted', refused: 'refused', failed: 'not decided' };
function outcomeOf(status) {
  if (!Number.isInteger(status) || status < 100 || status > 599) return 'unknown';
  if (status >= 200 && status < 300) return 'accepted';
  return status === 401 || status === 403 ? 'refused' : 'failed';
}

// The file server's answer, which the client relays inside its own, under
// the name of the button that asked for it.
function renderResource(data, asked) {
  if (!Object.hasOwn(data, 'status')) return;
  const outcome = node('#outcome');
  const kind = outcomeOf(data.status);
  outcome.textContent = kind === 'unknown'
    ? `${asked}: the client relayed no valid status`
    : `${asked}: ${OUTCOMES[kind]}, the file server answered ${data.status}`;
  if (kind === 'unknown') delete outcome.dataset.outcome; else outcome.dataset.outcome = kind;
  node('#result').textContent = JSON.stringify(data.result ?? null, null, 2);
}

// A known absence of session leaves only the start and the check.
function unlock() {
  for (const button of buttons) {
    button.disabled = known === 'none' && !['start', 'status'].includes(button.dataset.action);
  }
}

// The client's answer, read whole before anything is shown.
async function read(response) {
  let data = null;
  try { data = await response.json(); } catch { data = null; }
  return { status: response.status, data };
}

// What the client answered. Its HTTP status is the client's, never the file
// server's: a refused file request still arrives in a 200.
function show({ status, data }, asked) {
  const object = data !== null && typeof data === 'object' && !Array.isArray(data);
  if (status === 200 && object) {
    node('#error').textContent = '';
    renderView(data.session);
    event(data.event);
    renderResource(data, asked);
  } else if (status === 401) {
    renderView(null);
    setState('none');
    node('#error').textContent = 'No session for this browser: start one.';
  } else if (status === 400 && object && typeof data.error === 'string') {
    unknown(`The client refused: ${data.error}. Check the session state.`);
  } else {
    unknown('The client gave no usable answer. Check the session state.');
  }
}

function body(action) {
  if (action !== 'attenuate') return {};
  const raw = node('#seconds').value.trim();
  const seconds = /^[0-9]{1,3}$/.test(raw) ? Number(raw) : NaN;
  if (!(seconds >= 1 && seconds <= 600)) throw new RangeError('Enter a whole number of seconds from 1 to 600.');
  const file = node('#file').value;
  if (!Object.hasOwn(FILES, file)) throw new RangeError('Choose the notes or the draft.');
  return { file, seconds };
}

for (const button of buttons) {
  button.addEventListener('click', async () => {
    if (busy) return;
    const action = button.dataset.action;
    let payload;
    try { payload = body(action); } catch (error) { node('#error').textContent = error.message; return; }
    busy = true;
    generation += 1;
    for (const item of buttons) item.disabled = true;
    try {
      const response = await fetch(`/action/${action}`, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload),
      });
      show(await read(response), button.textContent);
    } catch {
      unknown('The client could not be reached. Check that the three services are available, then check the session state.');
    } finally {
      busy = false;
      unlock();
    }
  });
}

// One status read when the page opens, and none after: each read counts
// against the session's operations. An action started meanwhile wins.
(async () => {
  const opened = generation;
  try {
    const response = await fetch('/action/status', {
      method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    const answered = await read(response);
    if (opened !== generation || busy) return;
    show(answered, 'Session state');
    // Opening the page without a session isn't an error.
    if (known === 'none') node('#error').textContent = '';
  } catch {
    if (opened === generation && !busy) unknown('The client could not be reached. Check the session state.');
  }
  if (opened === generation && !busy) unlock();
})();
