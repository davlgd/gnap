'use strict';
let ticket = document.body.dataset.ticket;
let busy = false;
const consent = document.querySelector('#consent');
async function submit(path, payload) {
  if (busy) return;
  busy = true;
  document.querySelector('#error').textContent = '';
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try {
    const response = await fetch(path, {method: 'POST', credentials: 'same-origin', headers: {'content-type': 'application/json'}, body: JSON.stringify({ticket, ...payload})});
    const data = await response.json();
    if (data.ticket) ticket = data.ticket;
    if (Number.isInteger(data.remaining)) document.querySelector('#remaining').textContent = `${data.remaining} attempts remain. Invalid submissions and decisions count too.`;
    if (!response.ok) {
      consent.hidden = true;
      throw new Error(data.error || 'The request could not be completed. Reload before trying again.');
    }
    if (data.rights) {
      const list = document.querySelector('#rights'); list.replaceChildren();
      for (const slot of data.rights) { const item = document.createElement('li'); item.textContent = `${slot.label || 'Access token'}: ${(slot.rights || []).join(', ')}`; list.append(item); }
      consent.hidden = false;
    }
    if (data.complete) {
      consent.hidden = true;
      document.querySelector('#lookup').hidden = true;
      document.querySelector('#result').textContent = 'Your decision is recorded. Return to the first screen and poll for the result.';
    }
  } catch (e) { document.querySelector('#error').textContent = e.message; }
  finally { busy = false; for (const button of document.querySelectorAll('button')) button.disabled = false; }
}
document.querySelector('#lookup').addEventListener('submit', event => {
  event.preventDefault();
  const code = document.querySelector('#code').value;
  document.querySelector('#code').value = '';
  submit('/code/lookup', {code});
});
for (const button of document.querySelectorAll('[data-choice]')) button.addEventListener('click', () => submit('/code/consent', {choice: button.dataset.choice}));
