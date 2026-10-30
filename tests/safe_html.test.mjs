import assert from 'node:assert/strict';
import { makeDom, PAYLOADS } from './helpers/xss_payloads.mjs';
import { SafeHtml, escapeHtml, html, raw, join, setHtml, act, actOn, ACT_THIS, installActionDelegation } from '../audithor/static/js/safe_html.js';

for (const payload of PAYLOADS) {
  assert.equal(escapeHtml(payload), payload.replace(/[&<>\"'`]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', "'": '&#39;', '`': '&#96;' })[char]));
  assert.equal(String(html`<span>${payload}</span>`), `<span>${escapeHtml(payload)}</span>`);
}
const nested = html`<b>${'<nested>'}</b>`;
assert.equal(String(html`<p>${nested}</p>`), '<p><b>&lt;nested&gt;</b></p>');
assert.equal(String(html`${[1, null, false, html`<b>ok</b>`]}`), '1<b>ok</b>');
assert.equal(String(html`${null}${undefined}${false}`), '');
assert.equal(String(raw('<b>trusted</b>')), '<b>trusted</b>');
assert.equal(String(join(['a', null, '<b>'], ',')), 'a,,&lt;b&gt;');
assert.equal(`x${html`<b>y</b>`}`, 'x<b>y</b>');
const dom = makeDom('<main></main>');
assert.throws(() => setHtml(dom.window.document.querySelector('main'), '<b>x</b>'), TypeError);
const target = dom.window.document.querySelector('main');
let received;
dom.window.receiveArguments = (...args) => { received = args; };
target.innerHTML = `<button ${act('receiveArguments', ...PAYLOADS)}>Open</button>`;
installActionDelegation(dom.window.document);
installActionDelegation(dom.window.document);
target.querySelector('button').click();
assert.deepEqual(received, PAYLOADS);
assert.throws(() => act('bad-name'), TypeError);
assert.throws(() => act('receiveArguments', () => {}), TypeError);
assert.throws(() => act('receiveArguments', 1n), TypeError);
target.innerHTML = `<button ${actOn('change', 'receiveArguments', 'x')}>Change</button>`;
target.querySelector('button').dispatchEvent(new dom.window.Event('change', { bubbles: true }));
assert.deepEqual(received, ['x']);
let clickedElement;
dom.window.captureElement = (...args) => { clickedElement = args; };
target.innerHTML = `<button ${act('captureElement', ACT_THIS, '$act', { $act: 'this', untrusted: true })}>Capture</button>`;
const actionButton = target.querySelector('button');
actionButton.click();
assert.equal(clickedElement[0], actionButton);
assert.equal(clickedElement[1], '$act');
assert.deepEqual(clickedElement[2], { $act: 'this', untrusted: true });
// Only the exact dedicated marker can be replaced; untrusted values here are not that marker, and AWS interpolation is string-only.
received = null;
for (const [markup, name] of [
  ['<button data-act="missing" data-args="[]"></button>', 'missing'],
  ['<button data-act="receiveArguments" data-args="{}"></button>', 'receiveArguments'],
  ['<button data-act="bad-name" data-args="[]"></button>', 'bad-name'],
  ['<button data-act="notCallable" data-args="[]"></button>', 'notCallable'],
  ['<button data-act="eval" data-args="[]"></button>', 'eval'],
  ['<button data-act="constructor" data-args="[]"></button>', 'constructor'],
  ['<button data-act="setTimeout" data-args="[]"></button>', 'setTimeout']
]) {
  if (name === 'notCallable') dom.window[name] = 3;
  else if (name === 'receiveArguments') dom.window.receiveArguments = (...args) => { received = args; };
  else delete dom.window[name];
  received = null;
  target.innerHTML = markup;
  target.querySelector('button').click();
  assert.equal(received, null);
}
const windowPrototype = Object.getPrototypeOf(dom.window);
let inheritedCalled = false;
windowPrototype.inheritedAction = () => { inheritedCalled = true; };
target.innerHTML = '<button data-act="inheritedAction" data-args="[]"></button>';
target.querySelector('button').click();
assert.equal(inheritedCalled, false);
delete windowPrototype.inheritedAction;
let nestedCalls = [];
dom.window.innerAction = () => nestedCalls.push('inner');
dom.window.outerAction = () => nestedCalls.push('outer');
target.innerHTML = `<button ${act('outerAction')}><span ${act('innerAction')}>Nested</span></button>`;
target.querySelector('span').click();
assert.deepEqual(nestedCalls, ['inner']);
let listenerCount = 0;
const root = { contains: () => true, addEventListener() { listenerCount++; } };
installActionDelegation(root);
installActionDelegation(root);
assert.equal(listenerCount, 3);
console.log('safe_html tests passed');
