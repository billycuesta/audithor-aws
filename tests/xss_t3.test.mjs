import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { makeDom, assertNoInjection, clickAll, benignText, tagSequence, PAYLOADS } from './helpers/xss_payloads.mjs';

const dom = makeDom('<input id="access-key-input" value="key"><input id="secret-key-input" value="secret"><input id="session-token-input"><div id="playground-view"></div>');
window.allAvailableRegions = [];
const baselineUrl = pathToFileURL(`${process.cwd()}/tests/baseline/audithor_project/static/js/views/16_playground.js`).href;
const currentUrl = pathToFileURL(`${process.cwd()}/audithor_project/static/js/views/16_playground.js`).href;
const baseline = await import(baselineUrl);
const current = await import(currentUrl);
const fetchCalls = [];
const makeResponse = payload => async url => {
  fetchCalls.push(String(url));
  return { ok: true, json: async () => ({ results: payload.path }) };
};

async function render(module, payload) {
  window.playgroundApiData = null;
  globalThis.fetch = makeResponse(payload);
  document.getElementById('playground-view').replaceChildren();
  module.buildPlaygroundView();
  document.getElementById('pg-source-arn').value = 'arn:source';
  document.getElementById('pg-target-arn').value = 'arn:target';
  document.getElementById('pg-run-analysis-btn').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  return {
    path: document.getElementById('playground-results-container'),
    root: document.getElementById('playground-view')
  };
}

const benign = {
  path: { status: 'REACHABLE', reason: '', tables: ['route summary one', 'route summary two'], detail_tables: { 'resource-1': 'resource detail' } }
};
const baselineRendered = await render(baseline, benign);
baselineRendered.root.querySelector('[data-tab="pg-sslscan-content"]')?.remove();
baselineRendered.root.querySelector('#pg-sslscan-content')?.remove();
const currentRendered = await render(current, benign);
assert.deepEqual(tagSequence(currentRendered.root), tagSequence(baselineRendered.root));
assert.equal(benignText(currentRendered.root), benignText(baselineRendered.root));
assert.deepEqual(tagSequence(currentRendered.path), tagSequence(baselineRendered.path));
assert.equal(benignText(currentRendered.path), benignText(baselineRendered.path));
assert.ok(currentRendered.path.querySelector('.bg-green-50'));
assert.doesNotMatch(currentRendered.root.textContent, /ssl scan/i);
assert.equal([...currentRendered.root.querySelectorAll('*')].some(element => /sslscan/i.test(element.id) || /sslscan/i.test(element.textContent)), false);
assert.equal(fetchCalls.some(url => /sslscan/i.test(url)), false);

for (const payload of PAYLOADS) {
  const hostile = {
    path: { status: 'UNREACHABLE', reason: payload, tables: [payload, payload], detail_tables: { [payload]: payload } }
  };
  const rendered = await render(current, hostile);
  assertNoInjection(window, rendered.root);
  assertNoInjection(window, rendered.path);
  clickAll(window, rendered.root);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(fetchCalls.some(url => /sslscan/i.test(url)), false);
}
dom.window.close();
console.log('Playground rendered parity and payload checks passed');
