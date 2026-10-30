import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { makeDom, assertNoInjection, clickAll, benignText, tagSequence, PAYLOADS } from './helpers/xss_payloads.mjs';

const dom = makeDom('<input id="access-key-input" value="key"><input id="secret-key-input" value="secret"><input id="session-token-input"><div id="playground-view"></div>');
window.allAvailableRegions = [];
const baselineUrl = pathToFileURL(`${process.cwd()}/tests/baseline/audithor_project/static/js/views/16_playground.js`).href;
const currentUrl = pathToFileURL(`${process.cwd()}/audithor_project/static/js/views/16_playground.js`).href;
const baseline = await import(baselineUrl);
const current = await import(currentUrl);
const makeResponse = payload => async url => ({
  ok: true,
  json: async () => String(url).includes('sslscan')
    ? { results: payload.sslscan }
    : { results: payload.path }
});

async function render(module, payload) {
  window.playgroundApiData = null;
  globalThis.fetch = makeResponse(payload);
  document.getElementById('playground-view').replaceChildren();
  module.buildPlaygroundView();
  document.getElementById('pg-source-arn').value = 'arn:source';
  document.getElementById('pg-target-arn').value = 'arn:target';
  document.getElementById('pg-sslscan-target').value = 'one.example,two.example';
  document.getElementById('pg-run-analysis-btn').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  document.getElementById('pg-run-sslscan-btn').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  return {
    path: document.getElementById('playground-results-container'),
    ssl: document.getElementById('sslscan-results-container'),
    root: document.getElementById('playground-view')
  };
}

const benign = {
  path: { status: 'REACHABLE', reason: '', tables: ['route summary one', 'route summary two'], detail_tables: { 'resource-1': 'resource detail' } },
  sslscan: [{ target: 'one.example', error: '', output: 'scan details' }, { target: 'two.example', error: 'Target is not a valid hostname or IP address with an optional port.', output: '' }]
};
const baselineRendered = await render(baseline, benign);
const currentRendered = await render(current, benign);
assert.deepEqual(tagSequence(currentRendered.path), tagSequence(baselineRendered.path));
assert.equal(benignText(currentRendered.path), benignText(baselineRendered.path));
assert.deepEqual(tagSequence(currentRendered.ssl), tagSequence(baselineRendered.ssl));
assert.equal(benignText(currentRendered.ssl), benignText(baselineRendered.ssl));
assert.ok(currentRendered.path.querySelector('.bg-green-50'));
assert.ok(currentRendered.ssl.querySelector('pre'));

for (const payload of PAYLOADS) {
  const hostile = {
    path: { status: 'UNREACHABLE', reason: payload, tables: [payload, payload], detail_tables: { [payload]: payload } },
    sslscan: [{ target: payload, error: payload, output: payload }, { target: payload, error: '', output: payload }]
  };
  const rendered = await render(current, hostile);
  assertNoInjection(window, rendered.root);
  assertNoInjection(window, rendered.path);
  assertNoInjection(window, rendered.ssl);
  clickAll(window, rendered.root);
}
dom.window.close();
console.log('Playground rendered parity and payload checks passed');
