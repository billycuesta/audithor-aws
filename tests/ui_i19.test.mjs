import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const template = readFileSync(new URL('../audithor/templates/dashboard.html', import.meta.url), 'utf8');
const dom = new JSDOM(template);
const { document } = dom.window;
for (const id of ['landing-aws-profile-refresh', 'aws-profile-refresh']) {
  const button = document.getElementById(id);
  assert(button, `${id} exists`);
  const svg = button.querySelector('svg');
  assert.equal(svg?.getAttribute('fill'), 'currentColor');
  assert(svg.classList.contains('w-5') && svg.classList.contains('h-5'));
  assert(button.classList.contains(id.startsWith('landing') ? 'text-white' : 'text-[#204071]'));
}
const downloadPaths = [...document.querySelector('#export-results-button svg').querySelectorAll('path')].map(path => path.getAttribute('d'));
assert.deepEqual(downloadPaths, [
  'M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5',
  'M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 9.293V1.5a.5.5 0 0 0-1 0v7.793L5.354 7.146a.5.5 0 1 0-.708.708z'
]);
const links = [...document.querySelectorAll('#sidebar-nav a')];
assert.equal(links[0].dataset.view, 'inventory');
assert(links[0].classList.contains('bg-[#eb3496]'));
const app = readFileSync(new URL('../audithor/static/js/app.js', import.meta.url), 'utf8');
assert.match(app, /const DEFAULT_VIEW = ['"]inventory['"]/);
assert.match(app, /safeRender\(DEFAULT_VIEW,\s*buildInventoryView\)/);
assert.doesNotMatch(app, /data-view=\\?['"]iam['"][^\n]*bg-\\?\[#eb3496\]/);

const collectionSource = readFileSync(new URL('../audithor/static/js/collection.js', import.meta.url), 'utf8');
const { coverageMessage, renderCollectionNotice, mergeInspectorCoverage } = await import(`data:text/javascript;base64,${Buffer.from(collectionSource).toString('base64')}`);
globalThis.document = document;
const dataFor = status => ({ results: { _collection: { status, coverageKnown: true, units: [] } } });
const host = document.createElement('div');
for (const [status, expectedClass] of [['complete', null], ['partial', 'bg-yellow-50'], ['failed', 'bg-red-50'], ['not_applicable', 'text-gray-500']]) {
  host.replaceChildren();
  renderCollectionNotice(host, dataFor(status));
  const notice = host.querySelector('[data-collection-notice]');
  if (expectedClass) assert(notice.classList.contains(expectedClass), `${status} notice style`);
  else assert(!notice || !notice.classList.contains('bg-yellow-50'), 'complete has no warning box');
}
const regionSkips = Array.from({ length: 18 }, (_, index) => ({ service: 'ec2', region: `region-${index}`, operation: 'region_selection', status: 'skipped', category: 'region_not_enabled' }));
host.replaceChildren();
renderCollectionNotice(host, { results: { _collection: { status: 'partial', coverageKnown: true, units: regionSkips } } });
assert.match(host.textContent, /18 regions skipped \(not enabled in this account\)/);
assert.equal(host.querySelectorAll('[data-region-skip-summary]').length, 1);
const merged = mergeInspectorCoverage({ status: 'complete', coverageKnown: true, units: [{ operation: 'batch_get_account_status', status: 'complete' }] }, { status: 'not_applicable', coverageKnown: false, units: [], findingsStatus: 'not_run' });
assert.equal(merged.status, 'complete');
assert.doesNotMatch(coverageMessage({ results: { _collection: merged } }), /No applicable/);
console.log('I19 UI checks passed');
