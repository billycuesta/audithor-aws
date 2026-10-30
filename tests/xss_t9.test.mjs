import assert from 'node:assert/strict';
import { makeDom, PAYLOADS, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';

const root = new URL('../audithor/static/js/views/', import.meta.url).href;
const baselineRoot = new URL('./baseline/audithor_project/static/js/views/', import.meta.url).href;
const dom = makeDom('<div id="config-sh-view"></div><div id="inventory-view"></div>');
const { window } = dom;
window.scopedResources = {};
globalThis.fetch = window.fetch = async () => ({ ok: true, json: async () => ({ results: { findings: [], service_status: [] }, metadata: { executionDate: '2026-10-25' } }) });
window.runAndDisplayHealthyStatus = () => {};
window.handleTabClick = () => () => {};
const inventory = await import(root + '21_inventory.js');
const config = await import(root + '15_config_sh.js');
const baselineInventory = await import(baselineRoot + '21_inventory.js');
const baselineConfig = await import(baselineRoot + '15_config_sh.js');

function assertNoLiteralMarkup(root) {
  assert.doesNotMatch(root.textContent, /<(?:div|td|tr|span|pre)\b|<\//i);
}
function cloneWithStrings(value, replacement) {
  if (typeof value === 'string') return replacement;
  if (Array.isArray(value)) return value.map(item => cloneWithStrings(item, replacement));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, cloneWithStrings(item, replacement)]));
  return value;
}
function snapshot(root) { return [benignText(root), tagSequence(root)]; }
function normalizeElementBoundaries(root) {
  const visit = parent => {
    for (const child of [...parent.children]) {
      visit(child);
      if (child.nextSibling && child.nextSibling.nodeType === 1) parent.insertBefore(document.createTextNode(' '), child.nextSibling);
    }
  };
  visit(root);
}
function assertParity(render, baselineRender, root) {
  root.replaceChildren();
  render();
  assertNoLiteralMarkup(root);
  normalizeElementBoundaries(root);
  const actual = snapshot(root);
  root.replaceChildren();
  baselineRender();
  assertNoLiteralMarkup(root);
  normalizeElementBoundaries(root);
  const expected = snapshot(root);
  assert.deepEqual(actual, expected);
}

const inventoryFixture = {
  ec2_instances: { total: 2, by_region: { 'us-east-1': 2, Global: 1 } },
  s3_buckets: { total: 1, by_region: { 'us-east-1': 1 } },
  lambda_functions: { total: 3, by_region: { 'us-west-2': 3 } }
};
window.inventoryApiData = { results: inventoryFixture };
assertParity(() => inventory.buildInventoryView(), () => baselineInventory.buildInventoryView(), document.querySelector('#inventory-view'));

const finding = {
  Title: 'Benign finding', Description: 'Benign description', GeneratorId: 'security-control/test',
  ProductName: 'Security Hub', ProductFields: { StandardsArn: 'arn:aws:securityhub:::ruleset/cis' },
  Severity: { Label: 'HIGH' }, Compliance: { Status: 'FAILED' }, Region: 'us-east-1',
  AwsAccountId: '123456789012', CreatedAt: '2026-10-25T00:00:00Z', UpdatedAt: '2026-10-25T00:00:00Z',
  Resources: [{ Type: 'AwsS3Bucket', Id: 'bucket-one' }],
  Remediation: { Recommendation: { Text: 'Review configuration', Url: 'https://example.com/guide' } }
};
const configFixture = {
  metadata: { executionDate: '2026-10-25' },
  results: { findings: [finding], service_status: [{ Region: 'us-east-1', ConfigEnabled: true, SecurityHubEnabled: true,
    EnabledStandards: ['arn:aws:securityhub:::standards/cis'], EnabledConformancePacks: ['baseline-pack'] }] }
};
window.configSHApiData = configFixture;
window.configSHStatusApiData = configFixture;
const configRoot = document.querySelector('#config-sh-view');
assertParity(() => config.buildConfigSHView(), () => baselineConfig.buildConfigSHView(), configRoot);
await new Promise(resolve => setTimeout(resolve, 80));
assertNoLiteralMarkup(configRoot);
assert.equal(configRoot.querySelectorAll('.finding-row').length, 1);
configRoot.querySelector('.finding-row').click();
await new Promise(resolve => setTimeout(resolve, 20));
assertNoLiteralMarkup(configRoot);
assert.match(configRoot.querySelector('#modal-body').textContent, /Benign description/);
normalizeElementBoundaries(configRoot);
const convertedModalSnapshot = snapshot(configRoot);
configRoot.replaceChildren();
window.configSHApiData = configFixture;
window.configSHStatusApiData = configFixture;
baselineConfig.buildConfigSHView();
await new Promise(resolve => setTimeout(resolve, 80));
configRoot.querySelector('.finding-row').click();
await new Promise(resolve => setTimeout(resolve, 20));
assertNoLiteralMarkup(configRoot);
normalizeElementBoundaries(configRoot);
assert.deepEqual(convertedModalSnapshot, snapshot(configRoot));

const inventoryRoot = document.querySelector('#inventory-view');
for (const payload of PAYLOADS) {
  window.inventoryApiData = { results: cloneWithStrings(inventoryFixture, payload) };
  inventory.buildInventoryView();
  assertNoInjection(window, inventoryRoot);
  clickAll(window, inventoryRoot);
  window.configSHApiData = cloneWithStrings(configFixture, payload);
  window.configSHStatusApiData = cloneWithStrings(configFixture, payload);
  config.buildConfigSHView();
  assertNoInjection(window, configRoot);
  clickAll(window, configRoot);
}

// Exercise the finding-details modal opener with each payload while retaining actionable control fields.
for (const payload of PAYLOADS) {
  const payloadFinding = { ...finding, Title: payload, Description: payload, AwsAccountId: payload, Region: payload,
    Resources: [{ Type: payload, Id: payload }], Remediation: { Recommendation: { Text: payload, Url: 'https://example.com/guide' } } };
  window.configSHApiData = { ...configFixture, results: { ...configFixture.results, findings: [payloadFinding] } };
  window.configSHStatusApiData = configFixture;
  config.buildConfigSHView();
  await new Promise(resolve => setTimeout(resolve, 60));
  const row = configRoot.querySelector('.finding-row');
  assert.ok(row, 'payload fixture retains a clickable finding row');
  row.click();
  await new Promise(resolve => setTimeout(resolve, 20));
  assertNoInjection(window, configRoot);
  clickAll(window, configRoot);
}

// Exercise the run-analysis button and its click-triggered result renderer in both versions.
window.configSHApiData = null;
window.configSHStatusApiData = null;
config.buildConfigSHView();
const scanButton = configRoot.querySelector('#run-deep-scan-btn');
assert.ok(scanButton);
scanButton.click();
await new Promise(resolve => setTimeout(resolve, 30));
assertNoLiteralMarkup(configRoot);
normalizeElementBoundaries(configRoot);
const convertedScanSnapshot = snapshot(configRoot);
window.configSHApiData = null;
window.configSHStatusApiData = null;
configRoot.replaceChildren();
baselineConfig.buildConfigSHView();
configRoot.querySelector('#run-deep-scan-btn').click();
await new Promise(resolve => setTimeout(resolve, 30));
assertNoLiteralMarkup(configRoot);
normalizeElementBoundaries(configRoot);
assert.deepEqual(convertedScanSnapshot, snapshot(configRoot));
console.log('T9 Config/Security Hub and inventory parity/XSS checks passed');
