import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="iam-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
window.securityHubApiData = {results: {findings: {iamFindings: []}}};
window.iamApiData = {metadata: {accountId: '111111111111'}, results: {users: [], groups: [], roles: [], password_policy: {Error: 'not configured'}, region_guardrails: {
    OrganizationId: 'o-example', Enrichment: {regionGuardrails: {status: 'complete'}}, Policies: [{
        PolicyId: 'p-example', Name: 'Region policy', AllowedRegions: ['us-east-1'], DeniedRegions: ['ap-east-1'],
        ExemptActions: ['iam:*'], Targets: [{TargetId: 'ou-root', Name: '<img src=x onerror=alert(1)>', Type: 'ROOT'}]
    }]
}}};
const { buildIamView } = await import(new URL('../audithor/static/js/views/01_iam.js', import.meta.url));
buildIamView();
const root = document.getElementById('iam-view');
assert.ok(root.textContent.includes('Region guardrails'));
assert.ok(root.textContent.includes('us-east-1'));
assert.ok(root.textContent.includes('ap-east-1'));
assert.ok(root.textContent.includes('iam:*'));
assert.ok(root.textContent.includes('p-example'));
const cells = [...root.querySelectorAll('#resumen-content section table tbody tr td')].map(cell => cell.textContent.trim());
assert.deepEqual(cells, ['Region policy (p-example)', 'us-east-1', 'ap-east-1', '<img src=x onerror=alert(1)> (ROOT)', 'iam:*']);
assert.ok(root.textContent.includes('<img src=x onerror=alert(1)>'));
assert.equal(root.querySelector('img'), null);
window.iamApiData.results.region_guardrails.Policies = [{PolicyId: 'p-empty', Name: 'Empty SCP', AllowedRegions: [], DeniedRegions: [], ExemptActions: [], Targets: []}];
buildIamView();
const emptyCells = [...root.querySelectorAll('#resumen-content section table tbody tr td')].map(cell => cell.textContent.trim());
assert.deepEqual(emptyCells, ['Empty SCP (p-empty)', 'None', 'None', 'None', 'None']);
window.iamApiData.results.region_guardrails.Policies = [];
buildIamView();
assert.ok(root.textContent.includes('No region-restricting SCP found'));
window.iamApiData = {metadata: {}, results: {users: [], groups: [], roles: [], password_policy: {Error: 'not configured'}, region_guardrails: {Enrichment: {regionGuardrails: {status: 'skipped', reason: 'organizations_not_in_use'}}}}};
buildIamView();
assert.ok(root.textContent.includes('Not collected: organizations_not_in_use'));
window.iamApiData = {metadata: {}, results: {users: [], groups: [], roles: [], password_policy: {Error: 'not configured'}}};
buildIamView();
assert.ok(root.textContent.includes('Not collected'));
console.log('IAM region guardrail view checks passed');
