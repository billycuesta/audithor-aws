import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="inspector-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
window.scopedResources = {};
window.securityHubApiData = null;
const root = new URL('../audithor/static/js/views/', import.meta.url).href;
const inspector = await import(root + '08_inspector.js');
const metadata = { executionDate: '2026-01-01' };
const view = document.getElementById('inspector-view');
window.inspectorApiData = { metadata, results: { findings: [], findingsStatus: 'not_run', scan_status: [
    { Region: 'us-east-1', InspectorStatus: 'ENABLED', ScanEC2: 'ENABLED', ScanECR: 'DISABLED', ScanLambda: 'ENABLED',
      Coverage: [
          { resourceType: '<img src=x onerror=alert(1)>', resourceId: 'i-1234567890', scanType: 'NETWORK', scanStatus: 'ACTIVE', lastScannedAt: '2026-01-01' },
          { resourceType: 'AWS_EC2_INSTANCE', resourceId: 'i-0987654321', scanType: 'PACKAGE', scanStatus: 'INACTIVE', reason: 'not enabled' }
      ], Enrichment: { coverage: { status: 'complete' } } },
    { Region: 'eu-west-1', InspectorStatus: 'ENABLED', ScanEC2: 'ENABLED', ScanECR: 'UNKNOWN', ScanLambda: 'UNKNOWN',
      Coverage: [], Enrichment: { coverage: { status: 'failed', reason: 'permission_denied' } } }
] } };
inspector.buildInspectorView();
assert.match(view.textContent, /Covered: 1 · Not covered: 1/);
assert.match(view.textContent, /Not collected: eu-west-1 \(permission_denied\)/);
assert.equal(view.querySelector('.mt-6 tbody tr td:last-child').textContent, '-');
assert.match(view.textContent, /<img src=x onerror=alert\(1\)>/);
assert.match(view.textContent, /i-1234567890/);
assert.match(view.textContent, /NETWORK/);
assert.match(view.textContent, /ACTIVE/);
assert.equal(view.querySelector('img'), null);
window.inspectorApiData = { metadata, results: { findings: [], scan_status: [{ Region: 'us-east-1', InspectorStatus: 'ENABLED', ScanEC2: 'ENABLED', ScanECR: 'UNKNOWN', ScanLambda: 'UNKNOWN', Coverage: [], Enrichment: { coverage: { status: 'complete' } } }] } };
inspector.buildInspectorView();
assert.match(view.textContent, /No resources reported/);
window.inspectorApiData = { metadata, results: { findings: [], scan_status: [{ Region: 'us-east-1', InspectorStatus: 'ENABLED', ScanEC2: 'ENABLED', ScanECR: 'UNKNOWN', ScanLambda: 'UNKNOWN' }] } };
inspector.buildInspectorView();
assert.match(view.textContent, /Not collected/);
assert.doesNotMatch(view.textContent, /No resources reported/);
console.log('Inspector coverage view checks passed');
