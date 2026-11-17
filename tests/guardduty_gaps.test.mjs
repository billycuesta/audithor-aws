import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="guardduty-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
const root = new URL('../audithor/static/js/views/', import.meta.url).href;
const view = await import(root + '03_guardduty.js');
const metadata = { executionDate: '2026-01-02' };
window.guarddutyApiData = { metadata, results: { status: [{
    Region: 'us-east-1', Status: 'Enabled', 'S3 Logs': 'Enabled', 'Kubernetes Logs': 'N/A',
    'EC2 Malware Protection': 'Enabled', 'EKS Malware Protection': 'N/A',
    Features: [{ Name: 'LAMBDA_NETWORK_LOGS', Status: 'ENABLED', AdditionalConfiguration: [{ Name: 'EKS_ADDON_MANAGEMENT', Status: 'ENABLED' }, { Name: '<img src=x onerror=alert(1)>', Status: 'ENABLED' }] }], Enrichment: { features: { status: 'complete' } }
}], findings: [{ SeverityScore: 7, SeverityLabel: 'HIGH', Region: 'us-east-1', Title: 'Probe', Resource: 'Instance - ID: i-1', LastSeen: '2026-01-02', Source: 'GuardDuty API', CollectedAt: '2026-01-02T00:00:00+00:00' }] } };
view.buildGuarddutyView();
const statusTab = document.getElementById('gd-status-content');
assert.match(statusTab.textContent, /LAMBDA_NETWORK_LOGS/);
assert.match(statusTab.textContent, /ENABLED/);
assert.match(statusTab.textContent, /EKS_ADDON_MANAGEMENT: ENABLED/);
assert.equal(statusTab.querySelector('img'), null);
assert.match(document.getElementById('gd-findings-table-container').textContent, /GuardDuty API/);
assert.match(document.getElementById('gd-findings-table-container').textContent, /2026-01-02T00:00:00\+00:00/);

window.guarddutyApiData = { metadata, results: { status: [{ Region: 'us-east-1', Status: 'Enabled', 'S3 Logs': 'Enabled', 'Kubernetes Logs': 'N/A', 'Malware Protection': 'Enabled' }], findings: [{ SeverityScore: 1, SeverityLabel: 'LOW', Region: 'us-east-1', Title: 'Legacy', Resource: 'N/A', LastSeen: 'N/A' }] } };
view.buildGuarddutyView();
const legacyFeatureSection = document.querySelector('#gd-status-content section');
assert.ok(legacyFeatureSection);
assert.match(legacyFeatureSection.textContent, /Not collected/);
console.log('GuardDuty feature and finding provenance view checks passed');
