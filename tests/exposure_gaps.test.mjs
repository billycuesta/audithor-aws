import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="exposure-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
window.securityHubApiData = { results: { findings: { exposureFindings: [] } } };
window.allAvailableRegions = [];
const payload = '<img src=x onerror=alert(1)>';
window.exposureApiData = { metadata: { executionDate: 'today' }, results: {
  details: { 'CloudFront Distributions': { Global: [{ Id: 'D1', DomainName: payload, Aliases: ['www.example'], Enabled: true, Origins: [{ Id: 'origin', DomainName: 's3.example', OriginType: 'S3', OriginProtocolPolicy: null, OriginAccessControlPresent: false, OriginAccessIdentityPresent: true }], DefaultCacheBehaviorViewerProtocolPolicy: 'allow-all', CacheBehaviors: [{ PathPattern: '/api/*', ViewerProtocolPolicy: 'https-only' }, { PathPattern: '/legacy/*', ViewerProtocolPolicy: 'http-only' }], ViewerCertificateMinimumProtocolVersion: 'TLSv1.2_2021', WebACLId: '' }] }, 'API Custom Domains': { 'us-east-1': [{ DomainName: 'api.example', SecurityPolicy: 'TLS_1_2', EndpointType: 'REGIONAL', Mappings: [{ BasePath: 'v1', RestApiId: 'abc', Stage: 'prod' }] }] } },
  Enrichment: { cloudFront: { status: 'complete' }, apiDomains: { status: 'complete', regions: { 'us-east-1': { v1: { status: 'complete' }, v2: { status: 'complete' } } } } },
  summary: {}, network_ports: []
} };
const root = new URL('../audithor/static/js/views/', import.meta.url).href;
const view = await import(root + '02_exposure.js');
const rootElement = document.getElementById('exposure-view');
view.buildExposureView();
const cfCells = [...rootElement.querySelector('#exposure-cloudfront-content tbody tr').cells].map(cell => cell.textContent.trim());
assert.deepEqual(cfCells, ['D1', payload, 'www.example', 'allow-all — Risk: HTTP allowed', 'TLSv1.2_2021', 'No WAF', 's3.example (S3; origin protocol: N/A; OAC: absent; OAI: present)', '/api/*: https-only; /legacy/*: http-only (Risk: HTTP allowed)']);
const apiCells = [...rootElement.querySelector('#exposure-api-domains-content tbody tr').cells].map(cell => cell.textContent.trim());
assert.deepEqual(apiCells, ['us-east-1', 'api.example', 'TLS_1_2', 'REGIONAL', 'v1 -> abc/prod']);
assert.equal(document.querySelectorAll('img').length, 0);
assert.ok(rootElement.textContent.includes(payload));

window.exposureApiData.results.details = {};
window.exposureApiData.results.Enrichment = { cloudFront: { status: 'failed', reason: 'permission_denied' }, apiDomains: { status: 'failed', regions: { 'us-east-1': { v1: { status: 'failed', reason: 'permission_denied' }, v2: { status: 'complete' } } } } };
view.buildExposureView();
assert.equal(rootElement.querySelector('#exposure-cloudfront-content').textContent.trim(), 'Not collected: permission_denied');
assert.ok(rootElement.querySelector('#exposure-api-domains-content').textContent.includes('Not collected: us-east-1 v1 permission_denied'));

window.exposureApiData.results = { details: {}, summary: {}, network_ports: [] };
view.buildExposureView();
assert.equal(rootElement.querySelector('#exposure-cloudfront-content').textContent.trim(), 'Not collected');
assert.equal(rootElement.querySelector('#exposure-api-domains-content tbody td').textContent.trim(), 'Not collected');

window.exposureApiData.results.details = { 'CloudFront Distributions': { Global: [] }, 'API Custom Domains': {} };
window.exposureApiData.results.Enrichment = { cloudFront: { status: 'complete' }, apiDomains: { status: 'complete', regions: {} } };
view.buildExposureView();
assert.equal(rootElement.querySelector('#exposure-cloudfront-content').textContent.trim(), 'None found');
assert.equal(rootElement.querySelector('#exposure-api-domains-content tbody td').textContent.trim(), 'None found');
console.log('Exposure gap view checks passed');
