import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { JSDOM } from 'jsdom';
import { PAYLOADS, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';

const current = resolve('audithor/static/js/views/');
const baseline = resolve('tests/baseline/audithor_project/static/js/views/');
const load = async (base, file) => import(pathToFileURL(resolve(base, file)).href + `?run=${Math.random()}`);
const coverage = { status: 'complete', coverageKnown: true, units: [] };
const inspectorFinding = (severity = 'HIGH', value = 'Benign finding') => ({ severity, firstObservedAt: '2025-01-01', Region: 'us-east-1', title: value, description: value, remediation: { recommendation: { text: value } }, type: value, resources: [{ id: value, type: 'AWS_EC2_INSTANCE', tags: { Name: value } }] });
const statusRows = [{ Region: 'us-east-1', InspectorStatus: 'ENABLED', ScanEC2: 'ENABLED', ScanECR: 'ENABLED', ScanLambda: 'ENABLED' }, { Region: 'us-west-2', InspectorStatus: 'DISABLED', ScanEC2: 'DISABLED', ScanECR: 'DISABLED', ScanLambda: 'DISABLED' }];
const securityFinding = { Severity: { Label: 'HIGH' }, Region: 'us-east-1', Title: 'Certificate finding', Resources: [{ Type: 'AWS::ACM::Certificate' }] };
const certificate = (status, domain, days = 180) => ({ DomainName: domain, Region: 'us-east-1', Status: status, Issuer: 'Example CA', CertificateArn: `arn:aws:acm:us-east-1:123:certificate/${domain}`, IssuedAt: '2025-01-01', NotAfter: new Date(Date.now() + days * 86400000).toISOString(), SubjectAlternativeNames: [`www.${domain}`], InUseBy: [] });
const acmCertificates = [certificate('ISSUED', 'issued.example', 20), certificate('ISSUED', 'later.example', 80), certificate('EXPIRED', 'expired.example'), certificate('PENDING_VALIDATION', 'pending.example'), { DomainName: 'unknown.example', Region: 'us-east-1', Issuer: 'Unknown CA', SubjectAlternativeNames: [] }];

function freshDom() {
  const dom = new JSDOM('<div id="inspector-view"></div><div id="acm-view"></div><input id="access-key-input" value="key"><input id="secret-key-input" value="secret"><input id="session-token-input">', { url: 'http://localhost/' });
  globalThis.window = dom.window; globalThis.document = dom.window.document;
  window.scopedResources = {}; window.securityHubApiData = { results: { findings: { inspectorFindings: [securityFinding], cloudwatchFindings: [securityFinding] } } };
  window.log = () => {}; window.runAndDisplayHealthyStatus = () => {};
  window.openScopeModal = () => {}; window.renderSecurityHubFindings = () => {};
  return dom;
}
function fixture(payload = 'Benign') {
  return {
    inspectorApiData: { metadata: { executionDate: '2025-01-01' }, results: { findings: [], findingsStatus: 'not_run', scan_status: statusRows.map(row => ({ ...row })), _collection: structuredClone(coverage) } },
    acmApiData: { metadata: { executionDate: '2025-01-01' }, results: { certificates: acmCertificates.map(cert => ({ ...cert, DomainName: payload === 'Benign' ? cert.DomainName : payload, Issuer: payload, SubjectAlternativeNames: [payload] })), _collection: structuredClone(coverage) } }
  };
}
function installFixture(data) { window.inspectorApiData = structuredClone(data.inspectorApiData); window.acmApiData = structuredClone(data.acmApiData); }
async function reachInspectorComplete(build, findings) {
  window.fetch = globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: { findings, findingsStatus: 'complete', _collection: structuredClone(coverage) } }) });
  build();
  document.getElementById('run-deep-inspector-scan-btn')?.click();
  await new Promise(resolve => setTimeout(resolve, 150));
  document.getElementById('inspector-search-filter')?.dispatchEvent(new window.Event('input', { bubbles: true }));
  assert.ok(document.querySelector('#inspector-findings-tbody tr'), 'complete Inspector findings table contains a real row');
  document.querySelector('#inspector-tabs-results a[data-tab="inspector-findings-content"]')?.click();
  document.querySelector('#inspector-tabs-results a[data-tab="inspector-sh-content"]')?.click();
  document.querySelector('#sh-inspector-pagination-controls button')?.click();
}

// PARITY: use matching populated fixtures and compare the original and converted DOM.
for (const file of ['08_inspector.js', '09_acm.js']) {
  const original = await load(baseline, file);
  const converted = await load(current, file);
  for (const module of [original, converted]) {
    freshDom(); const data = fixture(); installFixture(data);
    if (file === '08_inspector.js') {
      await reachInspectorComplete(module.buildInspectorView, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map(severity => inspectorFinding(severity)));
    } else {
      module.buildAcmView();
      for (const tab of ['acm-certificates-content', 'acm-lifecycle-content', 'acm-sh-content', 'acm-summary-content']) document.querySelector(`#acm-tabs a[data-tab="${tab}"]`).click();
    }
    const root = document.getElementById(file === '08_inspector.js' ? 'inspector-view' : 'acm-view');
    if (module === original) { globalThis[`text_${file}`] = benignText(root); globalThis[`tags_${file}`] = tagSequence(root); }
    else {
      assert.equal(benignText(root), globalThis[`text_${file}`], `${file} benign text parity`);
      assert.deepEqual(tagSequence(root), globalThis[`tags_${file}`], `${file} element structure parity`);
    }
  }
}

// PAYLOAD: exercise both builders and the completed Inspector path for every payload.
for (const payload of PAYLOADS) {
  for (const file of ['08_inspector.js', '09_acm.js']) {
    const module = await load(current, file);
    freshDom(); const data = fixture(payload); installFixture(data);
    if (file === '08_inspector.js') {
      const findings = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map(severity => inspectorFinding(severity, payload));
      await reachInspectorComplete(module.buildInspectorView, findings);
      const root = document.getElementById('inspector-view'); assertNoInjection(window, root); clickAll(window, root);
      window.fetch = globalThis.fetch = async () => { throw new Error(payload); };
      installFixture(data); module.buildInspectorView(); document.getElementById('run-deep-inspector-scan-btn').click();
      await new Promise(resolve => setTimeout(resolve, 150));
      assertNoInjection(window, root); clickAll(window, root);
    } else {
      module.buildAcmView();
      for (const tab of ['acm-certificates-content', 'acm-lifecycle-content', 'acm-sh-content']) document.querySelector(`#acm-tabs a[data-tab="${tab}"]`).click();
      const root = document.getElementById('acm-view'); assertNoInjection(window, root); clickAll(window, root);
    }
  }
}
console.log('T6 baseline parity and payload path checks passed');
