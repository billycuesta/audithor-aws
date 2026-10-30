import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { PAYLOADS, makeDom, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';
import { installActionDelegation } from '../audithor_project/static/js/safe_html.js';

const baselineUrl = new URL('./baseline/audithor_project/static/js/views/02_exposure.js', import.meta.url).href;
const currentUrl = new URL('../audithor_project/static/js/views/02_exposure.js', import.meta.url).href;
const fixture = () => ({ metadata: { executionDate: '2025-01-01' }, results: { details: {
  'ALB/NLB Public': { 'us-east-1': [{ name: 'edge-lb', region: 'us-east-1', listeners: [{ protocol: 'HTTPS', port: 443, policyName: 'TLS-1-2', tlsVersions: ['TLSv1.2'], ciphers: ['cipher-a'], rules: [], targetGroupName: 'tg', targets: [{ Id: '10.0.0.1' }], isOutdated: false }] }] },
  'API Gateway Public': { 'us-east-1': [{ name: 'api-one', id: 'abc123', region: 'us-east-1', apiType: 'REST', endpointConfiguration: ['REGIONAL'], stages: ['prod'], createdDate: '2025-01-01', description: 'benign API', integrations: [{ method: 'GET', path: '/items', type: 'AWS_PROXY', uri: 'arn:aws:lambda:us-east-1:123:function:test' }] }] },
  'S3 Public Buckets': { 'us-east-1': ['audit-bucket'] },
  'Security Groups Open': { 'us-east-1': [{ Region: 'us-east-1', GroupId: 'sg-123', GroupName: 'open', Protocol: 'tcp', PortRange: '443' }] },
  'Lambda URLs': { 'us-east-1': ['https://function.lambda-url.us-east-1.on.aws/'] }
 }, network_ports: [], lambda_credentials: [{ severity: 'HIGH', region: 'us-east-1', function_name: 'fn', runtime: 'nodejs', type: 'Credential', finding: 'Finding text', function_arn: 'arn:aws:lambda:us-east-1:123:function:fn', env_var_name: 'TOKEN', env_var_value: 'value', detected_pattern: 'token', sample_value: 'sample' }], summary: {} } });
const replaceStrings = (value, replacement) => typeof value === 'string' ? replacement : Array.isArray(value) ? value.map(v => replaceStrings(v, replacement)) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replaceStrings(v, replacement)])) : value;
const assertNoLiteralMarkup = root => assert.doesNotMatch(root.textContent, /<(?:div|td|tr|span|pre|button)\b|<\//i);
const create = async (url, data = fixture()) => {
  const dom = makeDom('<input id="access-key-input" value="AKIAEXAMPLE"><input id="secret-key-input" value="secret-example"><input id="session-token-input" value=""><div id="exposure-view"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>');
  const { window } = dom;
  globalThis.window = window; globalThis.document = window.document;
  window.exposureApiData = data; window.allAvailableRegions = ['us-east-1'];
  window.computeApiData = { results: { ec2_instances: [{ Region: 'us-east-1', InstanceId: 'i-1', InstanceType: 't3.micro', State: 'running', PublicIpAddress: '1.2.3.4', OperatingSystem: 'Linux', SecurityGroups: [], ARN: 'arn:aws:ec2:us-east-1:123:instance/i-1', Tags: [{ Key: 'Name', Value: 'web' }] }] } };
  window.securityHubApiData = { results: { findings: { exposureFindings: [] } } };
  window.copyToClipboard = () => {};
  window.openModalWithEc2Tags = () => {};
  const view = await import(`${url}?run=${Math.random()}`);
  if (view.openModalWithTlsDetails) window.openModalWithTlsDetails = view.openModalWithTlsDetails;
  if (view.openModalWithResourceMap) window.openModalWithResourceMap = view.openModalWithResourceMap;
  installActionDelegation(window.document);
  view.buildExposureView();
  return { dom, view };
};
const modalRoot = window => window.document.querySelector('#modal-content');
const openAll = async ({ window }, view, stubFetch = false, benign = true) => {
  globalThis.window = window; globalThis.document = window.document;
  const snapshots = [];
  const capture = () => {
    const root = modalRoot(window);
    if (benign) assertNoLiteralMarkup(root); else assertNoInjection(window, root);
    snapshots.push({ text: benignText(root).replace(/Completed at .+$/, 'Completed at <timestamp>'), tags: tagSequence(root) });
  };
  const click = selector => {
    const element = window.document.querySelector(selector);
    assert.ok(element, `operator action exists: ${selector}`);
    element.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
  };
  click('#exposure-ALB-NLB-Public-content tbody tr'); capture();
  click('#exposure-ALB-NLB-Public-content button[onclick*="openModalWithTlsDetails"], #exposure-ALB-NLB-Public-content button[data-act="openModalWithTlsDetails"]'); capture();
  click('#exposure-API-Gateway-Public-content button[onclick*="openModalWithApiMap"], #exposure-API-Gateway-Public-content button[data-act="openModalWithApiMap"]'); capture();
  click('#exposure-S3-Public-Buckets-content button[onclick*="openS3BucketDetails"], #exposure-S3-Public-Buckets-content button[data-act="openS3BucketDetails"]'); capture();
  click('#exposure-Lambda-Credential-Harvesting-content button[onclick*="openLambdaCredentialDetails"], #exposure-Lambda-Credential-Harvesting-content button[data-act="openLambdaCredentialDetails"]'); capture();
  click('#exposure-EC2-Public-Instances-content button[data-act="copyToClipboard"], #exposure-EC2-Public-Instances-content button[onclick*="copyToClipboard"]');
  click('#exposure-EC2-Public-Instances-content button[data-act="openModalWithEc2Tags"], #exposure-EC2-Public-Instances-content button[onclick*="openModalWithEc2Tags"]');
  if (stubFetch) {
    let fetchCalls = 0;
    const fetchStub = async (url, options) => {
      fetchCalls += 1;
      assert.equal(url, '/api/run-s3-security-check');
      assert.equal(options.method, 'POST');
      assert.equal(JSON.parse(options.body).bucket_name, 'audit-bucket');
      return { ok: true, json: async () => ({ analysis: { risk_level: 'LOW', risk_score: 10, issues: [], warnings: [], configuration: { encryption: true, public_access_block: { blockPublicAcls: true } }, recommendations: ['Keep access reviewed'] } }) };
    };
    window.fetch = fetchStub; globalThis.fetch = fetchStub;
    assert.equal(typeof window.runS3BucketSecurityCheck, 'function', 'S3 security action is installed');
    let actionCalls = 0;
    const runSecurityCheck = window.runS3BucketSecurityCheck;
    window.runS3BucketSecurityCheck = (...args) => { actionCalls += 1; return runSecurityCheck(...args); };
    const securityButton = window.document.querySelector('#exposure-S3-Public-Buckets-content button[data-act="runS3BucketSecurityCheck"]');
    if (securityButton) assert.equal(securityButton.dataset.act, 'runS3BucketSecurityCheck');
    click('#exposure-S3-Public-Buckets-content button[onclick*="runS3BucketSecurityCheck"], #exposure-S3-Public-Buckets-content button[data-act="runS3BucketSecurityCheck"]');
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(actionCalls, 1, 'S3 security-check button invokes its action');
    assert.equal(fetchCalls, 1, 'S3 security check performs exactly one fetch');
    capture();
  }
  return snapshots;
};
const main = async () => {
  const parityFixture = fixture();
  parityFixture.results.details = {};
  parityFixture.results.lambda_credentials = [];
  const baseline = await create(baselineUrl, parityFixture);
  const converted = await create(currentUrl, parityFixture);
  const baseRoot = baseline.dom.window.document.querySelector('#exposure-view');
  const currentRoot = converted.dom.window.document.querySelector('#exposure-view');
  assertNoLiteralMarkup(currentRoot); assertNoLiteralMarkup(baseRoot);
  assert.equal(benignText(currentRoot), benignText(baseRoot));
  assert.deepEqual(tagSequence(currentRoot), tagSequence(baseRoot));
  assertNoLiteralMarkup(currentRoot);
  const baselinePopulated = await create(baselineUrl);
  const convertedPopulated = await create(currentUrl);
  const s3Baseline = await openAll(baselinePopulated.dom, baselinePopulated.view, true);
  const s3Current = await openAll(convertedPopulated.dom, convertedPopulated.view, true);
  for (const candidate of [baselinePopulated, convertedPopulated]) assertNoLiteralMarkup(candidate.dom.window.document.querySelector('#exposure-view'));
  assert.deepEqual(s3Current, s3Baseline, 'modal and S3 analysis benign parity');
  // Modal parity is checked per public modal entry point in fresh, equivalent DOMs.
  for (const [name, args] of [['openModalWithTlsDetails', [0, 0]], ['openModalWithResourceMap', [0]], ['openS3BucketDetails', ['audit-bucket', 'us-east-1']], ['openLambdaCredentialDetails', [0]], ['openModalWithApiMap', [0]]]) {
    const a = await create(baselineUrl); const b = await create(currentUrl);
    const fnA = a.dom.window[name] || a.view[name]; const fnB = b.dom.window[name] || b.view[name];
    assert.equal(typeof fnA, 'function', `${name} baseline action exists`); assert.equal(typeof fnB, 'function', `${name} current action exists`);
    globalThis.window = a.dom.window; globalThis.document = a.dom.window.document; fnA(...args);
    globalThis.window = b.dom.window; globalThis.document = b.dom.window.document; fnB(...args);
    assertNoLiteralMarkup(modalRoot(a.dom.window)); assertNoLiteralMarkup(modalRoot(b.dom.window));
    assert.equal(benignText(modalRoot(b.dom.window)), benignText(modalRoot(a.dom.window)), `${name} benign text parity`);
    assert.deepEqual(tagSequence(modalRoot(b.dom.window)), tagSequence(modalRoot(a.dom.window)), `${name} benign tag parity`);
  }
  for (const payload of PAYLOADS) {
    const data = replaceStrings(fixture(), payload);
    const { dom, view } = await create(currentUrl, data);
    const root = dom.window.document.querySelector('#exposure-view');
    assertNoInjection(dom.window, root);
    await openAll(dom, view, true, false);
    assertNoInjection(dom.window, modalRoot(dom.window));
    clickAll(dom.window, root);
  }
  console.log('Exposure XSS parity, modal, S3 fetch, and payload checks passed');
};
await main();
