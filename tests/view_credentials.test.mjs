import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const viewsDir = fileURLToPath(new URL('../audithor/static/js/views/', import.meta.url));
for (const file of fs.readdirSync(viewsDir).filter(name => name.endsWith('.js'))) {
  const source = fs.readFileSync(path.join(viewsDir, file), 'utf8');
  assert.doesNotMatch(source, /access-key-input|secret-key-input|session-token-input/, `${file} must not read credential inputs`);
}

const cases = [
  { file: '01_iam.js', fn: 'openModalWithUserRoles', fields: { username: 'alice' }, container: 'modal-content', args: ['alice', 0] },
  { file: '01_iam.js', fn: 'openModalWithSsoDetails', fields: { group_id: 'group-1' }, container: 'modal-content', args: ['group-1', 'Developers'] },
  { file: '01_iam.js', fn: 'analyzeCustomPolicy', fields: { policy_name: 'CustomPolicy' }, container: 'iam-search-results-container', args: ['CustomPolicy'] },
  { file: '02_exposure.js', fn: 'runS3BucketSecurityCheck', fields: { bucket_name: 'audit-bucket' }, container: 'modal-content', args: ['audit-bucket'] },
  { file: '06_cloudtrail.js', fn: 'runCloudtrailLookupAnalysis', fields: { event_name: 'ConsoleLogin', start_date: '2025-01-01', end_date: '2025-01-02', region: 'us-east-1' }, container: 'ct-lookup-results-container' },
  { file: '08_inspector.js', fn: 'runDeepInspectorAnalysis', fields: {}, container: 'deep-inspector-scan-error' },
  { file: '13_network_policies.js', fn: 'runNetworkDetailAnalysis', fields: { resource_id: 'sg-123', region: 'us-east-1' }, container: 'np-detail-results-container' },
  { file: '15_config_sh.js', fn: 'runDeepConfigSHAnalysis', fields: {}, container: 'deep-scan-error-container' },
  { file: '16_playground.js', fn: 'runPlaygroundAnalysis', fields: { source_arn: 'arn:source', target_arn: 'arn:target' }, container: 'playground-results-container' },
  { file: '16_playground.js', fn: 'runSimulation', fields: { username: 'alice', actions: ['s3:GetObject'] }, container: 'simulation-results-container' },
  { file: '16_playground.js', fn: 'runLambdaSimulation', fields: { function_name: 'worker', region: 'us-east-1', actions: ['lambda:InvokeFunction'] }, container: 'lambda-simulation-results-container' },
];

function fixture() {
  const dom = new JSDOM(`<!doctype html><body>
    <button id="credential-mode-keys"></button><button id="credential-mode-profile"></button>
    <select id="aws-profile-select"><option value="audit-prod">audit-prod</option></select>
    <input id="access-key-input" value="AKIAEXAMPLE"><input id="secret-key-input" value="secret-example"><input id="session-token-input" value="token-example">
    <div id="details-modal"><h2 id="modal-title"></h2><div id="modal-content"></div></div>
    <div id="iam-search-results-container"></div><button id="iam-search-btn"></button><span id="search-btn-text"></span>
    <input id="ct-event-name" value="ConsoleLogin"><input id="ct-start-date" value="2025-01-01"><input id="ct-end-date" value="2025-01-02"><select id="ct-lookup-region"><option value="us-east-1" selected>us-east-1</option></select><button id="ct-run-lookup-btn"></button><span id="ct-lookup-btn-text"></span><div id="ct-lookup-spinner"></div><div id="ct-lookup-results-container"></div>
    <button id="run-deep-inspector-scan-btn"></button><span id="deep-inspector-scan-btn-text"></span><div id="deep-inspector-scan-spinner"></div><div id="deep-inspector-scan-error"></div>
    <input id="np-resource-id" value="sg-123"><select id="np-resource-region"><option value="us-east-1" selected>us-east-1</option></select><button id="np-run-detail-btn"></button><span id="np-detail-btn-text"></span><div id="np-detail-spinner"></div><div id="np-detail-results-container"></div>
    <button id="run-deep-scan-btn"></button><span id="deep-scan-btn-text"></span><div id="deep-scan-spinner"></div><div id="deep-scan-error-container"></div>
    <input id="pg-source-arn" value="arn:source"><input id="pg-target-arn" value="arn:target"><button id="pg-run-analysis-btn"></button><span id="pg-button-text"></span><div id="pg-loading-spinner"></div><div id="playground-results-container"></div>
    <input id="pg-username" value="alice"><textarea id="pg-custom-actions"></textarea><input type="radio" name="mfa-context" value="with-mfa" checked><input type="checkbox" class="action-checkbox" value="s3:GetObject" checked><button id="pg-run-simulation-btn"></button><span id="pg-simulation-btn-text"></span><div id="pg-simulation-spinner"></div><div id="simulation-results-container"></div>
    <input id="pg-lambda-name" value="worker"><select id="pg-lambda-region"><option value="us-east-1" selected>us-east-1</option></select><textarea id="pg-lambda-custom-actions"></textarea><input type="checkbox" class="lambda-action-checkbox" value="lambda:InvokeFunction" checked><button id="pg-run-lambda-simulation-btn"></button><span id="pg-lambda-simulation-btn-text"></span><div id="pg-lambda-simulation-spinner"></div><div id="lambda-simulation-results-container"></div>
  </body>`, { url: 'http://localhost' });
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  globalThis.localStorage = dom.window.localStorage;
  return dom;
}

const credentials = await import('../audithor/static/js/credentials.js');
for (const action of cases) {
  for (const mode of ['profile', 'keys', 'missing-profile']) {
    const dom = fixture();
    const { window } = dom;
    credentials.initCredentialControls();
    window.document.getElementById(mode === 'keys' ? 'credential-mode-keys' : 'credential-mode-profile').click();
    if (mode === 'missing-profile') window.document.getElementById('aws-profile-select').value = '';
    let requests = [];
    window.fetch = globalThis.fetch = async (url, options) => {
      requests.push({ url, options, body: JSON.parse(options.body) });
      return { ok: false, status: 400, json: async () => ({ error: 'stub response' }) };
    };
    window.iamApiData = { results: { users: [{ Roles: [] }] } };
    window.inspectorApiData = { results: { findings: [], _collection: { status: 'complete', coverageKnown: true, units: [] } } };
    window.activeScanId = 'scan-test';
    const mod = await import(`../audithor/static/js/views/${action.file}?case=${encodeURIComponent(action.fn + mode)}`);
    const invoke = action.fn === 'runS3BucketSecurityCheck'
      ? window.runS3BucketSecurityCheck
      : mod[action.fn];
    assert.equal(typeof invoke, 'function', `${action.fn} is available`);
    const args = action.args || [];
    await invoke(...args);
    const output = window.document.getElementById(action.container);
    if (mode === 'missing-profile') {
      assert.equal(requests.length, 0, `${action.fn} must not fetch without a selected profile`);
      assert.match(output.textContent, /Please select an AWS profile\./, `${action.fn} shows helper validation message`);
      if (action.fn === 'runDeepConfigSHAnalysis') {
        assert.match(output.textContent, /Please select an AWS profile\./, 'Config deep dive shows missing-profile validation');
        assert.equal(requests.length, 0, 'Config deep dive sends no request without a selected profile');
      }
    } else {
      assert.equal(requests.length, 1, `${action.fn} makes one request in ${mode} mode`);
      const body = requests[0].body;
      for (const [key, value] of Object.entries(action.fields)) assert.deepEqual(body[key], value, `${action.fn} keeps ${key}`);
      if (mode === 'profile') {
        assert.equal(body.profile, 'audit-prod');
        assert.equal('access_key' in body, false);
        assert.equal('secret_key' in body, false);
        assert.equal('session_token' in body, false);
      } else {
        assert.equal(body.access_key, 'AKIAEXAMPLE');
        assert.equal(body.secret_key, 'secret-example');
        assert.equal(body.session_token, 'token-example');
        assert.equal('profile' in body, false);
      }
      if (action.fn === 'runDeepInspectorAnalysis') assert.equal(requests[0].options.headers['X-Scan-Id'], 'scan-test');
    }
    dom.window.close();
  }
}
console.log('All 11 view actions send profile/key payloads and reject missing profiles');
