import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { JSDOM } from 'jsdom';

const constantsSource = await readFile(new URL('../audithor/static/js/constants.js', import.meta.url), 'utf8');
const appSource = await readFile(new URL('../audithor/static/js/app.js', import.meta.url), 'utf8');
const expected = [
  ['iam', 'RUN_IAM', 'iam'], ['accessAnalyzer', 'RUN_ACCESS_ANALYZER', 'accessAnalyzer'], ['securityhub', 'RUN_SECURITYHUB', 'securityhub'],
  ['exposure', 'RUN_EXPOSURE', 'exposure'], ['guardduty', 'RUN_GUARDDUTY', 'guardduty'], ['waf', 'RUN_WAF', 'waf'],
  ['cloudtrail', 'RUN_CLOUDTRAIL', 'cloudtrail'], ['cloudwatch', 'RUN_CLOUDWATCH', 'cloudwatch'], ['inspector', 'RUN_INSPECTOR', 'inspector'],
  ['acm', 'RUN_ACM', 'acm'], ['compute', 'RUN_COMPUTE', 'compute'], ['ecr', 'RUN_ECR', 'ecr'], ['databases', 'RUN_DATABASES', 'databases'],
  ['network_policies', 'RUN_NETWORK_POLICIES', 'network_policies'], ['federation', 'RUN_FEDERATION', 'federation'],
  ['config_sh_status', 'RUN_CONFIG_SH_STATUS', 'config_sh_status'], ['kms-secrets', 'RUN_KMS', 'kms'],
  ['secrets_manager', 'RUN_SECRETS_MANAGER', 'secrets_manager'], ['connectivity', 'RUN_CONNECTIVITY', 'connectivity'],
  ['codepipeline', 'RUN_CODEPIPELINE', 'codepipeline'], ['inventory', 'RUN_INVENTORY', 'inventory']
];
const runBlock = appSource.slice(appSource.indexOf('window.activeScanId = crypto.randomUUID();'), appSource.indexOf('const totalTests = Object.keys(apiCalls).length;'));
assert.ok(runBlock.includes('const apiCalls = {'), 'actual scan entry request block found');
const verify = async (base, prefix, requestBlock = runBlock) => {
  const dom = new JSDOM('<!doctype html><body></body>', { url: 'https://audithor.test/', runScripts: 'outside-only' });
  if (base !== undefined) dom.window.BACKEND_BASE = base;
  dom.window.eval(constantsSource);
  const calls = [];
  const fetchStub = (url, options) => {
    calls.push({ url, ...options, body: JSON.parse(options.body) });
    return Promise.resolve({ ok: true, json: async () => ({ metadata: {}, results: {} }) });
  };
  const execute = new Function('window', 'fetch', 'crypto', 'JSON', `const payload = { access_key: 'dummy-access', secret_key: 'dummy-secret' }; ${requestBlock}\nreturn apiCalls;`);
  execute(dom.window, fetchStub, { randomUUID: () => 'test-scan' }, JSON);
  assert.equal(calls.length, 21);
  const api = dom.window.CONSTANTS.API;
  assert.deepEqual(calls.map(({ url, method, body }) => ({ url, method, body })), expected.map(([runKey, apiKey]) => ({ url: api[apiKey], method: 'POST', body: { access_key: 'dummy-access', secret_key: 'dummy-secret' } })));
  assert.ok(calls.every(({ url }) => typeof url === 'string' && !url.includes('undefined')));
  assert.ok(calls.every(({ url }) => url.startsWith(prefix)));
  dom.window.close();
};
const originalBrokenBlock = runBlock.replace('window.CONSTANTS.API.RUNS.iam', "window.CONSTANTS.API.RUNS['/api/run-iam-audit']");
await assert.rejects(verify(undefined, '/api/', originalBrokenBlock), /deep-equal|undefined|startsWith/);
await verify(undefined, '/api/');
await verify('https://backend.example/root/', 'https://backend.example/root/api/');
console.log('Actual scan request block issued all 21 configured POSTs with dummy credentials for default and custom backend bases');
