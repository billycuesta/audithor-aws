import assert from 'node:assert/strict';
import { makeDom, PAYLOADS, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';

const currentRoot = new URL('../audithor_project/static/js/views/', import.meta.url).href;
const baselineRoot = new URL('./baseline/audithor_project/static/js/views/', import.meta.url).href;
const specs = [
  {
    file: '03_guardduty.js', builder: 'buildGuarddutyView', rootId: 'guardduty-view',
    fixture: () => ({ metadata: { executionDate: '2026-07-11' }, results: {
      status: [{ Region: 'us-east-1', Status: 'Enabled', 'S3 Logs': 'Enabled', 'Kubernetes Logs': 'Disabled', 'Malware Protection': 'Enabled' }],
      findings: [{ SeverityLabel: 'HIGH', SeverityScore: 7, Region: 'us-east-1', Title: 'Sample finding', Resource: 'sample resource', LastSeen: '2026-07-10' }]
    } })
  },
  {
    file: '04_ecr.js', builder: 'buildEcrView', rootId: 'ecr-view',
    fixture: () => ({ metadata: { executionDate: '2026-07-11' }, results: { repositories: [{
      Region: 'us-east-1', RepositoryName: 'sample-repository', RepositoryArn: 'arn:aws:ecr:us-east-1:123456789012:repository/sample',
      IsPublic: false, ScanOnPush: true, ImageSigningEnabled: true, ImageTagMutability: 'IMMUTABLE', EncryptionType: 'AES256',
      HasLifecyclePolicy: true, SigningProfileName: 'sample-profile', Policy: { Version: '2012-10-17', Statement: [] }
    }] } })
  },
  {
    file: '05_waf.js', builder: 'buildWafView', rootId: 'waf-view',
    fixture: () => ({ metadata: { executionDate: '2026-07-11' }, results: { acls: [{
      Name: 'sample-acl', Scope: 'REGIONAL', Region: 'us-east-1', Version: 'V2',
      LoggingDetails: { all_logging: { enabled: true, destinations: ['arn:aws:logs:us-east-1:123:log-group:sample'] }, destination_only_logging: { enabled: false, destinations: [] } },
      VisibilityConfig: { SampledRequestsEnabled: true }, AssociatedResourceArns: ['arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/sample'],
      TopRules: [{ RuleName: 'sample-rule', BlockedRequests: 4 }]
    }], ip_sets: [{ Name: 'sample-ip-set', Scope: 'REGIONAL', Region: 'us-east-1', IPAddressVersion: 'IPV4', AddressCount: 1 }] } })
  },
  {
    file: '18_codepipeline.js', builder: 'buildCodePipelineView', rootId: 'codepipeline-view',
    fixture: () => ({ metadata: { executionDate: '2026-07-11' }, results: { pipelines: [{
      Name: 'sample-pipeline', Region: 'us-east-1', SourceProvider: 'CodeCommit', IsEncrypted: false,
      HasManualApproval: false, HasSecurityScan: false, RoleArn: 'arn:aws:iam::123456789012:role/sample', Updated: '2026-07-10T00:00:00Z',
      SourceDetails: { Owner: 'sample-owner', Repo: 'sample-repo' }
    }] } })
  }
];

function assertNoLiteralMarkup(root) {
  assert.doesNotMatch(root.textContent, /<(?:div|td|tr|span|pre|script|img|svg)\b|<\//i);
}

function fixtureStringsTo(value, replacement) {
  if (typeof value === 'string') return replacement;
  if (Array.isArray(value)) return value.map(item => fixtureStringsTo(item, replacement));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fixtureStringsTo(item, replacement)]));
  return value;
}

function setupDom(spec, isBaseline = false) {
  const dom = makeDom(`<div id="${spec.rootId}"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div><div id="sh-ecr-findings-container"></div><div id="sh-waf-findings-container"></div>`);
  const { window } = dom;
  window.scopedResources = {};
  window.securityHubApiData = { results: { findings: { ecrFindings: [], wafFindings: [] } } };
  window.fetch = async () => ({ ok: true, json: async () => ({}) });
  window.Chart = function Chart() {};
  globalThis.Chart = window.Chart;
  for (const name of ['openScopeModal', 'copyToClipboard', 'openModalWithEcrPolicy']) window[name] = () => {};
  return { dom, window, root: window.document.getElementById(spec.rootId), baseline: isBaseline };
}

for (const spec of specs) {
  const baselineModule = await import(`${baselineRoot}${spec.file}`);
  const currentModule = await import(`${currentRoot}${spec.file}?t10=${Date.now()}-${spec.file}`);
  const baselineEnv = setupDom(spec, true);
  baselineEnv.window[spec.file === '03_guardduty.js' ? 'guarddutyApiData' : spec.file === '04_ecr.js' ? 'ecrApiData' : spec.file === '05_waf.js' ? 'wafApiData' : 'codepipelineApiData'] = spec.fixture();
  if (spec.file === '05_waf.js') baselineEnv.window.securityHubApiData = { results: { findings: { wafFindings: [] } } };
  if (spec.file === '04_ecr.js') baselineEnv.window.securityHubApiData = { results: { findings: { ecrFindings: [] } } };
  baselineModule[spec.builder]();
  if (spec.file === '04_ecr.js') {
    baselineModule.openModalWithEcrPolicy(0);
    const baselinePolicy = baselineEnv.root.ownerDocument.querySelector('#modal-content code')?.textContent;
    assert.equal(baselinePolicy, JSON.stringify(spec.fixture().results.repositories[0].Policy, null, 2));
  }
  const baselineText = benignText(baselineEnv.root);
  const baselineTags = tagSequence(baselineEnv.root);
  assertNoLiteralMarkup(baselineEnv.root);

  const currentEnv = setupDom(spec);
  currentEnv.window[spec.file === '03_guardduty.js' ? 'guarddutyApiData' : spec.file === '04_ecr.js' ? 'ecrApiData' : spec.file === '05_waf.js' ? 'wafApiData' : 'codepipelineApiData'] = spec.fixture();
  if (spec.file === '05_waf.js') currentEnv.window.securityHubApiData = { results: { findings: { wafFindings: [] } } };
  if (spec.file === '04_ecr.js') currentEnv.window.securityHubApiData = { results: { findings: { ecrFindings: [] } } };
  currentModule[spec.builder]();
  assert.equal(benignText(currentEnv.root).replace(/\s+/g, ''), baselineText.replace(/\s+/g, ''), `${spec.file} benign text parity`);
  assert.deepEqual(tagSequence(currentEnv.root), baselineTags, `${spec.file} element parity`);
  assertNoLiteralMarkup(currentEnv.root);
  clickAll(currentEnv.window, currentEnv.root);

  for (const payload of PAYLOADS) {
    const env = setupDom(spec);
    const dataName = spec.file === '03_guardduty.js' ? 'guarddutyApiData' : spec.file === '04_ecr.js' ? 'ecrApiData' : spec.file === '05_waf.js' ? 'wafApiData' : 'codepipelineApiData';
    env.window[dataName] = fixtureStringsTo(spec.fixture(), payload);
    if (spec.file === '05_waf.js') env.window.securityHubApiData = { results: { findings: { wafFindings: [] } } };
    if (spec.file === '04_ecr.js') env.window.securityHubApiData = { results: { findings: { ecrFindings: [] } } };
    assert.doesNotThrow(() => currentModule[spec.builder](), `${spec.file} renders payload`);
    assertNoInjection(env.window, env.root);
    clickAll(env.window, env.root);
    if (spec.file === '04_ecr.js') {
      assert.doesNotThrow(() => currentModule.openModalWithEcrPolicy(0));
      assertNoInjection(env.window, env.window.document.getElementById('modal-content'));
    }
  }
}
console.log('T10 parity, literal-markup, payload, and click checks passed');
