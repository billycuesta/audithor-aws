import assert from 'node:assert/strict';
import { makeDom, assertNoInjection, clickAll, benignText, tagSequence, PAYLOADS } from './helpers/xss_payloads.mjs';
import { installActionDelegation } from '../audithor_project/static/js/safe_html.js';

const fixture = {
  kmsApiData: {
    metadata: { executionDate: '2025-01-01' },
    results: { keys: [
      { ARN: 'arn:aws:kms:us-east-1:123:key/customer', Region: 'us-east-1', Aliases: 'alias/customer', KeyId: 'customer-id', Status: 'Enabled', RotationEnabled: 'Enabled', KeyManager: 'CUSTOMER', Policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'kms:DescribeKey', Resource: '*' }] } },
      { ARN: 'arn:aws:kms:us-west-2:123:key/aws', Region: 'us-west-2', Aliases: 'alias/aws/example', KeyId: 'aws-id', Status: 'Enabled', RotationEnabled: 'Disabled', KeyManager: 'AWS', Policy: { Statement: [] } }
    ] }
  },
  secretsManagerApiData: {
    metadata: { executionDate: '2025-01-02' },
    results: { secrets: [
      { ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:db', Region: 'us-east-1', Name: 'database-credentials', Description: 'Primary database credentials', KmsKeyId: 'alias/customer', RotationEnabled: false, RiskScore: 70, LastAccessedDate: '2025-01-01T00:00:00Z', CreatedDate: '2024-01-01T00:00:00Z', LastRotatedDate: '2024-12-01T00:00:00Z', RotationLambdaARN: 'arn:aws:lambda:us-east-1:123:function:rotate', RotationRules: { AutomaticallyAfterDays: 30 }, RotationAnalysis: { issues: ['Rotation window is overdue'], recommendations: ['Rotate credentials promptly'] }, SecurityIssues: [{ severity: 'high', type: 'PUBLIC_ACCESS', description: 'Resource policy may allow broad access', recommendation: 'Restrict principals' }], ResourcePolicy: { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: 'secretsmanager:GetSecretValue', Principal: '*' }] }, Tags: [{ Key: 'Environment', Value: 'production' }] },
      { ARN: 'arn:aws:secretsmanager:us-west-2:123:secret:broken', Region: 'us-west-2', Name: 'unavailable-secret', Description: '', KmsKeyId: 'alias/aws/secretsmanager', Error: 'Access denied', RotationEnabled: false }
    ] }
  },
  connectivityApiData: {
    metadata: { executionDate: '2025-01-03' },
    results: {
      peering_connections: [{ Region: 'us-east-1', ConnectionId: 'pcx-123', RequesterVpc: { VpcId: 'vpc-requester', OwnerId: '111111111111' }, AccepterVpc: { VpcId: 'vpc-accepter', OwnerId: '222222222222' } }],
      tgw_attachments: [{ Region: 'us-east-1', TransitGatewayId: 'tgw-123', VpcId: 'vpc-123', AttachmentId: 'tgw-attach-123' }],
      vpn_connections: [{ Region: 'us-west-2', VpnConnectionId: 'vpn-123', CustomerGatewayId: 'cgw-123', TransitGatewayId: 'tgw-456' }],
      vpc_endpoints: [{ Region: 'eu-west-1', VpcId: 'vpc-endpoint', EndpointType: 'Interface', ServiceName: 'com.amazonaws.eu-west-1.ssm' }],
      nat_gateways: [{ Region: 'us-east-1', NatGatewayId: 'nat-123', VpcId: 'vpc-nat', SubnetId: 'subnet-nat', State: 'available', ConnectivityType: 'public', NatGatewayAddresses: [{ PublicIp: '203.0.113.10', PrivateIp: '10.0.0.10' }] }]
    }
  }
};

const configs = [
  { name: 'KMS and Secrets', id: 'kms-secrets-view', module: '12_kms_secrets', builder: 'buildKmsSecretsView', data: ['kmsApiData', 'secretsManagerApiData'] },
  { name: 'Connectivity', id: 'connectivity-view', module: '14_connectivity', builder: 'buildConnectivityView', data: ['connectivityApiData'] }
];

function assertNoLiteralMarkup(root) {
  assert.doesNotMatch(root.textContent, /<(?:div|td|tr|span|pre)\b|<\//i, 'rendered text must not contain literal markup');
}

function replaceStrings(value, payload) {
  if (typeof value === 'string') return payload;
  if (Array.isArray(value)) return value.map(item => replaceStrings(item, payload));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceStrings(item, payload)]));
  }
  return value;
}

async function loadView(moduleDir, config, dataFixture) {
  const dom = makeDom(`<div id="${config.id}"></div><div id="details-modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-content"></div></div>`);
  dom.window.fetch = async () => ({ ok: true, json: async () => ({}) });
  dom.window.scopedResources = {};
  for (const [key, value] of Object.entries(dataFixture)) dom.window[key] = structuredClone(value);
  const mod = await import(new URL(`${moduleDir}/${config.module}.js`, import.meta.url));
  if (mod.openModalWithKmsPolicy) dom.window.openModalWithKmsPolicy = mod.openModalWithKmsPolicy;
  if (mod.openModalWithSecretDetails) dom.window.openModalWithSecretDetails = mod.openModalWithSecretDetails;
  if (moduleDir.startsWith('../audithor_project')) installActionDelegation(dom.window.document);
  mod[config.builder]();
  return { dom, mod, root: dom.window.document.getElementById(config.id) };
}

for (const config of configs) {
  const baseline = await loadView(`./baseline/audithor_project/static/js/views`, config, fixture);
  const current = await loadView(`../audithor_project/static/js/views`, config, fixture);
  assertNoLiteralMarkup(baseline.root);
  assertNoLiteralMarkup(current.root);
  assert.equal(benignText(current.root), benignText(baseline.root), `${config.name} benign text parity`);
  assert.deepEqual(tagSequence(current.root), tagSequence(baseline.root), `${config.name} benign tag parity`);

  // Exercise every view tab in both implementations.
  const tabLinks = [...current.root.querySelectorAll('nav a[data-tab]')];
  const baseLinks = [...baseline.root.querySelectorAll('nav a[data-tab]')];
  assert.equal(tabLinks.length, baseLinks.length);
  for (let i = 0; i < tabLinks.length; i++) {
    tabLinks[i].click();
    baseLinks[i].click();
    assert.equal(benignText(current.root), benignText(baseline.root), `${config.name} tab ${i} text parity`);
    assert.deepEqual(tagSequence(current.root), tagSequence(baseline.root), `${config.name} tab ${i} tag parity`);
  }

  if (config.module === '12_kms_secrets') {
    for (const [section, label] of [['#secrets-manager-content', 'View Details'], ['#kms-customer-keys-content', 'View Policy']]) {
      const currentButton = [...current.root.querySelectorAll(`${section} button`)].find(button => button.textContent.trim() === label);
      const baselineButton = [...baseline.root.querySelectorAll(`${section} button`)].find(button => button.textContent.trim() === label);
      assert.ok(currentButton, `current view has operator action ${label}`);
      assert.ok(baselineButton, `baseline view has operator action ${label}`);
      for (const method of ['openModalWithKmsPolicy', 'openModalWithSecretDetails']) {
        if (current.mod[method]) current.dom.window[method] = current.mod[method];
        if (baseline.mod[method]) baseline.dom.window[method] = baseline.mod[method];
      }
      globalThis.window = current.dom.window;
      globalThis.document = current.dom.window.document;
      currentButton.click();
      globalThis.window = baseline.dom.window;
      globalThis.document = baseline.dom.window.document;
      baselineButton.click();
      globalThis.window = current.dom.window;
      globalThis.document = current.dom.window.document;
      const currentModal = current.dom.window.document.getElementById('details-modal');
      const baselineModal = baseline.dom.window.document.getElementById('details-modal');
      assertNoLiteralMarkup(currentModal);
      assertNoLiteralMarkup(baselineModal);
      assert.equal(benignText(currentModal), benignText(baselineModal), `operator action ${label} modal text parity`);
      assert.deepEqual(tagSequence(currentModal), tagSequence(baselineModal), `operator action ${label} modal tag parity`);
      currentModal.classList.add('hidden');
      baselineModal.classList.add('hidden');
    }
  }

  for (const payload of PAYLOADS) {
    const poisonedFixture = replaceStrings(structuredClone(fixture), payload);
    const candidate = await loadView('../audithor_project/static/js/views', config, poisonedFixture);
    assertNoInjection(candidate.dom.window, candidate.root);
    clickAll(candidate.dom.window, candidate.root);
    candidate.dom.window.close();
  }
  baseline.dom.window.close();
  current.dom.window.close();
}

// Verify the exported KMS modal openers against the original output and all hostile values.
for (const [name, index] of [['policy', 0], ['secret', 0]]) {
  const domBase = makeDom('<div id="details-modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-content"></div></div>');
  const baseModule = await import(new URL('./baseline/audithor_project/static/js/views/12_kms_secrets.js', import.meta.url));
  domBase.window.kmsApiData = structuredClone(fixture.kmsApiData);
  domBase.window.secretsManagerApiData = structuredClone(fixture.secretsManagerApiData);
  const baseOpen = name === 'policy' ? baseModule.openModalWithKmsPolicy : baseModule.openModalWithSecretDetails;
  domBase.window[name === 'policy' ? 'openModalWithKmsPolicy' : 'openModalWithSecretDetails'] = baseOpen;
  baseOpen(index);

  const domCurrent = makeDom('<div id="details-modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-content"></div></div>');
  const currentModule = await import(new URL('../audithor_project/static/js/views/12_kms_secrets.js', import.meta.url));
  domCurrent.window.kmsApiData = structuredClone(fixture.kmsApiData);
  domCurrent.window.secretsManagerApiData = structuredClone(fixture.secretsManagerApiData);
  const currentOpen = name === 'policy' ? currentModule.openModalWithKmsPolicy : currentModule.openModalWithSecretDetails;
  domCurrent.window[name === 'policy' ? 'openModalWithKmsPolicy' : 'openModalWithSecretDetails'] = currentOpen;
  currentOpen(index);
  const baseContent = domBase.window.document.getElementById('details-modal');
  const currentContent = domCurrent.window.document.getElementById('details-modal');
  assertNoLiteralMarkup(baseContent);
  assertNoLiteralMarkup(currentContent);
  assert.equal(benignText(currentContent), benignText(baseContent), `${name} modal text parity`);
  assert.deepEqual(tagSequence(currentContent), tagSequence(baseContent), `${name} modal tag parity`);
  domBase.window.close();
  domCurrent.window.close();

  for (const payload of PAYLOADS) {
    const hostileFixture = structuredClone(fixture);
    const dataKey = name === 'policy' ? 'kmsApiData' : 'secretsManagerApiData';
    hostileFixture[dataKey] = replaceStrings(hostileFixture[dataKey], payload);
    const dom = makeDom('<div id="details-modal" class="hidden"><h1 id="modal-title"></h1><div id="modal-content"></div></div>');
    dom.window.kmsApiData = hostileFixture.kmsApiData;
    dom.window.secretsManagerApiData = hostileFixture.secretsManagerApiData;
    const mod = await import(new URL('../audithor_project/static/js/views/12_kms_secrets.js', import.meta.url));
    const open = name === 'policy' ? mod.openModalWithKmsPolicy : mod.openModalWithSecretDetails;
    open(index);
    assertNoInjection(dom.window, dom.window.document.getElementById('details-modal'));
    clickAll(dom.window, dom.window.document.getElementById('details-modal'));
    dom.window.close();
  }
}

console.log('T8 parity and XSS payload checks passed');
