import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';

const viewsDir = new URL('../audithor/static/js/views/', import.meta.url);
const entries = await readdir(viewsDir);
for (const file of entries.filter(name => name.endsWith('.js'))) {
  assert.doesNotMatch(await readFile(new URL(file, viewsDir), 'utf8'), /Audit Guidance/, `${file} source must not contain Audit Guidance`);
}

const specs = [
  ['01_iam.js', 'buildIamView', 'iam-view', 'iamApiData', { users: [], groups: [], roles: [], password_policy: {}, region_guardrails: null }],
  ['02_exposure.js', 'buildExposureView', 'exposure-view', 'exposureApiData', { details: { 'S3 Public Buckets': {}, 'EC2 Public Instances': { all: [] }, 'Security Groups Open': {}, 'ALB/NLB Public': {}, 'Lambda URLs': {}, 'API Gateway Public': {}, 'Route53 Subdomains': {}, 'Lambda Credential Harvesting': {}, 'CloudFront Distributions': { Global: [] }, 'API Custom Domains': {} }, network_ports: [], lambda_credentials: [], summary: {} }],
  ['03_guardduty.js', 'buildGuarddutyView', 'guardduty-view', 'guarddutyApiData', { status: [], findings: [] }],
  ['04_ecr.js', 'buildEcrView', 'ecr-view', 'ecrApiData', { repositories: [] }],
  ['05_waf.js', 'buildWafView', 'waf-view', 'wafApiData', { acls: [], ip_sets: [] }],
  ['09_acm.js', 'buildAcmView', 'acm-view', 'acmApiData', { certificates: [] }],
  ['11_databases.js', 'buildDatabasesView', 'databases-view', 'databasesApiData', {}],
  ['12_kms_secrets.js', 'buildKmsSecretsView', 'kms-secrets-view', 'kmsApiData', { keys: [] }],
  ['14_connectivity.js', 'buildConnectivityView', 'connectivity-view', 'connectivityApiData', { peering_connections: [], tgw_attachments: [], vpn_connections: [], vpc_endpoints: [], nat_gateways: [] }],
  ['18_codepipeline.js', 'buildCodePipelineView', 'codepipeline-view', 'codepipelineApiData', { pipelines: [] }]
];
for (const [file, builder, rootId, dataName, results] of specs) {
  const dom = new JSDOM(`<div id="${rootId}"></div><div id="sh-ecr-findings-container"></div><div id="sh-waf-findings-container"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div><div id="sh-iam-findings-container"></div>`, { url: 'http://localhost/' });
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  window[dataName] = { metadata: { executionDate: '2026-01-01' }, results };
  window.securityHubApiData = { results: { findings: { exposureFindings: [], iamFindings: [], ecrFindings: [], wafFindings: [], cloudwatchFindings: [] } } };
  window.scopedResources = {};
  window.allAvailableRegions = [];
  window.computeApiData = { results: { ec2_instances: [] } };
  window.Chart = function Chart() {};
  globalThis.Chart = window.Chart;
  const module = await import(new URL(file, viewsDir));
  assert.doesNotThrow(() => module[builder](), `${file} should render without exceptions`);
  assert.equal(dom.window.document.getElementById(rootId).querySelector('h3') && [...dom.window.document.getElementById(rootId).querySelectorAll('h3')].some(el => el.textContent.trim() === 'Audit Guidance'), false, `${file} should not render Audit Guidance`);
  dom.window.close();
}
console.log('Audit Guidance absence and view rendering checks passed');
