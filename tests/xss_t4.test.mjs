import assert from 'node:assert/strict';
import { makeDom, PAYLOADS, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';

const fixture = () => ({
  network: { metadata: { executionDate: '2025-01-01' }, results: {
    vpcs: [{ VpcId: 'vpc-1', Region: 'us-east-1', CidrBlock: '10.0.0.0/16', IsDefault: false, Tags: { Name: 'main' } }],
    acls: [{ AclId: 'acl-1', VpcId: 'vpc-1', Region: 'us-east-1', IsDefault: false, Tags: { Name: 'acl' } }],
    security_groups: [{ GroupId: 'sg-1', GroupName: 'web', VpcId: 'vpc-1', Region: 'us-east-1', Description: 'web', Tags: { Name: 'sg' }, IpPermissions: [] }],
    subnets: [{ SubnetId: 'subnet-1', VpcId: 'vpc-1', Region: 'us-east-1', CidrBlock: '10.0.1.0/24', Tags: { Name: 'private' } }], all_regions: ['us-east-1'],
    nat_gateways: [{ NatGatewayId: 'nat-1', SubnetId: 'subnet-1', VpcId: 'vpc-1', Tags: { Name: 'nat' } }]
  } }, compute: { metadata: {}, results: {
    ec2_instances: [{ InstanceId: 'i-1', Region: 'us-east-1', SubnetId: 'subnet-1', State: 'running', InstanceType: 't3.micro', SecurityGroups: ['sg-1'], Tags: { Name: 'ec2' } }],
    lambda_functions: [{ FunctionName: 'fn', Runtime: 'nodejs', Region: 'us-east-1', VpcConfig: { VpcId: 'vpc-1', SubnetIds: ['subnet-1'], SecurityGroupIds: ['sg-1'] } }]
  } }, databases: { metadata: {}, results: {
    rds_instances: [{ DBInstanceIdentifier: 'db', Region: 'us-east-1', VpcId: 'vpc-1', SubnetIds: ['subnet-1'], SecurityGroupIds: ['sg-1'], Engine: 'postgres' }],
    aurora_clusters: [{ ClusterIdentifier: 'aurora', Region: 'us-east-1', VpcId: 'vpc-1', SubnetIds: ['subnet-1'], SecurityGroupIds: ['sg-1'], Engine: 'aurora' }]
  } }
});
function poison(value, payload) {
  if (typeof value === 'string') return payload;
  if (Array.isArray(value)) return value.map(item => poison(item, payload));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, poison(item, payload)]));
  return value;
}
function install(data) {
  window.networkPoliciesApiData = data.network; window.computeApiData = data.compute; window.databasesApiData = data.databases;
  window.scopedResources = {}; window.iamApiData = { metadata: { accountId: '123' } };
  for (const name of ['openScopeModal', 'copyToClipboard']) window[name] = () => {};
  document.body.innerHTML = '<div id="network-policies-view"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>';
}
const baseline = await import(new URL('./baseline/audithor_project/static/js/views/13_network_policies.js', import.meta.url));
const converted = await import(new URL('../audithor_project/static/js/views/13_network_policies.js', import.meta.url));
const tabIds = ['np-summary-content', 'np-vpcs-content', 'np-acls-content', 'np-sgs-content', 'np-diagram-container', 'np-detail-content'];
function render(module, data) { install(data); module.buildNetworkPoliciesView(); return tabIds.map(id => document.getElementById(id)); }
const parityDom = makeDom('<div id="network-policies-view"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>');
const benign = fixture();
const originalRoots = render(baseline, structuredClone(benign));
const convertedRoots = render(converted, structuredClone(benign));
for (let i = 0; i < tabIds.length; i++) {
  assert.equal(benignText(convertedRoots[i]), benignText(originalRoots[i]), `${tabIds[i]} text parity`);
  assert.deepEqual(tagSequence(convertedRoots[i]), tagSequence(originalRoots[i]), `${tabIds[i]} tag parity`);
}
function openResourcesModal(module, data) {
  install(data);
  module.buildNetworkPoliciesView();
  document.querySelector('.view-sg-resources-btn').click();
  return document.getElementById('modal-content');
}
const baselineModal = openResourcesModal(baseline, structuredClone(benign));
const convertedModal = openResourcesModal(converted, structuredClone(benign));
assert.equal(benignText(convertedModal), benignText(baselineModal), 'associated resources modal text parity');
assert.deepEqual(tagSequence(convertedModal), tagSequence(baselineModal), 'associated resources modal tag parity');
assert.ok(convertedModal.querySelectorAll('ul li').length > 0, 'associated modal renders resource list items');
assert.doesNotMatch(convertedModal.textContent, /^\\s*<div/);
for (const payload of PAYLOADS) {
  const dom = makeDom('<div id="network-policies-view"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>');
  const data = poison(fixture(), payload); install(data); converted.buildNetworkPoliciesView();
  const root = document.getElementById('network-policies-view'); assertNoInjection(window, root); clickAll(window, root);
  document.querySelector('.view-sg-resources-btn').click();
  assertNoInjection(window, document.getElementById('details-modal'));
  converted.openModalWithVpcTags(0); assertNoInjection(window, document.getElementById('details-modal'));
  dom.window.close();
}
const empty = { network: { metadata: {}, results: { vpcs: [], acls: [], security_groups: [], subnets: [], all_regions: [], nat_gateways: [] } }, compute: { metadata: {}, results: { ec2_instances: [], lambda_functions: [] } }, databases: { metadata: {}, results: { rds_instances: [], aurora_clusters: [] } } };
const dom = makeDom('<div id="network-policies-view"></div>'); install(empty); assert.doesNotThrow(() => converted.buildNetworkPoliciesView()); dom.window.close();
parityDom.window.close();
console.log('Network policy parity and payload checks passed');
