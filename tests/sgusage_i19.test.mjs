import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="network-policies-view"></div><div id="details-modal"><span id="modal-title"></span><div id="modal-content"></div></div>');
globalThis.window = window; globalThis.document = window.document; window.scopedResources = {};
window.networkPoliciesApiData = { metadata: { executionDate: 'today' }, results: {
  vpcs: [], acls: [], all_regions: ['us-east-1'], subnets: [], nat_gateways: [],
  security_groups: [
    { Region: 'us-east-1', GroupId: 'sg-used', GroupName: 'used', VpcId: 'vpc-1', Description: 'attached', IngressRules: [], EgressRules: [], Enrichment: { securityGroupRules: { status: 'complete' } } },
    { Region: 'us-east-1', GroupId: 'sg-unused', GroupName: 'unused', VpcId: 'vpc-1', Description: 'unused', IngressRules: [], EgressRules: [], Enrichment: { securityGroupRules: { status: 'complete' } } }
  ],
  network_interfaces: [
    { Region: 'us-east-1', NetworkInterfaceId: 'eni-1', InterfaceType: 'vpc_endpoint', Description: 'endpoint', Groups: ['sg-used'], PublicIp: '198.51.100.1' },
    { Region: 'us-east-1', NetworkInterfaceId: 'eni-2', InterfaceType: 'vpc_endpoint', Description: 'endpoint', Groups: ['sg-used'], PublicIp: null },
    { Region: 'us-east-1', NetworkInterfaceId: 'eni-3', InterfaceType: 'network_load_balancer', Description: '<img src=x onerror=alert(1)>', Groups: ['sg-used'], PublicIp: null }
  ], Enrichment: { networkInterfaces: { status: 'complete' } }
} };
window.computeApiData = { results: { ec2_instances: [{Region:'us-east-1',SecurityGroups:['sg-used']}], lambda_functions: [{Region:'us-east-1',VpcConfig:{SecurityGroupIds:['sg-used']}}] } };
window.databasesApiData = { results: { rds_instances: [{Region:'us-east-1',SecurityGroupIds:['sg-used']}], aurora_clusters: [] } };
const root = new URL('../audithor/static/js/views/', import.meta.url).href;
const view = await import(root + '13_network_policies.js');
view.buildNetworkPoliciesView('np-sgs-content');
const table = document.querySelector('#np-sgs-content table');
const header = [...table.querySelectorAll('th')].map(cell => cell.textContent.trim());
const rows = [...table.querySelectorAll('tbody tr')];
const used = rows.find(row => row.cells[1].textContent.trim() === 'sg-used');
const unused = rows.find(row => row.cells[1].textContent.trim() === 'sg-unused');
const cell = name => used.cells[header.indexOf(name)].textContent.trim();
assert.equal(cell('Network Interfaces'), 'vpc_endpoint — endpoint (2); network_load_balancer — <img src=x onerror=alert(1)> (1)');
assert.equal(cell('Public IP'), 'Yes — public IP');
assert.equal(used.cells[header.indexOf('Associated Resources')].textContent.trim(), '3');
assert.equal(unused.cells[header.indexOf('Network Interfaces')].textContent.trim(), 'Unused (no network interfaces)');
assert.equal(unused.cells[header.indexOf('Public IP')].textContent.trim(), 'No');
assert.equal(document.querySelector('#np-sgs-content img'), null);
assert.equal(used.cells.length, header.length);

window.networkPoliciesApiData.results.network_interfaces = undefined;
window.networkPoliciesApiData.results.Enrichment = {};
view.buildNetworkPoliciesView('np-sgs-content');
const oldTable = document.querySelector('#np-sgs-content table');
const oldHeader = [...oldTable.querySelectorAll('th')].map(cell => cell.textContent.trim());
const oldUsed = [...oldTable.querySelectorAll('tbody tr')].find(row => row.cells[1].textContent.trim() === 'sg-used');
assert.equal(oldUsed.cells[oldHeader.indexOf('Network Interfaces')].textContent.trim(), 'Not collected');
assert.equal(oldUsed.cells[oldHeader.indexOf('Public IP')].textContent.trim(), 'Not collected');
console.log('Network interface DOM checks passed');
