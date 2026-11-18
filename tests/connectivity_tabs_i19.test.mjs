import { JSDOM } from 'jsdom';
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
let buildConnectivityView;
before(async () => {
  const dom = new JSDOM('<div id="connectivity-view"></div>', { runScripts: 'outside-only' });
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  ({ buildConnectivityView } = await import('../audithor/static/js/views/14_connectivity.js'));
});

test('connectivity sections and tab counters are placed correctly and tabs switch panes', () => {
  window.connectivityApiData = { metadata: { executionDate: 'today' }, results: {
    peering_connections: [], tgw_attachments: [{ TransitGatewayId: 'tgw-1' }], vpn_connections: [], vpc_endpoints: [], nat_gateways: [],
    network_firewalls: [{ Region: 'us-east-1', VpcId: 'vpc-1' }], route_tables: [{ Region: 'us-east-1', VpcId: 'vpc-1', RouteTableId: 'rtb-1', Routes: [{ GatewayId: 'igw-1' }] }],
    endpoint_coverage: [], transit_gateways: [{ TransitGatewayId: 'tgw-1' }], tgw_route_tables: [{ TransitGatewayRouteTableId: 'tgw-rtb-1' }], tgw_shares: [{ Principal: '123' }],
    Enrichment: { networkFirewall: { status: 'complete' }, routeTables: { status: 'complete' }, tgwRouting: { status: 'complete' }, tgwShares: { status: 'complete' } }
  } };
  buildConnectivityView();
  const root = document.querySelector('#connectivity-view');
  const paneFor = title => [...root.querySelectorAll('h3')].find(h => h.textContent === title).closest('.connectivity-tab-content');
  assert.equal(paneFor('Transit Gateway Settings').id, 'conn-tgw-content');
  assert.equal(paneFor('TGW Route Tables').id, 'conn-tgw-content');
  assert.equal(paneFor('RAM Principals').id, 'conn-tgw-content');
  assert.equal(paneFor('Network Firewalls').id, 'conn-netfw-content');
  assert.equal(paneFor('Route Tables').id, 'conn-routetables-content');
  assert.equal(paneFor('Endpoint Coverage').id, 'conn-endpoints-content');
  assert.equal(root.querySelector('#conn-tgw-content h3').textContent, 'Transit Gateway');
  assert.match(root.querySelector('#conn-routetables-content').textContent, /Internet gateway route/);
  const labels = [...root.querySelectorAll('#connectivity-tabs a')].map(a => a.textContent);
  assert.ok(labels.includes('Transit Gateway (1)'));
  assert.ok(labels.includes('Network Firewall (1)'));
  assert.ok(labels.includes('Route Tables (1)'));
  for (const id of ['conn-tgw-content', 'conn-netfw-content', 'conn-routetables-content', 'conn-endpoints-content']) {
    const link = root.querySelector(`[data-tab="${id}"]`);
    link.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.equal(root.querySelector(`#${id}`).classList.contains('hidden'), false);
    for (const other of root.querySelectorAll('.connectivity-tab-content')) if (other.id !== id) assert.equal(other.classList.contains('hidden'), true);
  }
  window.connectivityApiData.results.network_firewalls = [];
  buildConnectivityView();
  assert.match(root.querySelector('#conn-netfw-content').textContent, /No AWS Network Firewall found/);
  window.connectivityApiData.results.network_firewalls = [{ Region: 'us-east-1', RuleGroups: [{ RuleGroupName: '<img src=x onerror=alert(1)>' }] }];
  buildConnectivityView();
  assert.equal(root.querySelector('img'), null);
  assert.match(root.textContent, /<img src=x onerror=alert\(1\)>/);
});
