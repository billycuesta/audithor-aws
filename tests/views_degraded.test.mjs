import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';

const { window } = new JSDOM('<div id="acm-view"></div><div id="databases-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
window.scopedResources = {};
window.securityHubApiData = null;
const root = new URL('../audithor_project/static/js/views/', import.meta.url).href;
const coverage = { status: 'partial', coverageKnown: true, units: [] };

const acm = await import(root + '09_acm.js');
window.acmApiData = { metadata: { executionDate: '2026-10-25' }, results: { certificates: [], _collection: coverage } };
acm.buildAcmView();
assert.match(document.getElementById('acm-view').textContent, /Review the collection details above to see which checks failed\./);
assert.doesNotMatch(document.getElementById('acm-view').textContent, /This account does not have SSL\/TLS certificates/);
window.acmApiData.results._collection = { status: 'complete', coverageKnown: true, units: [] };
acm.buildAcmView();
assert.match(document.getElementById('acm-view').textContent, /This account does not have SSL\/TLS certificates/);

const db = await import(root + '11_databases.js');
window.databasesApiData = { metadata: { executionDate: '2026-10-25' }, results: {
  rds_instances: [{ DBInstanceIdentifier: 'db-one', Region: 'us-east-1', NetworkDetailsStatus: 'unknown', SubnetIds: null }],
  aurora_clusters: [{ ClusterIdentifier: 'cluster-one', Region: 'us-west-2', NetworkDetailsStatus: 'unknown', SubnetIds: null }],
  dynamodb_tables: [
    { TableName: 'same-name', Region: 'us-east-1' },
    { TableName: 'same-name', Region: 'us-west-2' },
    { TableName: 'named', Region: 'eu-west-1', ARN: 'arn:aws:dynamodb:eu-west-1:123:table/named' }
  ],
  documentdb_clusters: [], _collection: coverage
} };
assert.doesNotThrow(() => db.buildDatabasesView());
const dbText = document.getElementById('databases-view').textContent;
assert.match(dbText, /db-one/);
assert.match(dbText, /cluster-one/);
assert.doesNotMatch(document.querySelector('#db-rds-content').textContent, /undefined|null|NaN/);
assert.doesNotMatch(document.querySelector('#db-aurora-content').textContent, /undefined|null|NaN/);
const dynamo = document.getElementById('databases-view').querySelector('#db-dynamodb-content');
const buttons = [...dynamo.querySelectorAll('tbody tr')].map(row => [...row.querySelectorAll('button')]);
for (const [button, expectedScopeKey] of [
  [buttons[0][0], 'dynamodb:us-east-1:same-name'],
  [buttons[1][0], 'dynamodb:us-west-2:same-name'],
  [buttons[2][0], 'arn:aws:dynamodb:eu-west-1:123:table/named']
]) {
  assert.equal(button.getAttribute('data-act'), 'openScopeModal');
  assert.equal(JSON.parse(button.getAttribute('data-args'))[0], expectedScopeKey);
}
assert.equal(buttons[0][1].disabled, true);
assert.match(buttons[0][1].title, /ARN is unavailable/);
assert.equal(buttons[2][1].disabled, false);

window.acmApiData = { metadata: { executionDate: '2026-10-25' }, results: { certificates: [{ CertificateArn: 'arn:aws:acm:eu-west-1:123:certificate/example', DomainName: 'example.com', Region: 'eu-west-1', DetailsStatus: 'unknown' }], _collection: coverage } };
assert.doesNotThrow(() => acm.buildAcmView());
const acmText = document.getElementById('acm-view').textContent;
assert.match(acmText, /example\.com/);
assert.doesNotMatch(acmText, /undefined|null|NaN/);
assert.equal(document.getElementById('acm-issued-certs').textContent, '0');
console.log('Degraded ACM and database view checks passed');
