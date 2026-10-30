import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { pathToFileURL } from 'node:url';
import { makeDom, assertNoInjection, clickAll, benignText, tagSequence, PAYLOADS } from './helpers/xss_payloads.mjs';
import { installActionDelegation } from '../audithor_project/static/js/safe_html.js';

const fixtures = {
  compute: { metadata: { executionDate: '2026-01-01' }, results: { ec2_instances: [{ ARN: 'arn:aws:ec2:us-east-1:123:instance/i-1', Region: 'us-east-1', InstanceId: 'i-1', VpcId: 'vpc-1', SecurityGroups: ['sg-1'], IamInstanceProfile: 'role', State: 'running', PublicIpAddress: '127.0.0.1', OperatingSystem: 'Linux', Tags: { Name: 'safe' } }], lambda_functions: [{ ARN: 'arn:aws:lambda:us-east-1:123:function:f', Region: 'us-east-1', FunctionName: 'f', Role: 'arn:aws:iam::123:role/r', Runtime: 'nodejs', Tags: { Name: 'safe' }, VpcConfig: { VpcId: 'vpc-1' } }], eks_clusters: [{ ARN: 'arn:aws:eks:us-east-1:123:cluster/eks-one', Region: 'us-east-1', ClusterName: 'eks-one' }], ecs_clusters: [{ ARN: 'arn:aws:ecs:us-east-1:123:cluster/ecs-one', Region: 'us-east-1', ClusterName: 'ecs-one', Status: 'ACTIVE', ServicesCount: 2 }] } },
  databases: { metadata: { executionDate: '2026-01-01' }, results: { rds_instances: [{ ARN: 'arn:aws:rds:us-east-1:123:db:rds-one', Region: 'us-east-1', DBInstanceIdentifier: 'rds-one', Engine: 'postgres', DBInstanceStatus: 'available', PubliclyAccessible: false, Encrypted: true, KmsKeyAlias: 'alias/db' }], aurora_clusters: [{ ARN: 'arn:aws:rds:us-east-1:123:cluster:aurora-one', Region: 'us-east-1', ClusterIdentifier: 'aurora-one', Status: 'available', Encrypted: true, KmsKeyAlias: 'alias/aurora' }], dynamodb_tables: [{ ARN: 'arn:aws:dynamodb:us-east-1:123:table/ddb-one', Region: 'us-east-1', TableName: 'ddb-one', Encrypted: true, KmsKeyAlias: 'alias/ddb' }], documentdb_clusters: [{ ARN: 'arn:aws:docdb:us-east-1:123:cluster/doc-one', Region: 'us-east-1', ClusterIdentifier: 'doc-one', Status: 'available', Encrypted: true, KmsKeyAlias: 'alias/doc' }] } }
};
const clonePayload = (value, payload) => typeof value === 'string' ? payload : Array.isArray(value) ? value.map(item => clonePayload(item, payload)) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, clonePayload(item, payload)])) : value;
const assertNoLiteralMarkup = root => assert.doesNotMatch(root.textContent, /<(?:div|td|tr|span|pre)\b|<\//i);
const root = new URL('../audithor_project/static/js/views/', import.meta.url);
const baselineRoot = new URL('./baseline/audithor_project/static/js/views/', import.meta.url);
const views = [
  { file: '10_compute.js', id: 'compute-view', global: 'computeApiData', build: 'buildComputeView', fixture: fixtures.compute },
  { file: '11_databases.js', id: 'databases-view', global: 'databasesApiData', build: 'buildDatabasesView', fixture: fixtures.databases }
];
for (const view of views) {
  const original = await import(pathToFileURL(new URL(view.file, baselineRoot).pathname));
  const converted = await import(new URL(view.file, root));
  const render = async (module, fixture) => {
    const dom = makeDom(`<div id="${view.id}"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>`);
    globalThis.window = dom.window; globalThis.document = dom.window.document;
    dom.window[view.global] = structuredClone(fixture);
    dom.window.scopedResources = {}; dom.window.allAvailableRegions = ['us-east-1'];
    dom.window.iamApiData = { results: { roles: [{ RoleName: 'r', IsPrivileged: true, PrivilegeReasons: ['AdministratorAccess'] }] } };
    dom.window.fetch = async () => ({ ok: true, json: async () => ({}) });
    dom.window.openScopeModal = () => {};
    dom.window.copyToClipboard = () => {};
    for (const name of ['openModalWithEc2Tags', 'openModalWithLambdaTags', 'openModalWithLambdaRole']) {
      if (module[name]) dom.window[name] = module[name];
    }
    installActionDelegation(dom.window.document);
    module[view.build]();
    return { dom, container: dom.window.document.getElementById(view.id) };
  };
  const before = await render(original, view.fixture);
  const after = await render(converted, view.fixture);
  if (benignText(after.container) !== benignText(before.container)) {
    const actual = benignText(after.container), expected = benignText(before.container);
    const index = [...actual].findIndex((char, i) => char !== expected[i]);
    console.error('Parity difference', index, JSON.stringify(actual.slice(index - 20, index + 40)), JSON.stringify(expected.slice(index - 20, index + 40)));
  }
  assert.equal(benignText(after.container), benignText(before.container), `${view.file} parity text`);
  assert.deepEqual(tagSequence(after.container), tagSequence(before.container), `${view.file} parity structure`);
  assertNoLiteralMarkup(after.container);
  for (const tab of after.container.querySelectorAll('[data-tab]')) {
    tab.dispatchEvent(new after.dom.window.MouseEvent('click', { bubbles: true, cancelable: true }));
  }
  for (const tab of before.container.querySelectorAll('[data-tab]')) {
    tab.dispatchEvent(new before.dom.window.MouseEvent('click', { bubbles: true, cancelable: true }));
  }
  assert.equal(benignText(after.container), benignText(before.container), `${view.file} tab click parity text`);
  assert.deepEqual(tagSequence(after.container), tagSequence(before.container), `${view.file} tab click parity structure`);
  for (const payload of PAYLOADS) {
    const { dom, container } = await render(converted, clonePayload(view.fixture, payload));
    try { assertNoInjection(dom.window, container); } catch (error) {
      console.error(view.file, [...container.querySelectorAll('*')].flatMap(el => [...el.attributes].filter(attribute => /^on/i.test(attribute.name)).map(attribute => `${el.outerHTML.slice(0, 200)} [${attribute.name}]`)));
      throw error;
    }
    clickAll(dom.window, container);
  }
  if (view.file === '10_compute.js') {
    for (const [opener, index] of [['openModalWithEc2Tags', 0], ['openModalWithLambdaTags', 0], ['openModalWithLambdaRole', 0]]) {
      for (const module of [original, converted]) {
        const { dom, container } = await render(module, view.fixture);
        module[opener](index);
        const modalContent = dom.window.document.getElementById('modal-content');
        if (module === original) {
          var originalModal = { text: benignText(modalContent), tags: tagSequence(modalContent) };
        } else {
          assert.equal(benignText(modalContent), originalModal.text, `${opener} parity text`);
          assert.deepEqual(tagSequence(modalContent), originalModal.tags, `${opener} parity structure`);
          assertNoLiteralMarkup(modalContent);
        }
      }
      for (const payload of PAYLOADS) {
        const { dom } = await render(converted, clonePayload(view.fixture, payload));
        converted[opener](index);
        const modalContent = dom.window.document.getElementById('modal-content');
        assertNoInjection(dom.window, modalContent);
        clickAll(dom.window, modalContent);
      }
    }
  }
}
console.log('T7 parity and payload checks passed');
