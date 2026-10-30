import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { PAYLOADS, assertNoInjection, benignText, clickAll, makeDom, tagSequence } from './helpers/xss_payloads.mjs';
import { installActionDelegation } from '../audithor/static/js/safe_html.js';

const baselineUrl = new URL('./baseline/audithor_project/static/js/views/01_iam.js', import.meta.url).href;
const currentUrl = new URL('../audithor/static/js/views/01_iam.js', import.meta.url).href;
const inputMarkup = '<div id="iam-view"></div><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div><input id="access-key-input"><input id="secret-key-input"><input id="session-token-input"><div id="iam-search-results-container"></div><div id="iam-search-btn"></div><span id="search-btn-text"></span><div id="iam-sh-filter-controls"></div><div id="sh-iam-findings-container"></div>';
const makeFixture = () => ({
  iamApiData: null, securityHubApiData: { results: { findings: { iamFindings: [] } } }, securityHubStatusApiData: null,
  accessAnalyzerApiData: { results: { findings: [], summary: [] } }, federationApiData: null,
});
const renderBuilder = async (url) => {
  const dom = makeDom(inputMarkup);
  Object.assign(dom.window, makeFixture());
  const module = await import(url);
  module.buildIamView();
  return { dom, module, root: dom.window.document.getElementById('iam-view') };
};

// PARITY: benign fixture rendered by baseline and converted implementations.
const baseline = await renderBuilder(baselineUrl);
const current = await renderBuilder(currentUrl);
assert.equal(benignText(current.root), benignText(baseline.root));
assert.deepEqual(tagSequence(current.root), tagSequence(baseline.root));
baseline.dom.window.close();
current.dom.window.close();

function replaceStrings(value, payload, seen = new WeakMap()) {
  if (typeof value === 'string') return payload;
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return seen.get(value);
  const clone = Array.isArray(value) ? [] : {};
  seen.set(value, clone);
  for (const [key, child] of Object.entries(value)) clone[key] = replaceStrings(child, payload, seen);
  return clone;
}
const safeFixture = (payload) => replaceStrings({
  iamApiData: { metadata: { accountId: payload, executionDate: payload }, results: {
    users: [{ UserName: payload, IsPrivileged: false, PasswordEnabled: true, PasswordLastUsed: payload, MFADevices: [], Groups: [payload], Roles: [{ RoleName: payload }], AttachedPolicies: [payload], InlinePolicies: [payload], AccessKeys: [{ AccessKeyId: payload, CreateDate: '2020-01-01', Status: payload, LastUsedDate: 'N/A' }], mfa_compliance: null }],
    groups: [{ GroupName: payload, IsPrivileged: false, AttachedPolicies: [payload], CreateDate: '2020-01-01' }],
    roles: [{ RoleName: payload, IsPrivileged: false, AttachedPolicies: [payload], CreateDate: '2020-01-01' }],
    password_policy: { Error: true },
  } },
  accessAnalyzerApiData: { results: { findings: [{ Region: payload, ResourceType: payload, Resource: payload, Principal: payload, Action: payload }], summary: [{ Region: payload, Name: payload, Type: payload }] } },
  federationApiData: { results: { iam_federation: { account_alias: payload }, identity_center: { status: 'Found', instance_arn: payload, assignments: [{ GroupId: payload, GroupName: payload, PermissionSetName: payload, AccountId: payload }] } } },
  user: { UserName: payload, Roles: [{ RoleName: payload }], Groups: [payload], AccessKeys: [{ AccessKeyId: payload, CreateDate: '2020-01-01', Status: payload, LastUsedDate: 'N/A' }] },
  payload,
}, payload);

for (const payload of PAYLOADS) {
  // Exported view builder and its AWS-backed table renderers.
  {
    const { dom, module, root } = await renderBuilder(currentUrl + `?builder=${encodeURIComponent(payload)}`);
    const data = safeFixture(payload);
    Object.assign(dom.window, { iamApiData: data.iamApiData, accessAnalyzerApiData: data.accessAnalyzerApiData, federationApiData: data.federationApiData });
    module.buildIamView();
    assertNoInjection(dom.window, dom.window.document);
    clickAll(dom.window, dom.window.document);
    assertNoInjection(dom.window, dom.window.document);
    dom.window.close();
  }
  // Modal openers: every string in the relevant fixture takes this payload.
  for (const opener of ['openModalWithUserRoles', 'openModalWithSsoDetails', 'openModalWithAccessKeyDetails', 'openModalWithUserGroups']) {
    const { dom, module } = await renderBuilder(currentUrl + `?opener=${opener}&payload=${encodeURIComponent(payload)}`);
    const data = safeFixture(payload);
    dom.window.iamApiData = data.iamApiData;
    dom.window.iamApiData.results.users[0] = data.user;
    dom.window.fetch = async () => ({ ok: true, json: async () => ({ assumable_roles: [{ RoleName: payload, RoleArn: payload }], members: [payload] }) });
    installActionDelegation(dom.window.document);
    await module[opener](opener === 'openModalWithUserRoles' ? data.user.UserName : payload, 0);
    assertNoInjection(dom.window, dom.window.document);
    clickAll(dom.window, dom.window.document);
    assertNoInjection(dom.window, dom.window.document);
    dom.window.close();
  }
  // Also exercise the exported Security Hub updater with payload-backed data.
  {
    const { dom, module } = await renderBuilder(currentUrl + `?security=${encodeURIComponent(payload)}`);
    dom.window.securityHubApiData = { results: { findings: { iamFindings: [{ Title: payload, Description: payload, Severity: { Label: payload }, Resources: [{ Id: payload }] }] } } };
    module.updateSecurityHubDashboard();
    assertNoInjection(dom.window, dom.window.document);
    clickAll(dom.window, dom.window.document);
    assertNoInjection(dom.window, dom.window.document);
    dom.window.close();
  }
}
console.log('IAM XSS parity and payload checks passed');
