import assert from 'node:assert/strict';
import { makeDom, PAYLOADS, assertNoInjection, clickAll, benignText, tagSequence } from './helpers/xss_payloads.mjs';
import { installActionDelegation } from '../audithor/static/js/safe_html.js';

const cloudwatchFixture = () => ({ metadata: { executionDate: '2025-01-01' }, results: { alarms: [{ Region: 'us-east-1', AlarmName: 'CPU', StateValue: 'OK', Namespace: 'AWS/EC2', MetricName: 'CPUUtilization', ComparisonOperator: 'GreaterThanThreshold', Threshold: 80, AlarmActions: [] }], topics: [{ Region: 'us-east-1', TopicArn: 'arn:aws:sns:us-east-1:123:alerts', Subscriptions: [{ Endpoint: 'ops@example.com' }] }] } });
const poison = (value, payload) => typeof value === 'string' ? payload : Array.isArray(value) ? value.map(item => poison(item, payload)) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, poison(item, payload)])) : value;
const cloudwatchBaseline = await import(new URL('./baseline/audithor_project/static/js/views/07_cloudwatch.js', import.meta.url));
const cloudwatchConverted = await import(new URL('../audithor/static/js/views/07_cloudwatch.js', import.meta.url));
function renderCloudwatch(module, data) { window.cloudwatchApiData = data; window.securityHubApiData = { results: { findings: { cloudwatchFindings: [] } } }; document.body.innerHTML = '<div id="cloudwatch-view"></div>'; module.buildCloudwatchView(); return document.getElementById('cloudwatch-view'); }
const parityDom = makeDom('<div></div>');
const original = renderCloudwatch(cloudwatchBaseline, structuredClone(cloudwatchFixture())); const safe = renderCloudwatch(cloudwatchConverted, structuredClone(cloudwatchFixture()));
assert.equal(benignText(safe), benignText(original)); assert.deepEqual(tagSequence(safe), tagSequence(original));
for (const payload of PAYLOADS) { const dom = makeDom('<div></div>'); const root = renderCloudwatch(cloudwatchConverted, poison(cloudwatchFixture(), payload)); assertNoInjection(window, root); window.toggleAlarmDetails = cloudwatchConverted.toggleAlarmDetails; clickAll(window, root); dom.window.close(); }
parityDom.window.close();
console.log('CloudWatch parity and payload checks passed');

const cloudtrailFixture = () => ({ metadata: { executionDate: '2025-01-01' }, results: {
  trails: [{ Name: 'main-trail', HomeRegion: 'us-east-1', IsLogging: true, IsMultiRegionTrail: true, LogFileValidationEnabled: true, KmsKeyId: 'key-1', S3BucketName: 'logs', CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123:log-group:trail' }],
  events: [{ EventId: 'event-1', EventTime: '2025-01-01T00:00:00Z', EventName: 'ConsoleLogin', Username: 'operator', EventRegion: 'us-east-1', SourceIPAddress: '192.0.2.1' }],
  trailguard_findings: [{ TrailName: 'main-trail', Region: 'us-east-1', TrailArn: 'arn:aws:cloudtrail:us-east-1:123:trail/main', DirectCloudTrailEventBridge: { CloudTrailEventBridgeEnabled: true, Rules: [{ Name: 'direct-rule', Region: 'us-east-1', Targets: [{ Arn: 'arn:aws:sns:us-east-1:123:topic' }], SNSTargets: [{ TopicName: 'alerts', TopicArn: 'arn:aws:sns:us-east-1:123:alerts', DisplayName: 'Alerts', RuleName: 'direct-rule', SubscriptionCount: 1, Subscriptions: [{ Protocol: 'email', Endpoint: 'ops@example.com', Status: 'Confirmed' }] }] }] }, EventBridgeFlow: { S3EventBridgeEnabled: true, CompleteFlow: true, Rules: [{ Name: 's3-rule', Targets: [{ Arn: 'arn:aws:lambda:us-east-1:123:function:handler' }], SNSTargets: [] }] }, S3Destination: { BucketName: 'logs', Notifications: [{ Type: 'SNS', Target: 'arn:aws:sns:us-east-1:123:alerts' }] }, CloudWatchDestination: { LogGroupName: 'trail', Subscriptions: [{ Type: 'Lambda', Target: 'arn:aws:lambda:us-east-1:123:function:handler' }], MetricFilters: [] } }]
} });
const cloudtrailBaseline = await import(new URL('./baseline/audithor_project/static/js/views/06_cloudtrail.js', import.meta.url));
const cloudtrailConverted = await import(new URL('../audithor/static/js/views/06_cloudtrail.js', import.meta.url));
const cloudtrailMarkup = '<div id="cloudtrail-view"></div><input id="access-key-input" value="key"><input id="secret-key-input" value="secret"><input id="session-token-input" value=""><div id="details-modal" class="hidden"><h2 id="modal-title"></h2><div id="modal-content"></div></div>';
function renderCloudtrail(module, data) {
  document.body.innerHTML = cloudtrailMarkup;
  window.cloudtrailApiData = data; window.securityHubApiData = { results: { findings: { cloudtrailFindings: [] } } };
  window.allAvailableRegions = ['us-east-1']; window.lastCloudtrailLookupResults = undefined;
  installActionDelegation(document);
  window.showCloudtrailEventDetails = module.showCloudtrailEventDetails;
  module.buildCloudtrailView();
  return document.getElementById('cloudtrail-view');
}
const cloudtrailParityDom = makeDom(cloudtrailMarkup);
const oldCloudtrailRoot = renderCloudtrail(cloudtrailBaseline, structuredClone(cloudtrailFixture()));
const newCloudtrailRoot = renderCloudtrail(cloudtrailConverted, structuredClone(cloudtrailFixture()));
const cloudtrailOriginalText = benignText(oldCloudtrailRoot);
const cloudtrailConvertedText = benignText(newCloudtrailRoot);
assert.deepEqual(tagSequence(newCloudtrailRoot), tagSequence(oldCloudtrailRoot), 'CloudTrail main view tag parity');

async function searchAndOpenEvent(module, data) {
  const root = renderCloudtrail(module, data);
  document.getElementById('ct-event-name').value = 'ConsoleLogin';
  document.getElementById('ct-start-date').value = '01-01-2025';
  document.getElementById('ct-end-date').value = '02-01-2025';
  document.getElementById('ct-lookup-region').value = 'us-east-1';
  const lookup = document.getElementById('ct-lookup-results-container');
  document.getElementById('ct-run-lookup-btn').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  const resultText = benignText(lookup);
  const resultTags = tagSequence(lookup);
  const row = lookup.querySelector('[data-event-id], #event-row-event-1');
  if (row) row.click();
  const detail = document.getElementById('ct-event-detail-container');
  return { resultText, resultTags, detailText: detail ? benignText(detail) : '', detailTags: detail ? tagSequence(detail) : [] };
}
const lookupEvents = [{ EventId: 'event-1', EventTime: '2025-01-01T00:00:00Z', EventName: 'ConsoleLogin', Username: 'operator', EventRegion: 'us-east-1', SourceIPAddress: '192.0.2.1', CloudTrailEvent: '{"eventName":"ConsoleLogin"}' }];
const originalFetch = globalThis.fetch;
let oldLookup, newLookup;
try {
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ results: { events: lookupEvents } }) });
  const dom = makeDom(cloudtrailMarkup);
  oldLookup = await searchAndOpenEvent(cloudtrailBaseline, structuredClone(cloudtrailFixture()));
  newLookup = await searchAndOpenEvent(cloudtrailConverted, structuredClone(cloudtrailFixture()));
  dom.window.close();
} finally { globalThis.fetch = originalFetch; }
assert.equal(newLookup.resultText, oldLookup.resultText, 'CloudTrail lookup result text parity');
assert.deepEqual(newLookup.resultTags, oldLookup.resultTags, 'CloudTrail lookup result tag parity');
assert.equal(newLookup.detailText, oldLookup.detailText, 'CloudTrail event detail text parity');
assert.deepEqual(newLookup.detailTags, oldLookup.detailTags, 'CloudTrail event detail tag parity');
assert.equal(cloudtrailConvertedText, cloudtrailOriginalText, 'CloudTrail main view text parity');
for (const payload of PAYLOADS) {
  const dom = makeDom(cloudtrailMarkup);
  const root = renderCloudtrail(cloudtrailConverted, poison(cloudtrailFixture(), payload));
  assertNoInjection(window, root); clickAll(window, root);
  dom.window.close();
}
cloudtrailParityDom.window.close();
console.log('CloudTrail main-view, lookup, event-detail parity and payload checks passed');
