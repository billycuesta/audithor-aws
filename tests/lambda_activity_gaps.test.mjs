import { JSDOM } from 'jsdom';
import assert from 'node:assert/strict';
const { window } = new JSDOM('<div id="compute-view"></div>');
globalThis.window = window;
globalThis.document = window.document;
window.scopedResources = {};
window.allAvailableRegions = ['us-east-1'];
window.iamApiData = {results: {roles: []}};
window.computeApiData = {metadata: {executionDate: '2026-01-01'}, results: {
    ec2_instances: [], eks_clusters: [], ecs_clusters: [], lambda_functions: [{
        Region: 'us-east-1', FunctionName: 'worker', ARN: 'arn:lambda', Role: 'arn:role/service-role/worker',
        Runtime: 'python3.12', VpcConfig: {}, Tags: {}, Invocations90d: 7, LastInvocationDate: '2026-01-01',
        Enrichment: {activity: {status: 'complete'}}
    }]
}};
const moduleUrl = new URL('../audithor/static/js/views/10_compute.js', import.meta.url).href;
const view = await import(moduleUrl);
view.buildComputeView();
const root = document.getElementById('compute-view');
const lambdaTab = root.querySelector('[data-tab="compute-lambda-content"]');
lambdaTab.click();
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(8)').textContent.trim(), '7');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(9)').textContent.trim(), '2026-01-01');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(10)').textContent.trim(), 'Active');
window.computeApiData.results.lambda_functions[0].LastInvocationDate = '<img src=x onerror=alert(1)>';
view.buildComputeView();
root.querySelector('[data-tab="compute-lambda-content"]').click();
assert.equal(root.querySelectorAll('#compute-lambda-content img').length, 0);
assert.match(root.querySelector('#compute-lambda-content').textContent, /<img src=x onerror=alert\(1\)>/);
window.computeApiData.results.lambda_functions[0] = {Region: 'us-east-1', FunctionName: 'idle', ARN: 'arn:idle', VpcConfig: {}, Tags: {}, Invocations90d: 0, LastInvocationDate: null, Enrichment: {activity: {status: 'complete'}}};
view.buildComputeView();
root.querySelector('[data-tab="compute-lambda-content"]').click();
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(8)').textContent.trim(), '0');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(9)').textContent.trim(), 'None');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(10)').textContent.trim(), 'Unused');
window.computeApiData.results.lambda_functions[0] = {Region: 'us-east-1', FunctionName: 'old', ARN: 'arn:old', VpcConfig: {}, Tags: {}};
view.buildComputeView();
root.querySelector('[data-tab="compute-lambda-content"]').click();
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(8)').textContent.trim(), 'Not collected');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(9)').textContent.trim(), 'Not collected');
assert.equal(root.querySelector('#compute-lambda-content tbody tr td:nth-child(10)').textContent.trim(), 'Not collected');
console.log('Lambda activity view checks passed');
