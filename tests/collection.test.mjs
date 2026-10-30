import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const source = readFileSync(new URL('../audithor/static/js/collection.js', import.meta.url), 'utf8');
const { coverageMessage, coverageIsComplete, emptyCollectionMessage, renderCollectionNotice, isMigratedCollector, failedCollectionResponse } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const partial = { results: { _collection: { status: 'partial', coverageKnown: true, scanId: 'scan', units: [
    { service: 'acm', operation: 'list_certificates', status: 'failed', awsCode: '<img src=x onerror=alert(1)>' }
] } } };
assert.equal(coverageIsComplete(partial), false);
assert.match(coverageMessage(partial), /Incomplete/);
assert.match(emptyCollectionMessage(partial, 'No resources'), /could not be established/);
assert.match(coverageMessage({ results: {} }), /unknown/);
assert.match(coverageMessage({ results: { _collection: { status: 'failed' } } }), /failed/);
assert.equal(coverageIsComplete({ results: { _collection: { status: 'complete', coverageKnown: true } } }), true);
assert.equal(isMigratedCollector('acm'), true);
assert.equal(isMigratedCollector('other'), false);
assert.deepEqual(failedCollectionResponse('inspector', 'scan').results, { scan_status: [], findings: [], findingsStatus: 'failed', _collection: { status: 'failed', coverageKnown: false, scanId: 'scan', units: [{ service: 'inspector', operation: 'api_request', status: 'failed', category: 'api_error' }] } });
assert.equal(failedCollectionResponse('other', 'scan'), null);
class Element {
    children = [];
    dataset = {};
    textContent = '';
    append(child) { this.children.push(child); }
    prepend(child) { this.children.unshift(child); }
    setAttribute() {}
    querySelectorAll() { return []; }
    set innerHTML(value) { throw new Error('Diagnostics must not render HTML'); }
}
globalThis.document = { createElement: () => new Element() };
const container = new Element();
renderCollectionNotice(container, partial);
assert.equal(container.children.length, 1);
const row = container.children[0].children[1].children[1];
assert.match(row.textContent, /<img/); // literal text, never parsed as markup
const imported = JSON.parse(JSON.stringify(partial));
assert.deepEqual(imported.results._collection, partial.results._collection);
console.log('Coverage, empty-state, safe DOM rendering and JSON round-trip checks passed');
