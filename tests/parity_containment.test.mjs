import assert from 'node:assert/strict';
import { assertOrderedSubsequence, assertTextContainsInOrder } from './helpers/xss_payloads.mjs';

for (const check of [assertOrderedSubsequence, assertTextContainsInOrder]) assert.equal(typeof check, 'function');
for (const check of [assertOrderedSubsequence]) {
  assert.doesNotThrow(() => check(['one', 'two'], ['one', 'two'], 'equal view'));
  assert.doesNotThrow(() => check(['zero', 'one', 'extra', 'two'], ['one', 'two'], 'expanded view'));
  assert.throws(() => check(['one'], ['one', 'missing'], 'missing view'), /missing view.*missing.*1/i);
  assert.throws(() => check(['two', 'one'], ['one', 'two'], 'reordered view'), /reordered view.*two.*1/i);
}
assert.doesNotThrow(() => assertTextContainsInOrder('one two', 'one two', 'equal text'));
assert.doesNotThrow(() => assertTextContainsInOrder('zero one extra two', 'one two', 'expanded text'));
assert.throws(() => assertTextContainsInOrder('one', 'one missing', 'missing text'), /missing text.*missing.*1/i);
assert.throws(() => assertTextContainsInOrder('two one', 'one two', 'reordered text'), /reordered text.*two.*1/i);

// A real header-token loss must fail even when unrelated content was added.
assert.throws(() => assertTextContainsInOrder('Account extra Region', 'Account Region Status', '01_iam.js'), /01_iam\.js.*Status.*2/i);
