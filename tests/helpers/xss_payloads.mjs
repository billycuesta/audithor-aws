import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

export const PAYLOADS = [
  '<img src=x onerror=window.__x=1>',
  '"><svg onload=window.__x=1>',
  "'); window.__x=1;//",
  '</td><script>window.__x=1</script>',
  '${window.__x=1}',
  '`template ${window.__x=1}`',
  'javascript:window.__x=1',
  '&lt;b&gt;',
  `quotes " ' and ampersand &`,
  'x'.repeat(10000),
  '安全性 🔐',
  '<iframe srcdoc="<script>window.__x=1</script>"></iframe>'
];

export function makeDom(html) {
  const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'http://localhost/' });
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  return dom;
}

export function assertNoInjection(window, root) {
  assert.equal(root.querySelector('script'), null);
  assert.equal([...root.querySelectorAll('*')].some(el => [...el.attributes].some(a => /^on/i.test(a.name))), false);
  assert.equal(window.__x, undefined);
}

export function clickAll(window, root) {
  for (const el of root.querySelectorAll('button, a, [data-act]')) {
    const names = Object.keys(window).filter(name => typeof window[name] === 'function');
    for (const name of names) {
      try { window[name] = () => {}; } catch {}
    }
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
  }
  assert.equal(window.__x, undefined);
}

export function assertOrderedSubsequence(actual, expected, label) {
  let actualIndex = 0;
  for (let expectedIndex = 0; expectedIndex < expected.length; expectedIndex++) {
    while (actualIndex < actual.length && actual[actualIndex] !== expected[expectedIndex]) actualIndex++;
    assert.ok(actualIndex < actual.length, `${label}: unmatched item ${JSON.stringify(expected[expectedIndex])} at index ${expectedIndex}`);
    actualIndex++;
  }
}

export function assertTextContainsInOrder(actual, expected, label) {
  assertOrderedSubsequence(actual.trim().split(/\s+/), expected.trim().split(/\s+/), label);
}

export const benignText = root => {
  const walker = root.ownerDocument.createTreeWalker(root, 4);
  const parts = [];
  while (walker.nextNode()) parts.push(walker.currentNode.nodeValue);
  return parts.join(' ').replace(/\s+/g, ' ').trim();
};
export const tagSequence = root => [...root.querySelectorAll('*')].map(el => el.tagName.toLowerCase());
