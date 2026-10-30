import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../audithor/static/js');
const allowlist = [
  // setHtml is the sole sanctioned innerHTML writer.
  { file: 'safe_html.js', rule: 'html-write' },
  // actionFragment builds trusted attributes from a validated name and escaped JSON arguments.
  { file: 'safe_html.js', rule: 'raw-dynamic' },
];

function violations(source) {
  const rules = [
    ['html-write', /(?:\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\()/g],
    ['inline-event', /\bon(?:click|change|input|error|load|submit|keyup|keydown|mouseover|mouseout|focus|blur)\s*=\s*(?:["'`]|\\["'])/gi],
    ['javascript-url', /javascript\s*:/gi],
    ['dynamic-code', /\beval\s*\(|\bnew\s+Function\s*\(|\b(?:setTimeout|setInterval)\s*\(\s*(['"`])/g],
    ['html-identity', /\bhtml\s*`\s*\$\{\s*[\w$]+(?:\.[\w$]+)*\s*\}\s*`/g],
    ['raw-dynamic', /\braw\s*\([^)]*(?:\$\{|\+\s*[A-Za-z_$])/g],
    ['markup-buffer', /(?:\+=\s*`\s*<|\+=\s*'\s*<|\blet\s+[\w$]+\s*=\s*'\s*<)/g],
  ];
  return rules.flatMap(([rule, regex]) => [...source.matchAll(regex)].map(match => ({ rule, line: source.slice(0, match.index).split('\n').length })));
}

const sample = `el.innerHTML = x;\n<button onclick="x">\n<button onclick='x'>\nx.onload = (e) => {};\njavascript:alert(1)\neval('x');\nhtml\u0060\u0024{resultHtml}\u0060\nraw(value + suffix)\nlet markup = '<b>';`;
const sampleViolations = violations(sample);
for (const rule of ['html-write', 'inline-event', 'javascript-url', 'dynamic-code', 'html-identity', 'raw-dynamic', 'markup-buffer']) {
  assert(sampleViolations.some(item => item.rule === rule), `self-check failed for ${rule}`);
}
assert.equal(sampleViolations.filter(item => item.rule === 'inline-event').length, 2, 'inline-event self-check must match quoted attributes, not JavaScript properties');

function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? files(full) : entry.isFile() && entry.name.endsWith('.js') ? [full] : [];
  });
}
const failures = [];
for (const file of files(root)) {
  const relative = path.relative(root, file).split(path.sep).join('/');
  const source = fs.readFileSync(file, 'utf8');
  const hits = violations(source);
  if (relative === 'safe_html.js') {
    for (const rule of ['html-write', 'raw-dynamic']) {
      assert.equal(hits.filter(hit => hit.rule === rule).length, 1, `safe_html.js must contain exactly one ${rule} occurrence`);
    }
  }
  for (const hit of hits) {
    if (allowlist.some(item => item.file === relative && item.rule === hit.rule)) continue;
    failures.push(`${relative}:${hit.line}: ${hit.rule}`);
  }
}
assert.deepEqual(failures, [], `Unsafe JavaScript patterns found:\n${failures.join('\n')}`);
console.log('No disallowed JavaScript patterns found.');
