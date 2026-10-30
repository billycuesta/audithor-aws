import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../audithor/static/js');
function violations(source) {
  return [...source.matchAll(/(?:127\.0\.0\.1|localhost|:\s*500[01])[^\s'"`)]*/g)].map(match => match[0]);
}
for (const sample of ['http://127.0.0.1:5001/api', 'http://localhost:5000/api', 'http://host:5001/api']) {
  assert(violations(sample).length, `self-check failed to catch ${sample}`);
}
const knownApiPaths = ['/api/run-iam-audit', '/api/run-access-analyzer-audit'];
assert(knownApiPaths.every(endpoint => endpoint.startsWith('/')), 'known API paths must be root-relative');
function files(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? files(full) : entry.isFile() && entry.name.endsWith('.js') ? [full] : [];
  });
}
const failures = [];
for (const file of files(root)) {
  const source = fs.readFileSync(file, 'utf8');
  for (const hit of violations(source)) failures.push(`${path.relative(root, file)}: ${hit}`);
}
assert.deepEqual(failures, [], `Hardcoded backend origins found:\n${failures.join('\n')}`);
console.log('No hardcoded backend origins found.');
