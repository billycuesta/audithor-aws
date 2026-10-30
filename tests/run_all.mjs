import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const files = fs.readdirSync('tests').filter(file => file.endsWith('.test.mjs')).sort();
let failed = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, [path.join('tests', file)], { encoding: 'utf8' });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const lastLine = output.trim().split('\n').at(-1) ?? '';
  const ok = result.status === 0;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${file}${lastLine ? ` — ${lastLine}` : ''}`);
  if (!ok) {
    failed++;
    console.log(output);
  }
}
console.log(`Summary: ${files.length - failed}/${files.length} passed`);
process.exitCode = failed ? 1 : 0;
