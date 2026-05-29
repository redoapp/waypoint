import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diagnose } from '../src/lib/test-index.mjs';

const WEBSITE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const DOCS_DIR = join(WEBSITE_ROOT, 'src/content/docs');
const TEST_REF_RE = /<TestRef\s+name=["']([^"']+)["']/g;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (entry.isFile() && (p.endsWith('.md') || p.endsWith('.mdx'))) out.push(p);
  }
  return out;
}

const errors = [];
let ok = 0;

for (const file of walk(DOCS_DIR)) {
  const src = readFileSync(file, 'utf8');
  let m;
  while ((m = TEST_REF_RE.exec(src)) !== null) {
    const name = m[1];
    const result = diagnose(name);
    const lineNo = src.slice(0, m.index).split('\n').length;
    if (result.status === 'ok') {
      ok++;
    } else {
      errors.push({ file: relative(WEBSITE_ROOT, file), line: lineNo, name, result });
    }
  }
}

if (errors.length > 0) {
  console.error(`verify-test-refs: ${errors.length} broken reference(s):`);
  for (const e of errors) {
    if (e.result.status === 'missing') {
      console.error(`  ${e.file}:${e.line}  <TestRef name="${e.name}" /> — no matching test function found`);
    } else {
      const locs = e.result.locations.map((l) => `${l.file}:${l.line}`).join(', ');
      console.error(`  ${e.file}:${e.line}  <TestRef name="${e.name}" /> — ambiguous (matches: ${locs})`);
    }
  }
  process.exit(1);
}

console.log(`verify-test-refs: ${ok} reference(s) OK`);
