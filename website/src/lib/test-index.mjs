import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const SCAN_DIRS = ['internal', 'test'];
const FUNC_RE = /^func (Test[A-Za-z0-9_]+)\(/;

let cache = null;

function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out);
    else if (entry.isFile() && p.endsWith('_test.go')) out.push(p);
  }
  return out;
}

function buildIndex() {
  const index = new Map();
  const files = [];
  for (const d of SCAN_DIRS) files.push(...walk(join(REPO_ROOT, d)));

  for (const file of files) {
    const lines = readFileSync(file, 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(FUNC_RE);
      if (!m) continue;
      const name = m[1];
      const entry = { file: relative(REPO_ROOT, file), line: i + 1 };
      const existing = index.get(name);
      if (existing) {
        index.set(name, { ambiguous: true, locations: [...(existing.locations ?? [existing]), entry] });
      } else {
        index.set(name, entry);
      }
    }
  }
  return index;
}

function getIndex() {
  if (!cache) cache = buildIndex();
  return cache;
}

export function resolveTest(name) {
  const entry = getIndex().get(name);
  if (!entry || entry.ambiguous) return null;
  return { file: entry.file, line: entry.line };
}

export function diagnose(name) {
  const entry = getIndex().get(name);
  if (!entry) return { status: 'missing' };
  if (entry.ambiguous) return { status: 'ambiguous', locations: entry.locations };
  return { status: 'ok', file: entry.file, line: entry.line };
}
