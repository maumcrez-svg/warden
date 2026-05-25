import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Glob } from 'bun';
import { scanUnicode } from '../packages/core/src/index.ts';

// Dogfood: Warden's own first-party files must contain no Unicode threats.
// Excludes tests/fixtures/ (those carry intentional payloads) and any vendor
// directories. Mirrors the spirit of `warden scan .` at the repo root.

const ROOT = resolve(import.meta.dir, '..');

const PATTERNS = [
  'CLAUDE.md',
  'README.md',
  'biome.json',
  'tsconfig.json',
  'package.json',
  'docs/**/*.md',
  'packages/**/src/**/*.ts',
  'packages/**/tests/**/*.ts',
  'packages/**/package.json',
  'tests/**/*.ts',
  '.claude/commands/*.md',
];

const IGNORE = ['tests/fixtures/**', '**/node_modules/**', '**/dist/**', '**/build/**'];

describe('dogfood — Warden source contains no Unicode threats', () => {
  test('first-party files scan clean', () => {
    const offenders: Array<{ path: string; count: number; high: number }> = [];
    const seen = new Set<string>();
    for (const pattern of PATTERNS) {
      const glob = new Glob(pattern);
      for (const rel of glob.scanSync({ cwd: ROOT, onlyFiles: true })) {
        if (IGNORE.some((ig) => new Glob(ig).match(rel))) continue;
        if (seen.has(rel)) continue;
        seen.add(rel);
        const content = readFileSync(resolve(ROOT, rel), 'utf8');
        const findings = scanUnicode(content);
        if (findings.length === 0) continue;
        const high = findings.filter((f) => f.severity === 'high').length;
        offenders.push({ path: rel, count: findings.length, high });
      }
    }
    if (offenders.length > 0) {
      const msg = offenders
        .map((o) => `  ${o.path}: ${o.count} findings (${o.high} high)`)
        .join('\n');
      throw new Error(`dogfood scan flagged Warden source files:\n${msg}`);
    }
    expect(seen.size).toBeGreaterThan(0);
  });
});
