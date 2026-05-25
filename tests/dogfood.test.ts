import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Glob } from 'bun';
import { scanPromptInjection, scanUnicode } from '../packages/core/src/index.ts';

// Dogfood: Warden's own first-party files must contain no Unicode threats
// and no prompt-injection findings. Excludes tests/fixtures/ (those carry
// intentional payloads) and any vendor directories. Mirrors the spirit of
// `warden scan .` at the repo root.

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

// The prompt-injection scanner cannot be run over its own rule data file
// or its own detector test without self-triggering: both files contain
// the canonical attack strings as inputs by design. This mirrors the
// .wardenignore entries for the same reason.
const PROMPT_INJECTION_EXTRA_IGNORE = [
  'packages/rules/src/data/prompt-injection.ts',
  'packages/core/tests/scan-prompt-injection.test.ts',
];

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

describe('dogfood — Warden source contains no prompt-injection findings (M3)', () => {
  test('first-party files scan clean for T4', () => {
    const offenders: Array<{ path: string; rule: string; match: string }> = [];
    const seen = new Set<string>();
    const piIgnore = [...IGNORE, ...PROMPT_INJECTION_EXTRA_IGNORE];
    for (const pattern of PATTERNS) {
      const glob = new Glob(pattern);
      for (const rel of glob.scanSync({ cwd: ROOT, onlyFiles: true })) {
        if (piIgnore.some((ig) => new Glob(ig).match(rel))) continue;
        if (seen.has(rel)) continue;
        seen.add(rel);
        const content = readFileSync(resolve(ROOT, rel), 'utf8');
        for (const f of scanPromptInjection(content)) {
          offenders.push({ path: rel, rule: f.ruleId, match: f.match });
        }
      }
    }
    if (offenders.length > 0) {
      const msg = offenders.map((o) => `  ${o.path} [${o.rule}]: ${o.match}`).join('\n');
      throw new Error(`dogfood scan flagged prompt-injection in Warden source:\n${msg}`);
    }
    expect(seen.size).toBeGreaterThan(0);
  });
});
