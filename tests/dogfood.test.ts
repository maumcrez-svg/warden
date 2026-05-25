import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Glob } from 'bun';
import {
  type Marker,
  applyMarker,
  parseMarker,
  scanPromptInjection,
  scanUnicode,
} from '../packages/core/src/index.ts';

// Dogfood: Warden's own first-party files must contain no Unicode threats
// and no prompt-injection findings — once payload-fixture markers (ADR 0010)
// are applied. Files that legitimately contain attack-shaped content
// declare a marker; this test consults the marker and accepts the
// suppression for the categories the marker covers.
//
// Excludes vendor / build directories. The historical `tests/fixtures/**`
// ignore is gone: those files now carry per-file markers and are scanned
// like everything else (per M3.1).

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
  'tests/**/*.md',
  '.claude/commands/*.md',
];

const IGNORE = ['**/node_modules/**', '**/dist/**', '**/build/**'];

type Offender = { path: string; rule: string; detail: string };

function loadMarker(rel: string, content: string): Marker | null {
  const r = parseMarker(rel, content);
  if (r.kind === 'error') {
    throw new Error(`dogfood: marker parse error in ${rel}: ${r.message}`);
  }
  return r.kind === 'ok' ? r.marker : null;
}

describe('dogfood — Warden source contains no live Unicode threats', () => {
  test('first-party files scan clean after markers are applied', () => {
    const offenders: Offender[] = [];
    const seen = new Set<string>();
    for (const pattern of PATTERNS) {
      const glob = new Glob(pattern);
      for (const rel of glob.scanSync({ cwd: ROOT, onlyFiles: true })) {
        if (IGNORE.some((ig) => new Glob(ig).match(rel))) continue;
        if (seen.has(rel)) continue;
        seen.add(rel);
        const content = readFileSync(resolve(ROOT, rel), 'utf8');
        const marker = loadMarker(rel, content);
        const raw = scanUnicode(content);
        const { kept } = applyMarker(marker, 'unicode', raw, content);
        for (const f of kept) {
          offenders.push({
            path: rel,
            rule: f.ruleId,
            detail: `U+${f.codepoint.toString(16).toUpperCase()} @byte ${f.byteOffset}`,
          });
        }
      }
    }
    if (offenders.length > 0) {
      const msg = offenders.map((o) => `  ${o.path} [${o.rule}]: ${o.detail}`).join('\n');
      throw new Error(`dogfood scan flagged Unicode in Warden source:\n${msg}`);
    }
    expect(seen.size).toBeGreaterThan(0);
  });
});

describe('dogfood — Warden source contains no live prompt-injection findings (M3)', () => {
  test('first-party files scan clean for T4 after markers are applied', () => {
    const offenders: Offender[] = [];
    const seen = new Set<string>();
    for (const pattern of PATTERNS) {
      const glob = new Glob(pattern);
      for (const rel of glob.scanSync({ cwd: ROOT, onlyFiles: true })) {
        if (IGNORE.some((ig) => new Glob(ig).match(rel))) continue;
        if (seen.has(rel)) continue;
        seen.add(rel);
        const content = readFileSync(resolve(ROOT, rel), 'utf8');
        const marker = loadMarker(rel, content);
        const raw = scanPromptInjection(content);
        const { kept } = applyMarker(marker, 'prompt-injection', raw, content);
        for (const f of kept) {
          offenders.push({ path: rel, rule: f.ruleId, detail: f.match });
        }
      }
    }
    if (offenders.length > 0) {
      const msg = offenders.map((o) => `  ${o.path} [${o.rule}]: ${o.detail}`).join('\n');
      throw new Error(`dogfood scan flagged prompt-injection in Warden source:\n${msg}`);
    }
    expect(seen.size).toBeGreaterThan(0);
  });
});

describe('dogfood — every payload-fixture marker parses cleanly (M3.1)', () => {
  test('no marker parse errors anywhere in scan scope', () => {
    const errors: string[] = [];
    const seen = new Set<string>();
    for (const pattern of PATTERNS) {
      const glob = new Glob(pattern);
      for (const rel of glob.scanSync({ cwd: ROOT, onlyFiles: true })) {
        if (IGNORE.some((ig) => new Glob(ig).match(rel))) continue;
        if (seen.has(rel)) continue;
        seen.add(rel);
        const content = readFileSync(resolve(ROOT, rel), 'utf8');
        const r = parseMarker(rel, content);
        if (r.kind === 'error') errors.push(r.message);
      }
    }
    if (errors.length > 0) {
      throw new Error(`dogfood: marker parse errors:\n  ${errors.join('\n  ')}`);
    }
    expect(seen.size).toBeGreaterThan(0);
  });
});
