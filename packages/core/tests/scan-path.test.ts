import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { scanPath } from '../src/scan-path.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const TRAPDOOR = resolve(REPO_ROOT, 'tests/fixtures/trapdoor');
const PROMPT_INJECTION = resolve(REPO_ROOT, 'tests/fixtures/prompt-injection');

describe('scanPath — TrapDoor (T1) / GlassWorm (T2) fixture directory', () => {
  test('matches all 8 fixtures as markdown', () => {
    const report = scanPath(TRAPDOOR);
    expect(report.matchedCount).toBe(8);
    for (const f of report.files) {
      expect(f.kind).toBe('markdown');
    }
  });

  test('total finding count is 211 (95 tag + 2 bidi + 64 vs + 50 zw)', () => {
    const report = scanPath(TRAPDOOR);
    expect(report.findingCount).toBe(211);
    expect(report.highCount).toBe(211);
    expect(report.mediumCount).toBe(0);
    expect(report.lowCount).toBe(0);
  });

  test('benign fixtures have zero findings', () => {
    const report = scanPath(TRAPDOOR);
    const benign = report.files.filter((f) => f.path.startsWith('benign-'));
    expect(benign.length).toBe(4);
    for (const f of benign) {
      expect(f.findings).toEqual([]);
    }
  });

  test('malicious fixtures all have at least one finding', () => {
    const report = scanPath(TRAPDOOR);
    const malicious = report.files.filter((f) => f.path.startsWith('malicious-'));
    expect(malicious.length).toBe(4);
    for (const f of malicious) {
      expect(f.findings.length).toBeGreaterThan(0);
    }
  });

  test('deterministic file order', () => {
    const a = scanPath(TRAPDOOR);
    const b = scanPath(TRAPDOOR);
    expect(a.files.map((f) => f.path)).toEqual(b.files.map((f) => f.path));
  });

  test('scannedAt is overridable for deterministic snapshots', () => {
    const fixed = new Date('2026-01-01T00:00:00.000Z');
    const report = scanPath(TRAPDOOR, { now: () => fixed });
    expect(report.scannedAt).toBe('2026-01-01T00:00:00.000Z');
  });
});

describe('scanPath — single-file target', () => {
  test('scanning a single malicious file yields findings', () => {
    const report = scanPath(resolve(TRAPDOOR, 'malicious-tag-chars.md'));
    expect(report.matchedCount).toBe(1);
    expect(report.findingCount).toBe(95);
  });

  test('scanning a single benign file yields zero findings', () => {
    const report = scanPath(resolve(TRAPDOOR, 'benign-emoji-zwj.md'));
    expect(report.matchedCount).toBe(1);
    expect(report.findingCount).toBe(0);
  });
});

describe('scanPath — repo root (dogfood path)', () => {
  test('warden repo scans clean (0 high)', () => {
    const report = scanPath(REPO_ROOT);
    expect(report.highCount).toBe(0);
  });
});

describe('scanPath — prompt-injection fixtures (T4, M3)', () => {
  test('positive fixtures all have promptInjectionFindings', () => {
    const report = scanPath(resolve(PROMPT_INJECTION, 'positive'));
    expect(report.files.length).toBeGreaterThanOrEqual(5);
    for (const f of report.files) {
      expect(f.promptInjectionFindings.length).toBeGreaterThan(0);
    }
    expect(report.highCount).toBeGreaterThan(0);
  });

  test('benign fixtures all have zero promptInjectionFindings', () => {
    const report = scanPath(resolve(PROMPT_INJECTION, 'benign'));
    expect(report.files.length).toBeGreaterThanOrEqual(3);
    for (const f of report.files) {
      expect(f.promptInjectionFindings).toEqual([]);
      expect(f.findings).toEqual([]);
    }
    expect(report.findingCount).toBe(0);
  });

  test('trapdoor fixtures have unicode findings but no prompt-injection findings', () => {
    const report = scanPath(TRAPDOOR);
    for (const f of report.files) {
      expect(f.promptInjectionFindings).toEqual([]);
    }
  });
});
