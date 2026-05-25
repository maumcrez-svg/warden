import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { printPretty } from '../src/report-pretty.ts';

const TRAPDOOR = resolve(import.meta.dir, '../../../tests/fixtures/trapdoor');

class StringWriter {
  buf = '';
  write(s: string): boolean {
    this.buf += s;
    return true;
  }
}

const ESC = '\x1b';

// Minimal ScanReport shape for synthesized cases.
function cleanReport(): {
  root: string;
  scannedAt: string;
  fileCount: number;
  matchedCount: number;
  findingCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  suppressedCount: number;
  suppressedByCategory: { unicode: number; 'prompt-injection': number; mcp: number; trust: number };
  files: [];
  unsupportedGitignorePatterns: string[];
  markerErrors: [];
  trustState: 'not-enforced';
  trustError: null;
  orphanTrustFindings: [];
} {
  return {
    root: '/tmp/x',
    scannedAt: '2026-01-01T00:00:00.000Z',
    fileCount: 0,
    matchedCount: 0,
    findingCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    suppressedCount: 0,
    suppressedByCategory: { unicode: 0, 'prompt-injection': 0, mcp: 0, trust: 0 },
    files: [],
    unsupportedGitignorePatterns: [],
    markerErrors: [],
    trustState: 'not-enforced',
    trustError: null,
    orphanTrustFindings: [],
  };
}

describe('printPretty', () => {
  test('default (non-quiet, no-color) on trapdoor: clean live findings + suppressed summary', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false });

    expect(out.buf).toContain('warden scan: 8 files scanned');
    // Post-M3.1: trapdoor fixtures are marker-suppressed; no live findings.
    expect(out.buf).toContain('summary: 0 finding(s)');
    expect(out.buf).toContain('suppressed: 211 unicode');
  });

  test('--verbose surfaces suppressed findings with file headers + marker line', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false, verbose: true });

    expect(out.buf).toContain('suppressed by marker or unlock:');
    expect(out.buf).toContain('malicious-tag-chars.md');
    expect(out.buf).toContain('unicode.tag-chars');
    expect(out.buf).toContain('payload-fixture [trapdoor-unicode]');
  });

  test('quiet mode prints only summary + suppressed lines (no per-file rows)', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: true });

    const lines = out.buf.split('\n').filter((l) => l !== '');
    // Two lines expected: summary + suppressed.
    expect(lines.length).toBe(2);
    expect(out.buf).toContain('summary:');
    expect(out.buf).toContain('suppressed:');
    // No per-file row.
    expect(out.buf).not.toContain('malicious-tag-chars.md');
  });

  test('color: false emits no ANSI escape sequences', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false });
    expect(out.buf.includes(ESC)).toBe(false);
  });

  test('color: true emits ANSI escape sequences', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: true, quiet: false });
    expect(out.buf.includes(ESC)).toBe(true);
  });

  test('clean scan prints "clean" line and omits suppressed line', () => {
    const out = new StringWriter();
    printPretty(cleanReport(), out, { color: false, quiet: false });
    expect(out.buf).toContain('clean');
    expect(out.buf).toContain('summary: 0 finding(s)');
    expect(out.buf).not.toContain('suppressed:');
  });

  test('unsupported gitignore patterns are surfaced as warnings', () => {
    const report = { ...cleanReport(), unsupportedGitignorePatterns: ['!keep.md'] };
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false });
    expect(out.buf).toContain('unsupported .gitignore pattern');
    expect(out.buf).toContain('!keep.md');
  });
});
