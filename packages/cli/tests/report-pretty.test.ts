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

describe('printPretty', () => {
  test('default (non-quiet, no-color) lists each file with findings', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false });

    expect(out.buf).toContain('warden scan: 8 files scanned');
    expect(out.buf).toContain('malicious-tag-chars.md');
    expect(out.buf).toContain('unicode.tag-chars');
    expect(out.buf).toContain('summary: 211 finding');
  });

  test('quiet mode prints only summary line', () => {
    const report = scanPath(TRAPDOOR);
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: true });

    expect(out.buf.split('\n').filter((l) => l !== '').length).toBe(1);
    expect(out.buf).toContain('summary:');
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

  test('clean scan prints "clean" line', () => {
    const cleanReport = {
      root: '/tmp/clean',
      scannedAt: '2026-01-01T00:00:00.000Z',
      fileCount: 0,
      matchedCount: 0,
      findingCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      files: [],
      unsupportedGitignorePatterns: [],
    };
    const out = new StringWriter();
    printPretty(cleanReport, out, { color: false, quiet: false });
    expect(out.buf).toContain('clean');
    expect(out.buf).toContain('summary: 0 finding(s)');
  });

  test('unsupported gitignore patterns are surfaced as warnings', () => {
    const report = {
      root: '/tmp/x',
      scannedAt: '2026-01-01T00:00:00.000Z',
      fileCount: 0,
      matchedCount: 0,
      findingCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      files: [],
      unsupportedGitignorePatterns: ['!keep.md'],
    };
    const out = new StringWriter();
    printPretty(report, out, { color: false, quiet: false });
    expect(out.buf).toContain('unsupported .gitignore pattern');
    expect(out.buf).toContain('!keep.md');
  });
});
