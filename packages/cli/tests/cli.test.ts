import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { runScan } from '../src/index.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const TRAPDOOR = resolve(REPO_ROOT, 'tests/fixtures/trapdoor');

class StringWriter {
  buf = '';
  isTTY = false;
  write(s: string): boolean {
    this.buf += s;
    return true;
  }
}

function streamsForTest(): { stdout: StringWriter; stderr: StringWriter } {
  return { stdout: new StringWriter(), stderr: new StringWriter() };
}

describe('runScan — exit codes (ADR 0007 §3)', () => {
  test('high-severity findings -> exit 1', () => {
    const s = streamsForTest();
    const code = runScan(TRAPDOOR, { quiet: true }, s);
    expect(code).toBe(1);
  });

  test('clean repo -> exit 0', () => {
    const s = streamsForTest();
    const code = runScan(REPO_ROOT, { quiet: true }, s);
    expect(code).toBe(0);
  });

  test('non-existent path -> exit 2 with stderr error', () => {
    const s = streamsForTest();
    const code = runScan(resolve(REPO_ROOT, 'does-not-exist'), {}, s);
    expect(code).toBe(2);
    expect(s.stderr.buf).toContain('path does not exist');
  });

  test('--json and --sarif together -> exit 2 with stderr error', () => {
    const s = streamsForTest();
    const code = runScan(TRAPDOOR, { json: true, sarif: true }, s);
    expect(code).toBe(2);
    expect(s.stderr.buf).toContain('mutually exclusive');
  });
});

describe('runScan — output mode selection', () => {
  test('default emits pretty (human-readable summary)', () => {
    const s = streamsForTest();
    runScan(TRAPDOOR, {}, s);
    expect(s.stdout.buf).toContain('warden scan: 8 files scanned');
    expect(s.stdout.buf).toContain('summary: 211 finding');
  });

  test('--json emits a parseable JSON object', () => {
    const s = streamsForTest();
    runScan(TRAPDOOR, { json: true }, s);
    const parsed = JSON.parse(s.stdout.buf);
    expect(parsed.version).toBe('warden/scan/v2');
    expect(parsed.findingCount).toBe(211);
  });

  test('--sarif emits a parseable SARIF document', () => {
    const s = streamsForTest();
    runScan(TRAPDOOR, { sarif: true }, s);
    const parsed = JSON.parse(s.stdout.buf);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
  });

  test('--quiet suppresses per-finding rows but keeps summary', () => {
    const s = streamsForTest();
    runScan(TRAPDOOR, { quiet: true }, s);
    expect(s.stdout.buf).not.toContain('unicode.tag-chars');
    expect(s.stdout.buf).toContain('summary:');
  });
});

describe('runScan — M2 acceptance criteria from ROADMAP', () => {
  test('warden repo itself produces 0 high-severity findings', () => {
    const s = streamsForTest();
    const code = runScan(REPO_ROOT, { json: true }, s);
    const parsed = JSON.parse(s.stdout.buf);
    expect(parsed.highCount).toBe(0);
    expect(code).toBe(0);
  });

  test('trapdoor fixtures produce 211 findings (matches M1 totals)', () => {
    const s = streamsForTest();
    runScan(TRAPDOOR, { json: true }, s);
    const parsed = JSON.parse(s.stdout.buf);
    expect(parsed.findingCount).toBe(211);
  });
});
