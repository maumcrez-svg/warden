import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { toJsonReport } from '../src/report-json.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const TRAPDOOR = resolve(REPO_ROOT, 'tests/fixtures/trapdoor');

describe('toJsonReport — warden/scan/v1 shape', () => {
  test('top-level shape matches contract', () => {
    const fixed = new Date('2026-01-01T00:00:00.000Z');
    const report = scanPath(TRAPDOOR, { now: () => fixed });
    const json = toJsonReport(report, '0.0.0-test');

    expect(json.version).toBe('warden/scan/v1');
    expect(json.tool).toEqual({ name: 'warden', version: '0.0.0-test' });
    expect(json.scannedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(json.findingCount).toBe(211);
    expect(json.highCount).toBe(211);
    expect(json.mediumCount).toBe(0);
    expect(json.lowCount).toBe(0);
    expect(Array.isArray(json.files)).toBe(true);
    expect(json.files.length).toBe(8);
  });

  test('files preserve scan-path output verbatim', () => {
    const report = scanPath(TRAPDOOR);
    const json = toJsonReport(report, '0.0.0-test');
    expect(json.files).toBe(report.files);
  });

  test('JSON.stringify round-trips without throwing', () => {
    const report = scanPath(TRAPDOOR);
    const json = toJsonReport(report, '0.0.0-test');
    const text = JSON.stringify(json);
    const parsed = JSON.parse(text);
    expect(parsed.version).toBe('warden/scan/v1');
    expect(parsed.findingCount).toBe(211);
  });
});
