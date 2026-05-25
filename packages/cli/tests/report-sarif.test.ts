import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { toSarifDocument } from '../src/report-sarif.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const TRAPDOOR = resolve(REPO_ROOT, 'tests/fixtures/trapdoor');

const SARIF_LEVELS = new Set(['error', 'warning', 'note']);

describe('toSarifDocument — SARIF 2.1.0 structural compliance', () => {
  test('top-level required fields present', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');

    expect(doc.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(doc.version).toBe('2.1.0');
    expect(Array.isArray(doc.runs)).toBe(true);
    expect(doc.runs.length).toBe(1);
  });

  test('run.tool.driver required fields present', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    const driver = doc.runs[0]?.tool.driver;
    if (!driver) throw new Error('expected driver');
    expect(driver.name).toBe('warden');
    expect(driver.version).toBe('0.0.0-test');
    expect(typeof driver.informationUri).toBe('string');
    expect(Array.isArray(driver.rules)).toBe(true);
  });

  test('every result has ruleId, level, message.text, and locations', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    const results = doc.runs[0]?.results ?? [];
    expect(results.length).toBe(211);
    for (const r of results) {
      expect(typeof r.ruleId).toBe('string');
      expect(SARIF_LEVELS.has(r.level)).toBe(true);
      expect(typeof r.message.text).toBe('string');
      expect(r.message.text.length).toBeGreaterThan(0);
      expect(r.locations.length).toBe(1);
      const loc = r.locations[0];
      if (!loc) throw new Error('expected location');
      expect(typeof loc.physicalLocation.artifactLocation.uri).toBe('string');
      expect(typeof loc.physicalLocation.region.byteOffset).toBe('number');
      expect(typeof loc.physicalLocation.region.byteLength).toBe('number');
    }
  });

  test('severity mapping: high -> error', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    const allErrors = doc.runs[0]?.results.every((r) => r.level === 'error');
    expect(allErrors).toBe(true);
  });

  test('rules array deduped to actually-fired rules only', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    const ruleIds = doc.runs[0]?.tool.driver.rules.map((r) => r.id) ?? [];
    expect(ruleIds).toContain('unicode.tag-chars');
    expect(ruleIds).toContain('unicode.bidi-overrides');
    expect(ruleIds).toContain('unicode.variation-selectors-supplement');
    expect(ruleIds).toContain('unicode.zero-width');
    // Hangul filler is never fired by these fixtures — should be absent.
    expect(ruleIds).not.toContain('unicode.hangul-filler');
  });

  test('JSON.stringify round-trips and produces stable schema reference', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    const text = JSON.stringify(doc);
    const parsed = JSON.parse(text);
    expect(parsed.$schema).toBe('https://json.schemastore.org/sarif-2.1.0.json');
    expect(parsed.version).toBe('2.1.0');
  });

  test('artifactLocation.uri is forward-slash normalized (POSIX style per SARIF §3.4.4)', () => {
    const report = scanPath(TRAPDOOR);
    const doc = toSarifDocument(report, '0.0.0-test');
    for (const r of doc.runs[0]?.results ?? []) {
      expect(r.locations[0]?.physicalLocation.artifactLocation.uri).not.toContain('\\');
    }
  });
});
