import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  INDEX_SCHEMA,
  type Index,
  type PrunedAdvisory,
  getAdvisoriesForPackage,
  readIndex,
  writeIndexAtomic,
} from '../src/index-store.ts';

function newTmp(): string {
  return mkdtempSync(join(tmpdir(), 'warden-ioc-index-'));
}

function buildIndex(packages: Record<string, ReadonlyArray<PrunedAdvisory>>): Index {
  let count = 0;
  for (const arr of Object.values(packages)) count += arr.length;
  return {
    schema: INDEX_SCHEMA,
    ecosystem: 'npm',
    source: 'osv',
    synced_at: '2026-05-25T12:00:00.000Z',
    advisory_count: count,
    packages,
  };
}

describe('writeIndexAtomic + readIndex round-trip', () => {
  test('writes deterministic key order (atomicity §10 byte-identical)', () => {
    const dir = newTmp();
    const path = resolve(dir, 'npm.json');
    const adv: PrunedAdvisory = {
      id: 'GHSA-test',
      severity: 'high',
      summary: 'x',
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
      references: ['https://example.test'],
    };
    // Write the same index twice with keys in different insertion
    // orders; the on-disk files must be byte-identical because keys
    // are sorted in writeIndexAtomic.
    writeIndexAtomic(path, buildIndex({ 'b-pkg': [adv], 'a-pkg': [adv] }));
    const first = readFileSync(path, 'utf8');
    writeIndexAtomic(path, buildIndex({ 'a-pkg': [adv], 'b-pkg': [adv] }));
    const second = readFileSync(path, 'utf8');
    expect(first).toBe(second);
  });

  test('round-trips through readIndex with schema preserved', () => {
    const dir = newTmp();
    const path = resolve(dir, 'npm.json');
    const idx = buildIndex({
      'event-stream': [
        {
          id: 'GHSA-mh6f-8j2x-4483',
          severity: 'high',
          summary: 'malicious dep',
          ranges: [{ type: 'SEMVER', events: [{ introduced: '3.3.6' }, { fixed: '4.0.0' }] }],
          references: ['https://example.test'],
        },
      ],
    });
    writeIndexAtomic(path, idx);
    const r = readIndex(path);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.index.ecosystem).toBe('npm');
    expect(r.index.advisory_count).toBe(1);
  });

  test('readIndex returns missing for unknown path', () => {
    expect(readIndex('/no/such/path.json').kind).toBe('missing');
  });
});

describe('getAdvisoriesForPackage', () => {
  test('returns the array for present packages', () => {
    const adv: PrunedAdvisory = {
      id: 'GHSA-x',
      severity: 'low',
      summary: 's',
      ranges: [],
      references: [],
    };
    const idx = buildIndex({ foo: [adv] });
    expect(getAdvisoriesForPackage(idx, 'foo')).toHaveLength(1);
  });

  test('returns empty array for absent packages', () => {
    const idx = buildIndex({});
    expect(getAdvisoriesForPackage(idx, 'nothing')).toEqual([]);
  });
});
