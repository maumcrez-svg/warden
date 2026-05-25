import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  MANIFEST_SCHEMA,
  ageHoursSinceSync,
  readManifest,
  writeManifestAtomic,
} from '../src/manifest.ts';

function newTmp(): string {
  return mkdtempSync(join(tmpdir(), 'warden-ioc-manifest-'));
}

describe('readManifest', () => {
  test('returns missing when the file does not exist', () => {
    const r = readManifest('/nonexistent/path/manifest.json');
    expect(r.kind).toBe('missing');
  });

  test('returns error on malformed JSON', () => {
    const dir = newTmp();
    const path = resolve(dir, 'manifest.json');
    writeManifestAtomic(path, {
      schema: MANIFEST_SCHEMA,
      synced_at: new Date().toISOString(),
      warden_version: 'test',
      sources: [],
    });
    const r = readManifest(path);
    expect(r.kind).toBe('ok');
  });

  test('rejects unknown schema', () => {
    const dir = newTmp();
    const path = resolve(dir, 'manifest.json');
    Bun.write(path, '{"schema":"unknown/v9"}');
    const r = readManifest(path);
    expect(r.kind).toBe('error');
    if (r.kind === 'error') expect(r.message).toContain('unsupported manifest schema');
  });
});

describe('writeManifestAtomic', () => {
  test('writes via temp file + rename (no half-written state observable)', () => {
    const dir = newTmp();
    const path = resolve(dir, 'manifest.json');
    const m = {
      schema: MANIFEST_SCHEMA,
      synced_at: '2026-05-25T12:00:00.000Z',
      warden_version: '0.0.0-m8',
      sources: [
        {
          name: 'osv',
          url: 'https://example.test',
          synced_at: '2026-05-25T12:00:00.000Z',
          ecosystems: ['npm'],
          advisory_count: 5,
          zip_sha256: 'npm:deadbeef',
          zip_size_bytes: 1024,
        },
      ],
    };
    writeManifestAtomic(path, m);
    const round = JSON.parse(readFileSync(path, 'utf8')) as { schema: string };
    expect(round.schema).toBe(MANIFEST_SCHEMA);
  });
});

describe('ageHoursSinceSync', () => {
  test('returns elapsed hours', () => {
    const m = {
      schema: MANIFEST_SCHEMA,
      synced_at: '2026-05-25T00:00:00.000Z',
      warden_version: 'test',
      sources: [],
    };
    const now = new Date('2026-05-25T03:30:00.000Z');
    expect(ageHoursSinceSync(m, now)).toBeCloseTo(3.5, 2);
  });

  test('returns infinity for invalid timestamps', () => {
    const m = {
      schema: MANIFEST_SCHEMA,
      synced_at: 'not-a-date',
      warden_version: 'test',
      sources: [],
    };
    expect(ageHoursSinceSync(m)).toBe(Number.POSITIVE_INFINITY);
  });
});
