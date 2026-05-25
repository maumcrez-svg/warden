// Sync orchestration tests. The default network fetcher is never
// invoked here — every test injects a `fetcher` that returns a
// fixture ZIP built in-process by buildFixtureZip(). ADR 0015 §7
// "no network in tests" is enforced by construction.

import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { indexPath, readIndex } from '../src/index-store.ts';
import { readManifest } from '../src/manifest.ts';
import { syncOsv, validateOsvUrl, verifyOsv } from '../src/sync.ts';
import {
  EVENT_STREAM_ADVISORY,
  LEFT_PAD_ADVISORY,
  buildBrokenZip,
  buildFixtureZip,
} from './fixtures.ts';

function newTmp(): string {
  return mkdtempSync(join(tmpdir(), 'warden-ioc-sync-'));
}

const FIXTURE = buildFixtureZip([EVENT_STREAM_ADVISORY, LEFT_PAD_ADVISORY]);
const BROKEN = buildBrokenZip([EVENT_STREAM_ADVISORY, LEFT_PAD_ADVISORY, EVENT_STREAM_ADVISORY]);

describe('syncOsv — happy path', () => {
  test('writes per-ecosystem index + manifest', async () => {
    const cache = newTmp();
    const result = await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
    });
    expect(result.ecosystems).toHaveLength(1);
    expect(result.ecosystems[0]?.ecosystem).toBe('npm');
    expect(result.ecosystems[0]?.advisory_count).toBe(2);
    expect(result.totalAdvisories).toBe(2);

    const idxPath = indexPath(cache, 'npm');
    expect(existsSync(idxPath)).toBe(true);
    const idx = readIndex(idxPath);
    expect(idx.kind).toBe('ok');
    if (idx.kind !== 'ok') return;
    expect(Object.keys(idx.index.packages)).toContain('event-stream');
    expect(Object.keys(idx.index.packages)).toContain('left-pad');

    const m = readManifest(resolve(cache, 'manifest.json'));
    expect(m.kind).toBe('ok');
  });

  test('re-syncing identical fixture produces a byte-identical index', async () => {
    const cache = newTmp();
    const fixed = '2026-05-25T12:00:00.000Z';
    const now = () => new Date(fixed);
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
      now,
    });
    const after1 = readFileSync(indexPath(cache, 'npm'), 'utf8');

    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
      now,
    });
    const after2 = readFileSync(indexPath(cache, 'npm'), 'utf8');
    expect(after1).toBe(after2);
  });

  test('diff reports added/dropped between syncs', async () => {
    const cache = newTmp();
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => buildFixtureZip([EVENT_STREAM_ADVISORY]),
    });
    const r = await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => buildFixtureZip([LEFT_PAD_ADVISORY]),
    });
    expect(r.ecosystems[0]?.diff.added).toBe(1);
    expect(r.ecosystems[0]?.diff.dropped).toBe(1);
  });
});

describe('syncOsv — atomicity (ADR 0015 §10)', () => {
  test('parse failure mid-sync leaves the previous cache intact', async () => {
    const cache = newTmp();
    // Seed a known-good cache.
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => buildFixtureZip([EVENT_STREAM_ADVISORY]),
    });
    const goodIndex = readFileSync(indexPath(cache, 'npm'), 'utf8');
    const goodManifest = readFileSync(resolve(cache, 'manifest.json'), 'utf8');

    // Attempt a sync that throws inside the parser.
    let threw = false;
    try {
      await syncOsv({
        cacheRoot: cache,
        ecosystems: ['npm'],
        wardenVersion: 'test',
        fetcher: async () => BROKEN,
      });
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);

    // Cache must be byte-identical to its pre-failure state.
    expect(readFileSync(indexPath(cache, 'npm'), 'utf8')).toBe(goodIndex);
    expect(readFileSync(resolve(cache, 'manifest.json'), 'utf8')).toBe(goodManifest);
  });

  test('no orphan .tmp-* directories remain after a successful sync', async () => {
    const cache = newTmp();
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
    });
    const orphans = readdirSync(cache).filter(
      (n) => n.startsWith('.tmp-') || n.startsWith('osv.prev-'),
    );
    expect(orphans).toEqual([]);
  });

  test('history retains the previous manifest after a re-sync', async () => {
    const cache = newTmp();
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => buildFixtureZip([EVENT_STREAM_ADVISORY]),
      now: () => new Date('2026-05-24T12:00:00.000Z'),
    });
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => buildFixtureZip([LEFT_PAD_ADVISORY]),
      now: () => new Date('2026-05-25T12:00:00.000Z'),
    });
    const history = readdirSync(resolve(cache, 'history'));
    expect(history.length).toBeGreaterThan(0);
  });
});

describe('validateOsvUrl (ADR 0015 §7 host pinning)', () => {
  test('accepts the OSV bucket URL', () => {
    expect(
      validateOsvUrl('https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip'),
    ).toBeNull();
  });

  test('rejects non-https URLs', () => {
    const m = validateOsvUrl('http://storage.googleapis.com/x');
    expect(m).toContain('non-HTTPS');
  });

  test('rejects hosts other than storage.googleapis.com', () => {
    const m = validateOsvUrl('https://attacker.example/x');
    expect(m).toContain('refusing host');
    expect(m).toContain('attacker.example');
  });

  test('rejects malformed URLs', () => {
    expect(validateOsvUrl('not a url')).not.toBeNull();
  });
});

describe('verifyOsv', () => {
  test('matches sha256 when fixture is unchanged', async () => {
    const cache = newTmp();
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
    });
    const v = await verifyOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      fetcher: async () => FIXTURE,
    });
    expect(v.allMatch).toBe(true);
    expect(v.ecosystems[0]?.matches).toBe(true);
  });

  test('reports mismatch when fixture content changes', async () => {
    const cache = newTmp();
    await syncOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      wardenVersion: 'test',
      fetcher: async () => FIXTURE,
    });
    const altered = buildFixtureZip([LEFT_PAD_ADVISORY]);
    const v = await verifyOsv({
      cacheRoot: cache,
      ecosystems: ['npm'],
      fetcher: async () => altered,
    });
    expect(v.allMatch).toBe(false);
    expect(v.ecosystems[0]?.matches).toBe(false);
  });
});
