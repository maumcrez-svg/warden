import { describe, expect, test } from 'bun:test';
import {
  emptyManifest,
  findTrust,
  findUnlock,
  parseManifest,
  serializeManifest,
  upsertTrust,
  upsertUnlock,
} from '../src/trust/manifest.ts';

const SAMPLE_TRUST = `schema = "v1"

[[trust]]
path = "CLAUDE.md"
hash = "blake3:abc123"
signer = "SHA256:xyz"
signed-at = "2026-05-25T03:14:00Z"
signature = "AAA"
reason = "first sign"

[[trust]]
path = "AGENTS.md"
hash = "blake3:def456"
signer = "SHA256:xyz"
signed-at = "2026-05-25T03:15:00Z"
signature = "BBB"

[[unlock]]
path = "experimental/draft.md"
reason = "wip"
unlocked-at = "2026-05-25T03:00:00Z"
unlocked-by = "rezende@example"
`;

describe('parseManifest', () => {
  test('parses [[trust]] + [[unlock]] blocks', () => {
    const r = parseManifest(SAMPLE_TRUST);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') throw new Error('unreachable');
    expect(r.manifest.schema).toBe('v1');
    expect(r.manifest.trust).toHaveLength(2);
    expect(r.manifest.unlock).toHaveLength(1);
    const claude = findTrust(r.manifest, 'CLAUDE.md');
    expect(claude?.reason).toBe('first sign');
    expect(claude?.hash).toBe('blake3:abc123');
    const agents = findTrust(r.manifest, 'AGENTS.md');
    expect(agents?.reason).toBeNull();
    const draft = findUnlock(r.manifest, 'experimental/draft.md');
    expect(draft?.reason).toBe('wip');
  });

  test('rejects missing schema declaration', () => {
    const r = parseManifest(
      '[[trust]]\npath = "x"\nhash = "y"\nsigner = "z"\nsigned-at = "t"\nsignature = "s"\n',
    );
    expect(r.kind).toBe('error');
  });

  test('rejects unsupported schema version', () => {
    const r = parseManifest('schema = "v2"\n');
    expect(r.kind).toBe('error');
    if (r.kind === 'error') expect(r.message).toMatch(/unsupported schema/);
  });

  test('rejects [[trust]] with missing required field', () => {
    const r = parseManifest(
      'schema = "v1"\n[[trust]]\npath = "x"\nhash = "y"\nsigner = "z"\nsigned-at = "t"\n',
    );
    expect(r.kind).toBe('error');
    if (r.kind === 'error') expect(r.message).toMatch(/signature/);
  });

  test('escapes round-trip with quotes and backslashes', () => {
    const m = emptyManifest();
    const withTrust = upsertTrust(m, {
      path: 'has\\backslash and "quote".md',
      hash: 'blake3:000',
      signer: 'SHA256:abc',
      signedAt: '2026-05-25T03:14:00Z',
      signature: 'BLOB',
      reason: 'because',
    }).manifest;
    const text = serializeManifest(withTrust);
    const parsed = parseManifest(text);
    expect(parsed.kind).toBe('ok');
    if (parsed.kind !== 'ok') throw new Error('unreachable');
    const t = parsed.manifest.trust[0];
    expect(t?.path).toBe('has\\backslash and "quote".md');
  });
});

describe('serializeManifest', () => {
  test('first line is schema = "v1"', () => {
    const text = serializeManifest(emptyManifest());
    expect(text.split('\n')[0]).toBe('schema = "v1"');
  });

  test('trust entries are sorted alphabetically by path', () => {
    const m = emptyManifest();
    const a = upsertTrust(m, {
      path: 'b.md',
      hash: 'blake3:1',
      signer: 'SHA256:a',
      signedAt: 't',
      signature: 's',
      reason: null,
    }).manifest;
    const b = upsertTrust(a, {
      path: 'a.md',
      hash: 'blake3:2',
      signer: 'SHA256:a',
      signedAt: 't',
      signature: 's',
      reason: null,
    }).manifest;
    const text = serializeManifest(b);
    const aIdx = text.indexOf('a.md');
    const bIdx = text.indexOf('b.md');
    expect(aIdx).toBeGreaterThan(0);
    expect(aIdx).toBeLessThan(bIdx);
  });

  test('field order inside [[trust]] is fixed: path, hash, signer, signed-at, signature, reason', () => {
    const m = emptyManifest();
    const withTrust = upsertTrust(m, {
      path: 'x.md',
      hash: 'blake3:1',
      signer: 'SHA256:a',
      signedAt: 't',
      signature: 's',
      reason: 'r',
    }).manifest;
    const text = serializeManifest(withTrust);
    const lines = text.split('\n');
    const start = lines.indexOf('[[trust]]');
    expect(start).toBeGreaterThan(-1);
    expect(lines[start + 1]?.startsWith('path =')).toBe(true);
    expect(lines[start + 2]?.startsWith('hash =')).toBe(true);
    expect(lines[start + 3]?.startsWith('signer =')).toBe(true);
    expect(lines[start + 4]?.startsWith('signed-at =')).toBe(true);
    expect(lines[start + 5]?.startsWith('signature =')).toBe(true);
    expect(lines[start + 6]?.startsWith('reason =')).toBe(true);
  });
});

describe('upsertTrust', () => {
  test('replaces an existing entry for the same path', () => {
    const a = upsertTrust(emptyManifest(), {
      path: 'x.md',
      hash: 'blake3:1',
      signer: 'SHA256:a',
      signedAt: 't1',
      signature: 's1',
      reason: null,
    }).manifest;
    const b = upsertTrust(a, {
      path: 'x.md',
      hash: 'blake3:2',
      signer: 'SHA256:a',
      signedAt: 't2',
      signature: 's2',
      reason: null,
    });
    expect(b.replaced).toBe(true);
    expect(b.manifest.trust).toHaveLength(1);
    expect(b.manifest.trust[0]?.hash).toBe('blake3:2');
  });
});

describe('upsertUnlock', () => {
  test('replaces an existing unlock for the same path', () => {
    const a = upsertUnlock(emptyManifest(), {
      path: 'x.md',
      reason: 'first',
      unlockedAt: 't1',
      unlockedBy: 'u',
    }).manifest;
    const b = upsertUnlock(a, {
      path: 'x.md',
      reason: 'second',
      unlockedAt: 't2',
      unlockedBy: 'u',
    });
    expect(b.replaced).toBe(true);
    expect(b.manifest.unlock).toHaveLength(1);
    expect(b.manifest.unlock[0]?.reason).toBe('second');
  });
});
