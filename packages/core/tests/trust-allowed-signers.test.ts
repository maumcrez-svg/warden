import { describe, expect, test } from 'bun:test';
import {
  findEntryByFingerprint,
  fingerprintFromKeyData,
  parseAllowedSigners,
} from '../src/trust/allowed-signers.ts';

// Minimal valid ed25519 SSH public key data for fingerprint tests.
// The base64 payload below is the SSH wire format for an ed25519 pubkey
// — exact bytes do not need to match a real key, we just need a
// deterministic fingerprint for the parser tests.
const ED25519_KEYDATA = 'AAAAC3NzaC1lZDI1NTE5AAAAIINNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN';

describe('parseAllowedSigners', () => {
  test('parses a single entry with namespaces and comment', () => {
    const text = `rezende@example namespaces="warden" ssh-ed25519 ${ED25519_KEYDATA} rezende@laptop\n`;
    const r = parseAllowedSigners(text);
    expect(r.errors).toHaveLength(0);
    expect(r.entries).toHaveLength(1);
    const e = r.entries[0];
    expect(e?.principal).toBe('rezende@example');
    expect(e?.namespaces).toEqual(['warden']);
    expect(e?.keyType).toBe('ssh-ed25519');
    expect(e?.comment).toBe('rezende@laptop');
    expect(e?.fingerprint.startsWith('SHA256:')).toBe(true);
  });

  test('parses entry without namespaces option', () => {
    const text = `alice@example ssh-ed25519 ${ED25519_KEYDATA}\n`;
    const r = parseAllowedSigners(text);
    expect(r.errors).toHaveLength(0);
    expect(r.entries).toHaveLength(1);
    expect(r.entries[0]?.namespaces).toEqual([]);
  });

  test('ignores blank lines and comment lines', () => {
    const text = `# header\n\nrezende@example ssh-ed25519 ${ED25519_KEYDATA}\n# trailing\n`;
    const r = parseAllowedSigners(text);
    expect(r.entries).toHaveLength(1);
  });

  test('reports error for too-few-tokens line', () => {
    const r = parseAllowedSigners('only-one-token\n');
    expect(r.errors.length).toBeGreaterThan(0);
  });

  test('reports error for invalid base64 keydata', () => {
    const r = parseAllowedSigners('alice ssh-ed25519 not!base64\n');
    expect(r.errors.length).toBeGreaterThan(0);
  });
});

describe('fingerprintFromKeyData', () => {
  test('produces SHA256:<base64> form', () => {
    const fp = fingerprintFromKeyData(ED25519_KEYDATA);
    expect(fp).not.toBeNull();
    expect(fp?.startsWith('SHA256:')).toBe(true);
    // base64 without padding — should have no '='
    expect(fp?.includes('=')).toBe(false);
  });

  test('returns null for invalid base64', () => {
    expect(fingerprintFromKeyData('!@#$')).toBeNull();
  });
});

describe('findEntryByFingerprint', () => {
  test('returns matching entry', () => {
    const text = `alice ssh-ed25519 ${ED25519_KEYDATA}\n`;
    const r = parseAllowedSigners(text);
    const e = r.entries[0];
    if (e === undefined) throw new Error('no entry');
    const found = findEntryByFingerprint(r.entries, e.fingerprint);
    expect(found?.principal).toBe('alice');
  });

  test('returns null when no match', () => {
    const r = parseAllowedSigners(`alice ssh-ed25519 ${ED25519_KEYDATA}\n`);
    const found = findEntryByFingerprint(r.entries, 'SHA256:nope');
    expect(found).toBeNull();
  });
});
