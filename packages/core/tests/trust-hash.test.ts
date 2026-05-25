import { describe, expect, test } from 'bun:test';
import { hashFileContent, parseHash } from '../src/trust/hash.ts';

describe('hashFileContent', () => {
  test('hashes the empty string with blake3 prefix', () => {
    const h = hashFileContent(new Uint8Array());
    expect(h.startsWith('blake3:')).toBe(true);
    // blake3 digest length is 32 bytes = 64 hex chars
    expect(h.length).toBe('blake3:'.length + 64);
  });

  test('is deterministic for the same input', () => {
    const a = hashFileContent(new TextEncoder().encode('hello world'));
    const b = hashFileContent(new TextEncoder().encode('hello world'));
    expect(a).toBe(b);
  });

  test('differs for different inputs', () => {
    const a = hashFileContent(new TextEncoder().encode('a'));
    const b = hashFileContent(new TextEncoder().encode('b'));
    expect(a).not.toBe(b);
  });
});

describe('parseHash', () => {
  test('accepts blake3:<hex>', () => {
    const r = parseHash('blake3:abcdef0123');
    expect(r).not.toBeNull();
    expect(r?.algo).toBe('blake3');
    expect(r?.hex).toBe('abcdef0123');
  });

  test('rejects missing prefix', () => {
    expect(parseHash('deadbeef')).toBeNull();
  });

  test('rejects non-hex hex portion', () => {
    expect(parseHash('blake3:nothex!')).toBeNull();
  });
});
