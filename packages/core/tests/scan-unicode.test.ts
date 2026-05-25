import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanUnicode } from '../src/scan-unicode.ts';

const FIXTURES = resolve(import.meta.dir, '../../../tests/fixtures/trapdoor');

const MALICIOUS = [
  'malicious-tag-chars.md',
  'malicious-vs-density.md',
  'malicious-bidi-spoof.md',
  'malicious-zwj-saturation.md',
] as const;

const BENIGN = [
  'benign-emoji-zwj.md',
  'benign-arabic-rtl.md',
  'benign-hangul.md',
  'benign-mixed-script.md',
] as const;

function read(name: string): string {
  return readFileSync(resolve(FIXTURES, name), 'utf8');
}

describe('scanUnicode — TrapDoor (T1) / GlassWorm (T2) fixtures', () => {
  for (const name of MALICIOUS) {
    test(`detects ${name}`, () => {
      const findings = scanUnicode(read(name));
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.severity === 'high')).toBe(true);
    });
  }

  for (const name of BENIGN) {
    test(`passes ${name}`, () => {
      const findings = scanUnicode(read(name));
      expect(findings).toEqual([]);
    });
  }
});

describe('scanUnicode — unit behavior', () => {
  test('empty input returns no findings', () => {
    expect(scanUnicode('')).toEqual([]);
  });

  test('ASCII-only input returns no findings', () => {
    expect(scanUnicode('# README\n\nplain text, no surprises.\n')).toEqual([]);
  });

  test('single Tag char is always-suspicious high', () => {
    const findings = scanUnicode(`hi${String.fromCodePoint(0xe0001)}`);
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    if (!finding) throw new Error('expected one finding');
    expect(finding.severity).toBe('high');
    expect(finding.kind).toBe('always-suspicious');
    expect(finding.codepoint).toBe(0xe0001);
    expect(finding.threatIds).toContain('T1');
  });

  test('single RLO override is high', () => {
    const findings = scanUnicode(`a${String.fromCodePoint(0x202e)}b`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.rangeName).toBe('Bidi overrides');
  });

  test('few variation selectors under threshold do not fire', () => {
    const input = `flag${String.fromCodePoint(0xe0100)}${String.fromCodePoint(0xe0101)}`;
    expect(scanUnicode(input)).toEqual([]);
  });

  test('variation selectors above threshold fire density-violation', () => {
    let payload = 'x';
    for (let i = 0; i < 32; i++) payload += String.fromCodePoint(0xe0100);
    const findings = scanUnicode(payload);
    expect(findings).toHaveLength(32);
    expect(findings.every((f) => f.kind === 'density-violation')).toBe(true);
    expect(findings.every((f) => f.severity === 'high')).toBe(true);
  });

  test('byte offsets are UTF-8 byte positions', () => {
    // "a" (1 byte) + emoji 😀 U+1F600 (4 bytes) + Tag char U+E0001 (4 bytes)
    const input = `a${String.fromCodePoint(0x1f600)}${String.fromCodePoint(0xe0001)}`;
    const findings = scanUnicode(input);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.byteOffset).toBe(5);
  });

  test('Hangul Filler (U+3164) is medium severity', () => {
    const findings = scanUnicode(`alpha${String.fromCodePoint(0x3164)}beta`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });
});
