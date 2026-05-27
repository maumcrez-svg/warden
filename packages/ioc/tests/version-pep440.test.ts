import { describe, expect, test } from 'bun:test';
import {
  comparePep440Versions,
  matchPep440Range,
  parsePep440Version,
} from '../src/version-pep440.ts';

describe('parsePep440Version', () => {
  test('parses simple release', () => {
    const v = parsePep440Version('1.2.3');
    expect(v?.release).toEqual([1, 2, 3]);
    expect(v?.preKind).toBe('');
  });

  test('accepts leading v', () => {
    const v = parsePep440Version('v2.0');
    expect(v?.release).toEqual([2, 0]);
  });

  test('parses pre-release alpha', () => {
    const v = parsePep440Version('1.0a1');
    expect(v?.preKind).toBe('a');
    expect(v?.preNum).toBe(1);
  });

  test('parses pre-release with explicit alpha word', () => {
    const v = parsePep440Version('1.0.0alpha2');
    expect(v?.preKind).toBe('a');
    expect(v?.preNum).toBe(2);
  });

  test('parses rc with separator', () => {
    const v = parsePep440Version('1.0.0.rc1');
    expect(v?.preKind).toBe('rc');
    expect(v?.preNum).toBe(1);
  });

  test('parses post-release', () => {
    const v = parsePep440Version('1.0.0.post1');
    expect(v?.postNum).toBe(1);
  });

  test('parses dev-release', () => {
    const v = parsePep440Version('1.0.0.dev3');
    expect(v?.devNum).toBe(3);
  });

  test('parses pre + dev combined', () => {
    const v = parsePep440Version('1.0a1.dev0');
    expect(v?.preKind).toBe('a');
    expect(v?.preNum).toBe(1);
    expect(v?.devNum).toBe(0);
  });

  test('rejects epoch versions (deferred per ADR 0016 §2)', () => {
    expect(parsePep440Version('1!2.0')).toBeNull();
  });

  test('rejects local versions (deferred per ADR 0016 §2)', () => {
    expect(parsePep440Version('1.0+ubuntu1')).toBeNull();
  });

  test('rejects garbage', () => {
    expect(parsePep440Version('not a version')).toBeNull();
  });
});

describe('comparePep440Versions', () => {
  const cmp = (a: string, b: string): number => {
    const pa = parsePep440Version(a);
    const pb = parsePep440Version(b);
    if (pa === null || pb === null) throw new Error(`unparseable: ${a} or ${b}`);
    return comparePep440Versions(pa, pb);
  };

  test('release tuple dominates', () => {
    expect(cmp('2.0.0', '1.99.99')).toBe(1);
    expect(cmp('1.0', '1.0.0')).toBe(0);
  });

  test('pre-release orders before release', () => {
    expect(cmp('1.0a1', '1.0')).toBe(-1);
    expect(cmp('1.0', '1.0rc1')).toBe(1);
  });

  test('alpha < beta < rc', () => {
    expect(cmp('1.0a1', '1.0b1')).toBe(-1);
    expect(cmp('1.0b1', '1.0rc1')).toBe(-1);
  });

  test('post-release orders after release', () => {
    expect(cmp('1.0.post1', '1.0')).toBe(1);
    expect(cmp('1.0.post2', '1.0.post1')).toBe(1);
  });

  test('dev orders before its parent', () => {
    expect(cmp('1.0.dev1', '1.0')).toBe(-1);
    expect(cmp('1.0a1.dev0', '1.0a1')).toBe(-1);
  });
});

describe('matchPep440Range', () => {
  test('in-range when target between introduced and fixed', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1.0' }, { fixed: '2.0' }],
    };
    expect(matchPep440Range('1.5', r).kind).toBe('in-range');
  });

  test('out-of-range below introduced', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1.0' }, { fixed: '2.0' }],
    };
    expect(matchPep440Range('0.9', r).kind).toBe('out-of-range');
  });

  test('fixed is exclusive', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1.0' }, { fixed: '2.0' }],
    };
    expect(matchPep440Range('2.0', r).kind).toBe('out-of-range');
  });

  test('unknown when target has epoch (deferred)', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1.0' }, { fixed: '2.0' }],
    };
    const m = matchPep440Range('1!1.5', r);
    expect(m.kind).toBe('unknown');
  });

  test('introduced: "0" is the beginning', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '0' }, { fixed: '1.0' }],
    };
    expect(matchPep440Range('0.5', r).kind).toBe('in-range');
  });

  test('GIT range yields unknown', () => {
    const r = { type: 'GIT' as const, events: [{ introduced: 'abc' }] };
    expect(matchPep440Range('1.0', r).kind).toBe('unknown');
  });
});
