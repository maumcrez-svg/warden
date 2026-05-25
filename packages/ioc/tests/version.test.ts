import { describe, expect, test } from 'bun:test';
import { compareVersions, matchOsvRange, parseVersion } from '../src/version.ts';

describe('parseVersion', () => {
  test('parses major.minor.patch', () => {
    const v = parseVersion('1.2.3');
    expect(v).toEqual({ major: 1, minor: 2, patch: 3, prerelease: '', raw: '1.2.3' });
  });

  test('parses with leading v', () => {
    const v = parseVersion('v0.4.0');
    expect(v?.major).toBe(0);
    expect(v?.minor).toBe(4);
  });

  test('parses prerelease', () => {
    const v = parseVersion('2.0.0-beta.1');
    expect(v?.prerelease).toBe('beta.1');
  });

  test('parses build metadata (ignored)', () => {
    const v = parseVersion('1.0.0+sha.abcd');
    expect(v?.raw).toBe('1.0.0+sha.abcd');
  });

  test('rejects garbage', () => {
    expect(parseVersion('not a version')).toBeNull();
  });

  test('accepts single-component', () => {
    const v = parseVersion('3');
    expect(v?.major).toBe(3);
    expect(v?.minor).toBe(0);
    expect(v?.patch).toBe(0);
  });
});

describe('compareVersions', () => {
  test('major dominates', () => {
    const a = parseVersion('2.0.0');
    const b = parseVersion('1.99.99');
    expect(compareVersions(a as never, b as never)).toBe(1);
  });

  test('prerelease orders below release', () => {
    const a = parseVersion('1.0.0-rc.1');
    const b = parseVersion('1.0.0');
    expect(compareVersions(a as never, b as never)).toBe(-1);
  });

  test('numeric prerelease identifiers compared numerically', () => {
    const a = parseVersion('1.0.0-alpha.9');
    const b = parseVersion('1.0.0-alpha.10');
    expect(compareVersions(a as never, b as never)).toBe(-1);
  });
});

describe('matchOsvRange — SEMVER', () => {
  const range = {
    type: 'SEMVER' as const,
    events: [{ introduced: '1.0.0' }, { fixed: '1.2.3' }],
  };

  test('version in introduced..fixed → in-range', () => {
    const v = parseVersion('1.1.0');
    expect(matchOsvRange(v as never, range).kind).toBe('in-range');
  });

  test('version below introduced → out-of-range', () => {
    const v = parseVersion('0.9.9');
    expect(matchOsvRange(v as never, range).kind).toBe('out-of-range');
  });

  test('version at fixed → out-of-range (fixed is exclusive)', () => {
    const v = parseVersion('1.2.3');
    expect(matchOsvRange(v as never, range).kind).toBe('out-of-range');
  });

  test('introduced: "0" is treated as the beginning', () => {
    const r = { type: 'SEMVER' as const, events: [{ introduced: '0' }, { fixed: '1.0.0' }] };
    const v = parseVersion('0.5.0');
    expect(matchOsvRange(v as never, r).kind).toBe('in-range');
  });
});

describe('matchOsvRange — GIT (deferred)', () => {
  test('GIT type returns unknown with explanation', () => {
    const r = { type: 'GIT' as const, events: [{ introduced: 'abc' }] };
    const v = parseVersion('1.0.0');
    const m = matchOsvRange(v as never, r);
    expect(m.kind).toBe('unknown');
    if (m.kind === 'unknown') expect(m.why).toContain('GIT');
  });
});

describe('matchOsvRange — ECOSYSTEM fallback', () => {
  test('semver-shaped versions match like SEMVER', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }],
    };
    const v = parseVersion('1.5.0');
    expect(matchOsvRange(v as never, r).kind).toBe('in-range');
  });

  test('PEP 440 epoch versions yield unknown', () => {
    const r = {
      type: 'ECOSYSTEM' as const,
      events: [{ introduced: '1!1.0.0' }, { fixed: '1!2.0.0' }],
    };
    const v = parseVersion('1.5.0');
    const m = matchOsvRange(v as never, r);
    expect(m.kind).toBe('unknown');
  });
});
