import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { IocIndexAdvisory, IocLookup, IocOsvRange } from '../src/scan-supply-chain.ts';
import { scanSupplyChain } from '../src/scan-supply-chain.ts';

const FIXTURES = resolve(import.meta.dir, '../../../tests/fixtures/supply-chain');

// Tiny in-memory IocLookup; emulates the shape the real bundle
// provides without depending on @warden-sh/ioc. ADR 0016 §8 — core
// is offline-pure and consumes a callable-data lookup, not a typed
// ioc import.
function makeLookup(advisories: Record<string, ReadonlyArray<IocIndexAdvisory>>): IocLookup {
  return {
    getAdvisoriesForPackage: (name) => advisories[name] ?? [],
    matchRange: (version, range) => {
      // Naive semver matcher: matches when version is within any
      // introduced/fixed window in the range events. Adequate for
      // these unit tests; the real CLI uses the @warden-sh/ioc
      // SEMVER + PEP 440 matchers.
      let inRange = false;
      for (const e of range.events) {
        if (e.introduced !== undefined && version >= e.introduced) inRange = true;
        if (e.fixed !== undefined && version >= e.fixed) inRange = false;
      }
      return inRange ? 'in-range' : 'out-of-range';
    },
  };
}

const eventStreamAdvisory: IocIndexAdvisory = {
  id: 'GHSA-mh6f-8j2x-4483',
  severity: 'high',
  summary: 'Critical severity vulnerability that affects event-stream and flatmap-stream',
  ranges: [
    {
      type: 'SEMVER',
      events: [{ introduced: '3.3.6' }, { fixed: '4.0.0' }],
    } as IocOsvRange,
  ],
  references: ['https://github.com/dominictarr/event-stream/issues/116'],
};

describe('scanSupplyChain — npm fixtures', () => {
  test('event-stream@3.3.6 (direct) → high finding', () => {
    const content = readFileSync(resolve(FIXTURES, 'npm-event-stream/package-lock.json'), 'utf8');
    const lookup = makeLookup({ 'event-stream': [eventStreamAdvisory] });
    const result = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: content, manifestContent: null },
      lookup,
    );
    expect(result.parseError).toBeNull();
    expect(result.findings.length).toBe(1);
    const f = result.findings[0];
    expect(f?.advisoryId).toBe('GHSA-mh6f-8j2x-4483');
    expect(f?.packageName).toBe('event-stream');
    expect(f?.version).toBe('3.3.6');
    expect(f?.position).toBe('direct');
    expect(f?.severity).toBe('high');
    expect(f?.threatIds).toEqual(['T6']);
  });

  test('event-stream@3.3.6 (transitive) → medium (modulated from high)', () => {
    const content = readFileSync(resolve(FIXTURES, 'npm-transitive/package-lock.json'), 'utf8');
    const lookup = makeLookup({ 'event-stream': [eventStreamAdvisory] });
    const result = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: content, manifestContent: null },
      lookup,
    );
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]?.position).toBe('transitive');
    expect(result.findings[0]?.severity).toBe('medium');
  });

  test('event-stream@4.0.1 → no finding (out-of-range)', () => {
    const content = readFileSync(resolve(FIXTURES, 'npm-clean/package-lock.json'), 'utf8');
    const lookup = makeLookup({ 'event-stream': [eventStreamAdvisory] });
    const result = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: content, manifestContent: null },
      lookup,
    );
    expect(result.findings.length).toBe(0);
    expect(result.parseError).toBeNull();
  });

  test('malformed npm lockfileVersion → parseError surfaced (non-fatal)', () => {
    const content = '{"lockfileVersion":1,"dependencies":{}}';
    const result = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: content, manifestContent: null },
      makeLookup({}),
    );
    expect(result.parseError).toContain('v2/v3');
    expect(result.findings.length).toBe(0);
  });
});

describe('scanSupplyChain — direct vs transitive matrix (ADR 0016 §4)', () => {
  const highAdv: IocIndexAdvisory = {
    id: 'GHSA-test-high',
    severity: 'high',
    summary: 'high',
    ranges: [
      { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] } as IocOsvRange,
    ],
    references: [],
  };
  const moderateAdv: IocIndexAdvisory = {
    id: 'GHSA-test-moderate',
    severity: 'medium',
    summary: 'moderate',
    ranges: [
      { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] } as IocOsvRange,
    ],
    references: [],
  };
  const lowAdv: IocIndexAdvisory = {
    id: 'GHSA-test-low',
    severity: 'low',
    summary: 'low',
    ranges: [
      { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '2.0.0' }] } as IocOsvRange,
    ],
    references: [],
  };

  function emit(adv: IocIndexAdvisory, position: 'direct' | 'transitive'): string {
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': position === 'direct' ? { dependencies: { x: '1.0.0' } } : {},
        ...(position === 'transitive'
          ? {
              'node_modules/parent': { version: '0.1.0', dependencies: { x: '1.0.0' } },
              'node_modules/parent/node_modules/x': { version: '1.0.0' },
            }
          : { 'node_modules/x': { version: '1.0.0' } }),
      },
    });
    const r = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: lockfile, manifestContent: null },
      makeLookup({ x: [adv] }),
    );
    return r.findings[0]?.severity ?? 'none';
  }

  test('direct HIGH → high', () => {
    expect(emit(highAdv, 'direct')).toBe('high');
  });
  test('direct MODERATE → medium', () => {
    expect(emit(moderateAdv, 'direct')).toBe('medium');
  });
  test('direct LOW → low', () => {
    expect(emit(lowAdv, 'direct')).toBe('low');
  });
  test('transitive HIGH → medium', () => {
    expect(emit(highAdv, 'transitive')).toBe('medium');
  });
  test('transitive MODERATE → low', () => {
    expect(emit(moderateAdv, 'transitive')).toBe('low');
  });
  test('transitive LOW → info', () => {
    expect(emit(lowAdv, 'transitive')).toBe('info');
  });
});

describe('scanSupplyChain — cargo + poetry + uv fixtures (benign)', () => {
  function clean(kind: 'cargo-lockfile' | 'poetry-lockfile' | 'uv-lockfile', dir: string): void {
    const lockBase =
      kind === 'cargo-lockfile'
        ? 'Cargo.lock'
        : kind === 'poetry-lockfile'
          ? 'poetry.lock'
          : 'uv.lock';
    const manifestBase =
      kind === 'cargo-lockfile'
        ? 'Cargo.toml'
        : kind === 'poetry-lockfile'
          ? 'pyproject.toml'
          : null;
    const lock = readFileSync(resolve(FIXTURES, dir, lockBase), 'utf8');
    const manifest =
      manifestBase === null ? null : readFileSync(resolve(FIXTURES, dir, manifestBase), 'utf8');
    const result = scanSupplyChain(
      { lockfileKind: kind, lockfileContent: lock, manifestContent: manifest },
      makeLookup({}),
    );
    expect(result.parseError).toBeNull();
    expect(result.findings.length).toBe(0);
  }

  test('cargo-clean parses cleanly', () => clean('cargo-lockfile', 'cargo-clean'));
  test('poetry-clean parses cleanly', () => clean('poetry-lockfile', 'poetry-clean'));
  test('uv-clean parses cleanly', () => clean('uv-lockfile', 'uv-clean'));
});

describe('scanSupplyChain — version-unknown confidence', () => {
  test('range type the matcher cannot evaluate → finding with confidence:version-unknown', () => {
    const lookup: IocLookup = {
      getAdvisoriesForPackage: (name) =>
        name === 'unknown-pkg'
          ? [
              {
                id: 'GHSA-test-unknown',
                severity: 'high',
                summary: 'unknown range',
                ranges: [{ type: 'GIT', events: [{ introduced: 'abc' }] } as IocOsvRange],
                references: [],
              },
            ]
          : [],
      matchRange: (_v, r) => {
        if (r.type === 'GIT') return { kind: 'unknown', why: 'GIT not supported' };
        return 'out-of-range';
      },
    };
    const lockfile = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { 'unknown-pkg': '1.0.0' } },
        'node_modules/unknown-pkg': { version: '1.0.0' },
      },
    });
    const result = scanSupplyChain(
      { lockfileKind: 'npm-lockfile', lockfileContent: lockfile, manifestContent: null },
      lookup,
    );
    expect(result.findings.length).toBe(1);
    expect(result.findings[0]?.confidence).toBe('version-unknown');
  });
});
