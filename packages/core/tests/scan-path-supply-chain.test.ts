// scan-path integration tests for the M9 supply-chain layer. Uses
// in-memory IocLookup bundles to avoid depending on the real
// ~/.warden/ioc/ cache.
//
// All integration tests scan from REPO_ROOT (rather than the fixture
// sub-directory) because the `supply-chain-fixture` marker has a path
// restriction (ADR 0016 §7) that requires repo-root-relative paths
// starting with `tests/fixtures/supply-chain/`. Sub-directory scans
// would see relative paths like `package-lock.json` and fail the
// restriction check.

import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';
import { scanPath } from '../src/scan-path.ts';
import type { IocIndexAdvisory, IocOsvRange, ScanIocLookup } from '../src/scan-supply-chain.ts';

const REPO_ROOT = resolve(import.meta.dir, '../../..');

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

function makeNpmBundle(): ScanIocLookup {
  return {
    forEcosystem: (eco) => {
      if (eco !== 'npm') return null;
      return {
        getAdvisoriesForPackage: (name) => (name === 'event-stream' ? [eventStreamAdvisory] : []),
        matchRange: (version, range) => {
          let inRange = false;
          for (const e of range.events) {
            if (e.introduced !== undefined && version >= e.introduced) inRange = true;
            if (e.fixed !== undefined && version >= e.fixed) inRange = false;
          }
          return inRange ? 'in-range' : 'out-of-range';
        },
      };
    },
  };
}

// Scan all supply-chain fixtures by scanning from REPO_ROOT, then
// filter results to the fixture directory. The path restriction on
// the supply-chain-fixture marker (ADR 0016 §7) only matches when the
// scan sees repo-root-relative paths. Tests sharing one full-tree
// scan amortize the walk cost.
const fullRepoReport = (lookup: ScanIocLookup | null) => {
  if (lookup === null) {
    return scanPath(REPO_ROOT);
  }
  return scanPath(REPO_ROOT, { iocLookup: lookup, iocStateHint: 'fresh' });
};

const FIXTURE_PREFIX = 'tests/fixtures/supply-chain/';

describe('scanPath — supply-chain integration (ADR 0016)', () => {
  test('iocState is "absent" when lockfiles present but no iocLookup provided', () => {
    const report = fullRepoReport(null);
    expect(report.iocState).toBe('absent');
    expect(report.iocMessage).toContain("'warden ioc sync'");
  });

  test('all M9 supply-chain fixture lockfiles are recognized + their markers parsed', () => {
    const report = fullRepoReport(makeNpmBundle());
    const lockfileFiles = report.files.filter(
      (f) =>
        f.path.startsWith(FIXTURE_PREFIX) &&
        (f.kind === 'npm-lockfile' ||
          f.kind === 'poetry-lockfile' ||
          f.kind === 'uv-lockfile' ||
          f.kind === 'cargo-lockfile'),
    );
    expect(lockfileFiles.length).toBeGreaterThanOrEqual(6); // npm × 3 + cargo + poetry + uv
    // Every fixture carries a supply-chain-fixture marker.
    for (const f of lockfileFiles) {
      expect(f.marker?.families).toEqual(['supply-chain-fixture']);
    }
    expect(report.iocState).toBe('fresh');
  });

  test('npm-event-stream lockfile → 1 supply-chain finding (high, direct), suppressed by marker', () => {
    const report = fullRepoReport(makeNpmBundle());
    const f = report.files.find(
      (x) => x.path === `${FIXTURE_PREFIX}npm-event-stream/package-lock.json`,
    );
    expect(f).toBeDefined();
    expect(f?.marker?.families).toEqual(['supply-chain-fixture']);
    // Kept findings: 0 (suppressed by marker).
    expect(f?.supplyChainFindings.length).toBe(0);
    // Suppressed findings: 1.
    expect(f?.suppressedSupplyChainFindings.length).toBe(1);
    const sup = f?.suppressedSupplyChainFindings[0];
    expect(sup?.advisoryId).toBe('GHSA-mh6f-8j2x-4483');
    expect(sup?.position).toBe('direct');
    expect(sup?.severity).toBe('high');
  });

  test('npm-transitive lockfile → 1 suppressed finding (transitive modulation to medium)', () => {
    const report = fullRepoReport(makeNpmBundle());
    const f = report.files.find(
      (x) => x.path === `${FIXTURE_PREFIX}npm-transitive/package-lock.json`,
    );
    expect(f).toBeDefined();
    expect(f?.suppressedSupplyChainFindings.length).toBe(1);
    expect(f?.suppressedSupplyChainFindings[0]?.position).toBe('transitive');
    expect(f?.suppressedSupplyChainFindings[0]?.severity).toBe('medium');
  });

  test('npm-clean lockfile → 0 findings, 0 suppressed', () => {
    const report = fullRepoReport(makeNpmBundle());
    const f = report.files.find((x) => x.path === `${FIXTURE_PREFIX}npm-clean/package-lock.json`);
    expect(f?.supplyChainFindings.length).toBe(0);
    expect(f?.suppressedSupplyChainFindings.length).toBe(0);
  });

  test('cargo-clean / poetry-clean / uv-clean → 0 findings + 0 parse errors', () => {
    const report = fullRepoReport(makeNpmBundle());
    const fixtureParseErrors = report.supplyChainParseErrors.filter((e) =>
      e.path.startsWith(FIXTURE_PREFIX),
    );
    expect(fixtureParseErrors).toEqual([]);
    for (const dir of ['cargo-clean', 'poetry-clean', 'uv-clean']) {
      const f = report.files.find((x) => x.path.startsWith(`${FIXTURE_PREFIX}${dir}/`));
      expect(f?.supplyChainFindings.length).toBe(0);
    }
  });
});
