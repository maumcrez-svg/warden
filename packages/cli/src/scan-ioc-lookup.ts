// Build the ScanIocLookup bundle that `warden scan` passes into
// scanPath. This file lives in the CLI (not in @warden-sh/core)
// because the bundle reaches into @warden-sh/ioc — packages/core is
// offline-pure and does not depend on the IOC package (ADR 0015 §7;
// ADR 0016 §8).

import { homedir } from 'node:os';
import { resolve } from 'node:path';
import type { IocLookup, IocOsvRange, ScanIocLookup } from '@warden-sh/core';
import {
  type Index,
  ageHoursSinceSync,
  indexPath,
  matchOsvRange,
  matchPep440Range,
  parseVersion,
  readIndex,
  readManifest,
} from '@warden-sh/ioc';

// Default staleness threshold: 7 days. Matches ADR 0016 §5 default of
// 7d before stderr emits a "stale" warning. Future `.warden.toml`
// config can override; for M9 the constant lives here.
const DEFAULT_STALENESS_HOURS = 7 * 24;

export type ScanIocBundle = {
  readonly state: 'absent' | 'fresh' | 'stale' | 'unreadable';
  readonly message: string | null;
  readonly lookup: ScanIocLookup | null;
};

export function defaultIocCacheRoot(): string {
  const xdg = process.env.XDG_CACHE_HOME;
  if (typeof xdg === 'string' && xdg.length > 0) {
    return resolve(xdg, 'warden', 'ioc');
  }
  return resolve(homedir(), '.warden', 'ioc');
}

export function buildScanIocBundle(cacheRoot: string = defaultIocCacheRoot()): ScanIocBundle {
  const manifestRead = readManifest(resolve(cacheRoot, 'manifest.json'));
  if (manifestRead.kind === 'missing') {
    return {
      state: 'absent',
      message: "ioc cache not initialized; run 'warden ioc sync' to enable supply-chain checks",
      lookup: null,
    };
  }
  if (manifestRead.kind === 'error') {
    return {
      state: 'unreadable',
      message: `ioc cache unreadable: ${manifestRead.message}`,
      lookup: null,
    };
  }
  const ageHours = ageHoursSinceSync(manifestRead.manifest);
  const state = ageHours >= DEFAULT_STALENESS_HOURS ? 'stale' : 'fresh';

  // Per-ecosystem lazy loader. Keep loaded indexes in a local cache so
  // multiple lockfiles of the same ecosystem in one scan share the I/O.
  const indexCache = new Map<string, Index | null>();
  const loadIndex = (ecosystem: string): Index | null => {
    if (indexCache.has(ecosystem)) {
      return indexCache.get(ecosystem) ?? null;
    }
    const r = readIndex(indexPath(cacheRoot, ecosystem));
    if (r.kind === 'ok') {
      indexCache.set(ecosystem, r.index);
      return r.index;
    }
    indexCache.set(ecosystem, null);
    return null;
  };

  const lookup: ScanIocLookup = {
    forEcosystem: (ecosystem) => {
      const index = loadIndex(ecosystem);
      if (index === null) return null;
      return buildIocLookup(index, ecosystem);
    },
  };

  return { state, message: null, lookup };
}

function buildIocLookup(index: Index, ecosystem: string): IocLookup {
  // SEMVER matcher (npm, crates.io) vs PEP 440 matcher (PyPI). The
  // ADR 0016 §2 contract: the matcher returns 'in-range' /
  // 'out-of-range' / { kind: 'unknown', why } same shape for both.
  const usePep440 = ecosystem === 'PyPI';

  return {
    getAdvisoriesForPackage: (name: string) => {
      const advisories = index.packages[name];
      if (advisories === undefined) {
        // PyPI normalizes name comparison (PEP 503). Try the canonical
        // form when the literal match fails.
        if (usePep440) {
          const normalized = normalizePypiName(name);
          if (normalized !== name) {
            return index.packages[normalized] ?? [];
          }
        }
        return [];
      }
      return advisories;
    },
    matchRange: (version: string, range: IocOsvRange) => {
      if (usePep440) {
        const m = matchPep440Range(version, range);
        if (m.kind === 'in-range') return 'in-range';
        if (m.kind === 'out-of-range') return 'out-of-range';
        return { kind: 'unknown', why: m.why };
      }
      const parsed = parseVersion(version);
      if (parsed === null) {
        return { kind: 'unknown', why: `cannot parse semver "${version}"` };
      }
      const m = matchOsvRange(parsed, range);
      if (m.kind === 'in-range') return 'in-range';
      if (m.kind === 'out-of-range') return 'out-of-range';
      return { kind: 'unknown', why: m.why };
    },
  };
}

// PEP 503 normalization (case-insensitive, runs of [_.-] → single '-')
// is the PyPI canonical name for advisory lookup.
function normalizePypiName(name: string): string {
  return name.replace(/[-_.]+/g, '-').toLowerCase();
}
