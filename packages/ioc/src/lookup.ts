// Lookup orchestration. Spec: ADR 0015 §8.
//
// Combines manifest + per-ecosystem index + version-range matcher
// to answer "is <ecosystem>:<package>@<version> a known
// vulnerability?" without any I/O of its own — callers pass the
// already-loaded structures so this stays pure.

import { type Index, type PrunedAdvisory, getAdvisoriesForPackage } from './index-store.ts';
import { type Version, matchOsvRange, parseVersion } from './version.ts';

export type LookupTarget = {
  readonly ecosystem: string;
  readonly packageName: string;
  readonly version: string;
};

export type LookupMatch = {
  readonly advisory: PrunedAdvisory;
  // 'in-range' is a confident match; 'version-unknown' means we
  // found an advisory for the package but couldn't evaluate the
  // version range with M8's matcher (e.g. PyPI epoch versions,
  // GIT range type). Users should investigate manually.
  readonly confidence: 'in-range' | 'version-unknown';
  readonly note: string;
};

export type LookupResult = {
  readonly target: LookupTarget;
  readonly matches: ReadonlyArray<LookupMatch>;
};

// Pure: given a loaded Index and a target, return all matching
// advisories. Out-of-range advisories are filtered out; unknown
// ranges are reported with confidence: 'version-unknown'.
export function lookupInIndex(index: Index, target: LookupTarget): LookupResult {
  const candidates = getAdvisoriesForPackage(index, target.packageName);
  if (candidates.length === 0) {
    return { target, matches: [] };
  }

  const parsedTarget: Version | null = parseVersion(target.version);
  // If we can't parse the target version, report all advisories with
  // 'version-unknown' confidence so the user knows to investigate.
  if (parsedTarget === null) {
    return {
      target,
      matches: candidates.map((advisory) => ({
        advisory,
        confidence: 'version-unknown' as const,
        note: `target version "${target.version}" is not parseable as semver`,
      })),
    };
  }

  const matches: LookupMatch[] = [];
  for (const advisory of candidates) {
    let inRange = false;
    let firstUnknownWhy = '';
    for (const range of advisory.ranges) {
      const m = matchOsvRange(parsedTarget, range);
      if (m.kind === 'in-range') {
        inRange = true;
        break;
      }
      if (m.kind === 'unknown' && firstUnknownWhy === '') {
        firstUnknownWhy = m.why;
      }
    }
    if (inRange) {
      matches.push({ advisory, confidence: 'in-range', note: '' });
      continue;
    }
    if (firstUnknownWhy !== '') {
      matches.push({
        advisory,
        confidence: 'version-unknown',
        note: firstUnknownWhy,
      });
    }
    // Confidently out-of-range: skip.
  }

  return { target, matches };
}

// Parse the CLI argument form `<ecosystem>:<package>@<version>`.
// Returns null on malformed input so the caller can emit a helpful
// error rather than fail mid-lookup.
export function parseLookupTarget(input: string): LookupTarget | null {
  const colon = input.indexOf(':');
  if (colon === -1) return null;
  const ecosystem = input.slice(0, colon);
  const rest = input.slice(colon + 1);
  const at = rest.lastIndexOf('@');
  if (at <= 0) return null;
  const packageName = rest.slice(0, at);
  const version = rest.slice(at + 1);
  if (ecosystem.length === 0 || packageName.length === 0 || version.length === 0) return null;
  return { ecosystem, packageName, version };
}
