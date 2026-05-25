// Minimal SemVer comparator for OSV range matching. ADR 0015 §5 +
// §12 resolved-decisions note: M8 ships a basic SEMVER comparator
// adequate for the `warden ioc lookup` debug surface. M9 will
// generalize to per-ecosystem version grammars (PEP 440, Cargo,
// Go pseudo-versions) when the scanner-finding integration lands.
//
// Pure functions. No I/O.

export type Version = {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  // Prerelease tag (e.g. "alpha.1"). Empty string = no prerelease.
  readonly prerelease: string;
  // Original string, retained for evidence output.
  readonly raw: string;
};

const VERSION_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseVersion(input: string): Version | null {
  const m = VERSION_RE.exec(input.trim());
  if (m === null) return null;
  const major = Number.parseInt(m[1] ?? '0', 10);
  const minor = Number.parseInt(m[2] ?? '0', 10);
  const patch = Number.parseInt(m[3] ?? '0', 10);
  const prerelease = m[4] ?? '';
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null;
  return { major, minor, patch, prerelease, raw: input };
}

// SemVer 2.0.0 ordering: numeric identifiers are compared numerically,
// alphanumeric lexically, numeric < alphanumeric, fewer fields < more
// fields. A version without a prerelease is greater than one with a
// prerelease at the same major.minor.patch.
function comparePrerelease(a: string, b: string): number {
  if (a === b) return 0;
  if (a === '' && b !== '') return 1;
  if (a !== '' && b === '') return -1;
  const aParts = a.split('.');
  const bParts = b.split('.');
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const ap = aParts[i];
    const bp = bParts[i];
    if (ap === undefined) return -1;
    if (bp === undefined) return 1;
    const aNum = /^\d+$/.test(ap);
    const bNum = /^\d+$/.test(bp);
    if (aNum && bNum) {
      const an = Number.parseInt(ap, 10);
      const bn = Number.parseInt(bp, 10);
      if (an !== bn) return an < bn ? -1 : 1;
      continue;
    }
    if (aNum !== bNum) return aNum ? -1 : 1;
    if (ap !== bp) return ap < bp ? -1 : 1;
  }
  return 0;
}

export function compareVersions(a: Version, b: Version): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return comparePrerelease(a.prerelease, b.prerelease);
}

// OSV range event sequence: an interleaved [introduced, fixed,
// limit, last_affected] event list per the OSV schema
// (https://ossf.github.io/osv-schema/, verified 2026-05-25).
// For M8 we support `introduced` and `fixed` only; `limit` and
// `last_affected` are uncommon and would need their own semantics
// — when they appear, the matcher returns 'unknown' rather than a
// confidently-wrong answer.
export type OsvRangeEvent = {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly limit?: string;
  readonly last_affected?: string;
};

export type OsvRange = {
  readonly type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  readonly events: ReadonlyArray<OsvRangeEvent>;
};

export type MatchResult =
  | { readonly kind: 'in-range' }
  | { readonly kind: 'out-of-range' }
  | { readonly kind: 'unknown'; readonly why: string };

// Walk the event list. A target version is in-range if there's an
// introduced event preceding (or at) it without a matching fixed
// event preceding (or at) it. OSV's event list is documented to be
// in version order; we re-sort defensively to be robust against
// malformed feeds.
export function matchOsvRange(target: Version, range: OsvRange): MatchResult {
  if (range.type === 'GIT') {
    return { kind: 'unknown', why: 'GIT range type not supported in M8' };
  }
  if (range.type === 'ECOSYSTEM') {
    // Best-effort: try the semver comparator. If introduced/fixed
    // versions don't parse as semver, fall back to 'unknown' so the
    // caller can surface a "verify manually" hint.
    for (const e of range.events) {
      const probe = e.introduced ?? e.fixed ?? e.limit ?? e.last_affected;
      if (probe !== undefined && probe !== '0' && parseVersion(probe) === null) {
        return {
          kind: 'unknown',
          why: `ECOSYSTEM range with non-semver version "${probe}" not supported in M8`,
        };
      }
    }
  }
  if (range.events.length === 0) {
    return { kind: 'unknown', why: 'empty events list' };
  }

  // Special: "introduced": "0" means "from the beginning of time."
  // Compare against {major:0,minor:0,patch:0,prerelease:""}.
  const ZERO: Version = { major: 0, minor: 0, patch: 0, prerelease: '', raw: '0' };

  let inRange = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      const introduced = event.introduced === '0' ? ZERO : parseVersion(event.introduced);
      if (introduced === null) {
        return {
          kind: 'unknown',
          why: `cannot parse introduced version "${event.introduced}"`,
        };
      }
      if (compareVersions(target, introduced) >= 0) inRange = true;
      continue;
    }
    if (event.fixed !== undefined) {
      const fixed = parseVersion(event.fixed);
      if (fixed === null) {
        return { kind: 'unknown', why: `cannot parse fixed version "${event.fixed}"` };
      }
      if (compareVersions(target, fixed) >= 0) inRange = false;
      continue;
    }
    if (event.last_affected !== undefined) {
      const last = parseVersion(event.last_affected);
      if (last === null) {
        return {
          kind: 'unknown',
          why: `cannot parse last_affected version "${event.last_affected}"`,
        };
      }
      if (compareVersions(target, last) > 0) inRange = false;
      continue;
    }
    if (event.limit !== undefined) {
      return { kind: 'unknown', why: '`limit` event semantics deferred to M9' };
    }
  }
  return inRange ? { kind: 'in-range' } : { kind: 'out-of-range' };
}
