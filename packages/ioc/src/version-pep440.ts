// PEP 440 version parser. Spec: ADR 0016 §2 (M9 version semantics).
// Reference grammar: PEP 440 — https://peps.python.org/pep-0440/
// (verified 2026-05-25).
//
// Pure functions. No I/O.
//
// Coverage:
//   release        N(.N)*                       — required
//   pre-release    {a|b|rc|alpha|beta|pre|preview}N — optional (preceded by '.', '-', '_' or nothing)
//   post-release   .postN  (also -N as shorthand, _postN, .rev/r N)
//   dev-release    .devN
//   optional leading 'v'
//
// Deliberately deferred (ADR 0016 §2):
//   epoch          N!N
//   local version  +<segment>
// Versions containing either yield `null` from parsePep440Version so
// callers can route them to the `version-unknown` match result.

export type Pep440Version = {
  // Release tuple, normalized to numeric components, padded with zeros
  // only for direct comparisons via comparePep440Versions. Stored as a
  // trimmed (no trailing zero pad) array here so the raw shape is
  // preserved for evidence output.
  readonly release: ReadonlyArray<number>;
  // Pre-release kind: '' = none, 'a'|'b'|'rc' = canonical alphas, 'dev'
  // and 'post' for those families. We collapse aliases (alpha→a,
  // beta→b, c/pre/preview→rc) to canonical kinds per PEP 440 §Version
  // matching.
  readonly preKind: '' | 'a' | 'b' | 'rc';
  readonly preNum: number;
  readonly postNum: number; // -1 if absent
  readonly devNum: number; // -1 if absent
  readonly raw: string;
};

// Single regex anchored to the full input. Captures: optional 'v',
// release segments, optional pre-release (with separator), optional
// post-release (.postN or -N or .rev/.r N), optional dev-release.
// PEP 440 normalization rules are applied in code on the captures.
const PEP440_RE =
  /^v?(\d+(?:\.\d+)*)(?:[._-]?(a|b|c|rc|alpha|beta|pre|preview)\.?(\d+)?)?(?:(?:\.post|-)(\d+)|\.rev(\d+)|\.r(\d+)|_post(\d+))?(?:\.dev(\d+))?$/i;

function normalizePreKind(raw: string): 'a' | 'b' | 'rc' {
  const lower = raw.toLowerCase();
  if (lower === 'a' || lower === 'alpha') return 'a';
  if (lower === 'b' || lower === 'beta') return 'b';
  // 'c', 'rc', 'pre', 'preview' all normalize to 'rc' per PEP 440.
  return 'rc';
}

export function parsePep440Version(input: string): Pep440Version | null {
  const trimmed = input.trim();
  if (trimmed === '') return null;
  // Deferred features: epoch and local version. Honest-unknown beats
  // confidently-wrong (ADR 0016 §2).
  if (trimmed.includes('!')) return null;
  if (trimmed.includes('+')) return null;

  const m = PEP440_RE.exec(trimmed);
  if (m === null) return null;

  const releaseStr = m[1] ?? '';
  const release = releaseStr.split('.').map((seg) => Number.parseInt(seg, 10));
  for (const n of release) {
    if (!Number.isFinite(n)) return null;
  }

  let preKind: '' | 'a' | 'b' | 'rc' = '';
  let preNum = 0;
  if (m[2] !== undefined) {
    preKind = normalizePreKind(m[2]);
    preNum = m[3] !== undefined ? Number.parseInt(m[3], 10) : 0;
  }

  // Post-release: .postN, -N shorthand, .revN, .rN, _postN — collapse
  // to a single field. Implicit post (just '-N' without 'post') is
  // PEP 440-compatible only when no other separator applies; the regex
  // already disambiguates.
  let postNum = -1;
  for (const idx of [4, 5, 6, 7]) {
    const v = m[idx];
    if (v !== undefined) {
      postNum = Number.parseInt(v, 10);
      break;
    }
  }

  const devNum = m[8] !== undefined ? Number.parseInt(m[8], 10) : -1;

  return { release, preKind, preNum, postNum, devNum, raw: input };
}

function compareReleaseTuples(a: ReadonlyArray<number>, b: ReadonlyArray<number>): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return 0;
}

// PEP 440 §Version ordering. Ordering inside a release tuple:
//   .devN  <  alpha  <  beta  <  rc  <  release  <  .postN
// dev coexists with pre and post: a pre/post may itself carry a dev
// (e.g. "1.0a1.dev0"). We model dev as "subtracts" from whatever
// release+pre+post slot the version otherwise occupies — PEP 440 calls
// this "dev releases sort before everything else of the same parent."
export function comparePep440Versions(a: Pep440Version, b: Pep440Version): number {
  const releaseCmp = compareReleaseTuples(a.release, b.release);
  if (releaseCmp !== 0) return releaseCmp;

  // Pre-release ordering: absent (release) > 'rc' > 'b' > 'a' > none
  // BUT this only applies if both versions are at the release tuple
  // level (no post). When post is present, pre is irrelevant since
  // post lifts above release; but a post-release can also have its
  // own pre-release in theory — we keep it simple and compare pre
  // only when both lack a post.
  const aPreRank = a.preKind === '' ? 4 : a.preKind === 'a' ? 1 : a.preKind === 'b' ? 2 : 3;
  const bPreRank = b.preKind === '' ? 4 : b.preKind === 'a' ? 1 : b.preKind === 'b' ? 2 : 3;

  // Post-release: present > absent.
  const aHasPost = a.postNum >= 0;
  const bHasPost = b.postNum >= 0;
  // Dev-release: present < absent at the same level.
  const aHasDev = a.devNum >= 0;
  const bHasDev = b.devNum >= 0;

  // Compare pre-release rank first (release > rc > b > a).
  if (aPreRank !== bPreRank) return aPreRank < bPreRank ? -1 : 1;
  if (aPreRank !== 4 && a.preNum !== b.preNum) return a.preNum < b.preNum ? -1 : 1;

  // Post-release segment.
  if (aHasPost !== bHasPost) return aHasPost ? 1 : -1;
  if (aHasPost && bHasPost && a.postNum !== b.postNum) return a.postNum < b.postNum ? -1 : 1;

  // Dev-release at the same parent: dev is lower than no-dev.
  if (aHasDev !== bHasDev) return aHasDev ? -1 : 1;
  if (aHasDev && bHasDev && a.devNum !== b.devNum) return a.devNum < b.devNum ? -1 : 1;

  return 0;
}

// OSV ECOSYSTEM range matcher specialized for PyPI / PEP 440.
// Mirrors the SEMVER matcher's event-walk semantics (ADR 0015 §5) so
// callers see the same MatchResult shape.

import type { MatchResult, OsvRange } from './version.ts';

export function matchPep440Range(targetRaw: string, range: OsvRange): MatchResult {
  if (range.type === 'GIT') {
    return { kind: 'unknown', why: 'GIT range type not supported' };
  }
  if (range.events.length === 0) {
    return { kind: 'unknown', why: 'empty events list' };
  }
  const target = parsePep440Version(targetRaw);
  if (target === null) {
    return { kind: 'unknown', why: `cannot parse target version "${targetRaw}" as PEP 440` };
  }

  const ZERO: Pep440Version = {
    release: [0],
    preKind: '',
    preNum: 0,
    postNum: -1,
    devNum: -1,
    raw: '0',
  };

  let inRange = false;
  for (const e of range.events) {
    if (e.introduced !== undefined) {
      const introduced = e.introduced === '0' ? ZERO : parsePep440Version(e.introduced);
      if (introduced === null) {
        return {
          kind: 'unknown',
          why: `cannot parse introduced version "${e.introduced}" as PEP 440`,
        };
      }
      if (comparePep440Versions(target, introduced) >= 0) inRange = true;
      continue;
    }
    if (e.fixed !== undefined) {
      const fixed = parsePep440Version(e.fixed);
      if (fixed === null) {
        return { kind: 'unknown', why: `cannot parse fixed version "${e.fixed}" as PEP 440` };
      }
      if (comparePep440Versions(target, fixed) >= 0) inRange = false;
      continue;
    }
    if (e.last_affected !== undefined) {
      const last = parsePep440Version(e.last_affected);
      if (last === null) {
        return {
          kind: 'unknown',
          why: `cannot parse last_affected version "${e.last_affected}" as PEP 440`,
        };
      }
      if (comparePep440Versions(target, last) > 0) inRange = false;
      continue;
    }
    if (e.limit !== undefined) {
      return { kind: 'unknown', why: '`limit` event semantics not supported' };
    }
  }
  return inRange ? { kind: 'in-range' } : { kind: 'out-of-range' };
}
