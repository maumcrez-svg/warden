// scanSupplyChain — pure function that consumes a lockfile (+ optional
// manifest, + a loaded OSV-style index) and emits
// `supply-chain.osv-known-vulnerability` findings.
//
// Spec: ADR 0016 §§4–5, §8.
//
// The orchestrator owns:
//   - Dispatching to the right per-lockfile parser.
//   - Looking up each entry in the IOC index.
//   - Severity modulation: direct vs transitive (ADR 0016 §4 matrix).
//
// What it does NOT own:
//   - Reading bytes from disk (callers do that).
//   - Loading the index (callers do that — index loads happen once
//     per scan, not once per lockfile).
//   - Network. There is no I/O in this file.

import type { FileKind } from './detect-format.ts';
import type { SupplyChainFinding, SupplyChainSeverity } from './findings.ts';
import { parseCargoLockfile } from './lockfiles/lockfile-cargo.ts';
import { parseNpmLockfile } from './lockfiles/lockfile-npm.ts';
import { parsePoetryLockfile } from './lockfiles/lockfile-poetry.ts';
import { parseUvLockfile } from './lockfiles/lockfile-uv.ts';
import type { LockfileEcosystem, LockfileEntry } from './lockfiles/types.ts';

// The minimal "loaded index" shape this scanner consumes. We don't
// import @warden-sh/ioc here to keep the dep direction clean
// (packages/core does not currently depend on @warden-sh/ioc; the
// orchestrator that calls scanSupplyChain wires the index through as
// data, not as a typed import).
export type IocIndexAdvisory = {
  readonly id: string;
  readonly severity: 'high' | 'medium' | 'low';
  readonly summary: string;
  readonly ranges: ReadonlyArray<IocOsvRange>;
  readonly references: ReadonlyArray<string>;
};

export type IocOsvRange = {
  readonly type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  readonly events: ReadonlyArray<{
    readonly introduced?: string;
    readonly fixed?: string;
    readonly limit?: string;
    readonly last_affected?: string;
  }>;
};

// Range-matcher contract: callers pass a matcher function so this
// module remains type-agnostic about how SEMVER vs PEP 440 is
// resolved. The orchestrator in scan-path.ts wires the SEMVER matcher
// from @warden-sh/ioc for npm/Cargo and the PEP 440 matcher for PyPI
// lockfiles.
export type RangeMatcher = (
  targetVersion: string,
  range: IocOsvRange,
) => 'in-range' | 'out-of-range' | { readonly kind: 'unknown'; readonly why: string };

export type IocLookup = {
  readonly getAdvisoriesForPackage: (name: string) => ReadonlyArray<IocIndexAdvisory>;
  readonly matchRange: RangeMatcher;
};

// Per-ecosystem dispatcher. The CLI (which depends on @warden-sh/ioc)
// constructs the bundle; packages/core stays independent of the
// network-bound package — see ADR 0015 §7 + ADR 0016 §8.
export type ScanIocLookup = {
  readonly forEcosystem: (ecosystem: 'npm' | 'PyPI' | 'crates.io') => IocLookup | null;
};

export type ScanSupplyChainInput = {
  readonly lockfileKind: FileKind;
  readonly lockfileContent: string;
  // For poetry-lockfile / cargo-lockfile: the adjacent manifest's
  // contents, when readable. Pass `null` to fall back to all-direct
  // classification (ADR 0016 §3).
  readonly manifestContent: string | null;
};

export type ScanSupplyChainResult = {
  readonly findings: ReadonlyArray<SupplyChainFinding>;
  // Surfaces non-fatal parse problems (e.g. v1 npm lockfile) so the
  // CLI can warn without aborting the whole scan.
  readonly parseError: string | null;
};

// Non-fatal lockfile parse problem. Surfaces into ScanReport so the
// CLI can warn on stderr without aborting the whole scan. Distinct
// from marker errors (which gate exit 2).
export type SupplyChainParseError = {
  readonly path: string;
  readonly message: string;
};

// Direct vs transitive × upstream severity → emitted severity.
// ADR 0016 §4 matrix.
function modulateSeverity(
  base: 'high' | 'medium' | 'low',
  position: 'direct' | 'transitive',
): SupplyChainSeverity {
  if (position === 'direct') return base;
  // Transitive: shift down one tier; low → info.
  if (base === 'high') return 'medium';
  if (base === 'medium') return 'low';
  return 'info';
}

export function scanSupplyChain(
  input: ScanSupplyChainInput,
  lookup: IocLookup,
): ScanSupplyChainResult {
  const parsed = parseLockfileByKind(input);
  if (parsed.kind === 'error') {
    return { findings: [], parseError: parsed.message };
  }

  const findings: SupplyChainFinding[] = [];
  for (const entry of parsed.entries) {
    if (!entryEcosystemMatches(entry.ecosystem, input.lockfileKind)) continue;
    const advisories = lookup.getAdvisoriesForPackage(entry.name);
    if (advisories.length === 0) continue;
    for (const adv of advisories) {
      const match = evaluateRanges(entry.version, adv.ranges, lookup.matchRange);
      if (match === 'out-of-range') continue;
      const severity = modulateSeverity(adv.severity, entry.position);
      const ref = adv.references[0] ?? '';
      findings.push({
        ruleId: 'supply-chain.osv-known-vulnerability',
        threatIds: ['T6'],
        severity,
        ecosystem: entry.ecosystem,
        packageName: entry.name,
        version: entry.version,
        position: entry.position,
        advisoryId: adv.id,
        advisoryUrl: ref,
        summary: adv.summary,
        confidence: match === 'in-range' ? 'in-range' : 'version-unknown',
        byteOffset: 0,
      });
    }
  }

  // Deterministic order: by advisory id, then package name, then
  // version. Order parity helps the JSON / SARIF reporters produce
  // diff-stable output across runs.
  const sorted = [...findings].sort((a, b) => {
    if (a.advisoryId !== b.advisoryId) return a.advisoryId.localeCompare(b.advisoryId);
    if (a.packageName !== b.packageName) return a.packageName.localeCompare(b.packageName);
    return a.version.localeCompare(b.version);
  });

  return { findings: sorted, parseError: null };
}

function parseLockfileByKind(
  input: ScanSupplyChainInput,
):
  | { readonly kind: 'ok'; readonly entries: ReadonlyArray<LockfileEntry> }
  | { readonly kind: 'error'; readonly message: string } {
  switch (input.lockfileKind) {
    case 'npm-lockfile':
      return parseNpmLockfile(input.lockfileContent);
    case 'poetry-lockfile':
      return parsePoetryLockfile(input.lockfileContent, input.manifestContent);
    case 'uv-lockfile':
      return parseUvLockfile(input.lockfileContent);
    case 'cargo-lockfile':
      return parseCargoLockfile(input.lockfileContent, input.manifestContent);
    default:
      return { kind: 'error', message: `not a lockfile kind: ${input.lockfileKind}` };
  }
}

function entryEcosystemMatches(entry: LockfileEcosystem, kind: FileKind): boolean {
  if (entry === 'npm') return kind === 'npm-lockfile';
  if (entry === 'PyPI') return kind === 'poetry-lockfile' || kind === 'uv-lockfile';
  if (entry === 'crates.io') return kind === 'cargo-lockfile';
  return false;
}

function evaluateRanges(
  version: string,
  ranges: ReadonlyArray<IocOsvRange>,
  match: RangeMatcher,
): 'in-range' | 'out-of-range' | 'version-unknown' {
  let sawUnknown = false;
  for (const r of ranges) {
    const result = match(version, r);
    if (result === 'in-range') return 'in-range';
    if (typeof result === 'object' && result.kind === 'unknown') sawUnknown = true;
    // 'out-of-range' on this range — keep checking the others.
  }
  return sawUnknown ? 'version-unknown' : 'out-of-range';
}
