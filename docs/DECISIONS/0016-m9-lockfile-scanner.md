# ADR 0016 — Lockfile scanning + `supply-chain.osv-known-vulnerability` findings (M9)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M9 design pass
**Threat:** T6 (compromised vulnerability feed — existing, ADR 0015 §9); no new T-entry. M9 *consumes* the IOC cache T6 protects; it does not introduce new vectors.
**Extends:** ADR 0015 (IOC sync foundation — this ADR wires the cache into `warden scan`)
**Extends:** ADR 0010 (payload-fixture markers — adds `supply-chain-fixture` family + TOML marker syntax)
**Extends:** ADR 0011 §4 (resolves the deferred `info` severity tier — M9 introduces the first rule that emits it)
**Closes:** none

---

## Context

M8 (ADR 0015) shipped the IOC sync foundation: `warden ioc sync`,
`warden ioc lookup`, `warden ioc status`, `warden ioc verify`. The
cache populates atomically; per-ecosystem JSON indexes are queryable
in O(1) by package name. What M8 explicitly deferred:

> §11 Non-goals: **No lockfile parsing in M8.** Deferred to M9.
> **No scanner findings in M8.** The cache populates and is queryable
> via `warden ioc lookup`, but no new finding category fires from
> `warden scan`. M9 wires this up alongside the lockfile parser.

This ADR specifies that wiring. M9's mission: when a project contains
a lockfile declaring `event-stream@3.3.6`, `warden scan` produces a
`supply-chain.osv-known-vulnerability` finding citing
`GHSA-mh6f-8j2x-4483`, exit 1.

The scope is deliberately narrow — three ecosystems, no auto-fix, no
SBOM — because each lockfile is its own grammar with its own edge
cases, and the version-range matcher needs per-ecosystem semantics.
Bundling more would dilute quality (same posture the M8 ADR took on
§5: "ship the foundation; build on it").

---

## Decision

### 1. Lockfile coverage — three ecosystems, opinionated subset

| Ecosystem | Lockfile | Why this one | Why not the alternatives |
|-----------|----------|--------------|---------------------------|
| npm       | `package-lock.json` v2/v3 | npm 7+ default since 2020; stable `packages` map shape; self-describing direct vs transitive via root `packages[""]` entry. | v1 deferred — legacy `dependencies` tree shape; rare in 2026 repos. `yarn.lock` v1 deferred — bespoke text format, dedicated parser. `pnpm-lock.yaml` deferred — YAML + virtual store, separate design pass. `bun.lockb` deferred indefinitely — binary, unstable format. |
| PyPI      | `poetry.lock` + `uv.lock` | The two dominant 2026 lockfile shapes. Both TOML. Together cover most modern Python projects. | `requirements.txt` deferred — not a real lockfile (accepts ranges like `>=2.28`); a pinned-only subset would mislead users into thinking ranged entries were checked. `Pipfile.lock` deferred — pipenv usage declining; revisit if fixture demand surfaces. `pip-tools *.lock` deferred — non-standard shape per project. |
| Cargo     | `Cargo.lock` | Workspace-resolved; TOML `[[package]]` blocks list exact versions; `dependencies` per package gives transitive structure. Self-describing for direct vs transitive when paired with workspace root (or treated all-direct when standalone). | No alternative — `Cargo.lock` is the canonical Rust lockfile. |

Detection happens via path-based matching in
`packages/core/src/detect-format.ts`, extending the existing
`FileKind` union with three new kinds:
`npm-lockfile`, `poetry-lockfile`, `uv-lockfile`, `cargo-lockfile`.
Path patterns: `package-lock.json` (any depth), `poetry.lock`,
`uv.lock`, `Cargo.lock`. `.gitignore` is respected as always —
lockfiles under `node_modules/`, `.venv/`, `target/`, or any other
ignored path are excluded by the M2 walker without special-case
logic.

### 2. Version semantics — extend M8's `version.ts`, no new dep

ADR 0015 §12.3 committed to JSON over SQLite "no new external dep"
discipline. M9 holds the same line for version parsing:

- **npm + Cargo** reuse `parseVersion` and `matchOsvRange` from
  `packages/ioc/src/version.ts`. Both ecosystems use SemVer 2.0.0
  for *resolved* versions (which is what lockfiles carry). The
  caret/tilde/pre-release-priority differences between npm and
  Cargo apply to *manifest* ranges, not lockfile pins — M9 reads
  pins, not ranges, so the existing matcher is sufficient.
- **PyPI** requires PEP 440, which SemVer cannot represent. New
  module `packages/ioc/src/version-pep440.ts` with
  `parsePep440Version` + `comparePep440Versions`. Covers: release
  segments (`N(.N)*`), pre-release (`aN`, `bN`, `rcN`,
  `.preN`), post-release (`.postN`), dev-release (`.devN`),
  optional `v` prefix.
- **PEP 440 deferred features:** epoch segments (`N!N`) and local
  versions (`+ubuntu1`). Versions containing either return
  `version-unknown` from the matcher (same fallback posture M8
  established for GIT range types — confidently-wrong is worse than
  honest-unknown).

Lines of code estimate: ~120 for PEP 440 parser + ~40 lines of
adapter code in the lockfile readers to route to the right matcher
by ecosystem. Vetting a single npm dep that covered all three would
be more work than writing this.

The matcher's `MatchResult` union (in-range / out-of-range / unknown)
is the contract `supply-chain.osv-known-vulnerability` consumes:
in-range → confident finding; unknown → finding with a "verify
manually" note; out-of-range → no finding.

### 3. Direct vs transitive detection — per-lockfile-shape

The severity tiering in §4 depends on knowing whether a vulnerable
package is a direct dependency (the project asked for it) or a
transitive dependency (some dependency-of-a-dependency pulled it in).
Each lockfile gives this information differently.

| Lockfile | How direct is determined | Fallback when uncertain |
|----------|--------------------------|-------------------------|
| `package-lock.json` v2/v3 | Root entry `packages[""]` lists `dependencies` and `devDependencies`. A package whose name appears in either set is **direct**; everything else under `packages/<name>` or `packages/<path>` is **transitive**. | Lockfile is self-describing; no fallback needed. |
| `uv.lock` | The project's own `[[package]]` entry (identified by `source.virtual = "."` or matching the project name) lists `dependencies`. Names listed are **direct**; others are **transitive**. | Lockfile is self-describing in v0.4+; older `uv.lock` files without the virtual entry treat all as **direct**. |
| `poetry.lock` | Poetry does not flag direct packages in the lockfile itself. Read `pyproject.toml#[tool.poetry.dependencies]` and `#[tool.poetry.group.*.dependencies]` and intersect names. | **`pyproject.toml` absent or unreadable → treat all as direct.** Better-safe-than-silent. Logged on stderr: `warden: pyproject.toml not found near poetry.lock; treating all dependencies as direct`. |
| `Cargo.lock` | Workspace root identifier comes from `Cargo.toml#[package].name` (or `#[workspace]` for workspaces). The matching `[[package]]` entry in `Cargo.lock` lists `dependencies` — names there are **direct**. | **`Cargo.toml` absent or unreadable → treat all as direct.** Same posture as poetry. |

The manifest reads (`pyproject.toml`, `Cargo.toml`) are pure-string
TOML parses — no resolution, no network, no transitive walk. The
files are read once per lockfile, cached in memory for the scan, and
discarded.

### 4. Severity model — direct vs transitive, with new `info` tier

Base severity comes from OSV per ADR 0015 §5. M9 modulates by
position in the dependency graph:

| Position    | OSV CRITICAL/HIGH | OSV MODERATE | OSV LOW |
|-------------|-------------------|--------------|---------|
| Direct      | **high**          | **medium**   | **low** |
| Transitive  | **medium**        | **low**      | **info**|

OSV `unset / UNKNOWN` → treated as MODERATE (ADR 0015 §5).

**`info` is a new severity tier** introduced by this ADR. ADR 0011
§4 had noted: `info deferred until a rule needs it`. M9 is the rule
that needs it. Behavior:

- **Default scan output:** `info` findings are NOT shown in per-file
  listings; summary line gains an `info: N` bucket alongside high /
  medium / low.
- **`--verbose`:** `info` findings shown like any other finding.
- **Exit code:** `info` does NOT contribute to the exit-1 gate by
  default. `findingCount` (the gating count) is unchanged in
  semantics: high + medium + low.
- **`--strict`:** `info` escalates — any `info` finding gates exit
  to 1. Same posture as `--strict` does for trust orphan entries
  (M5 / ADR 0012).

Rationale for the `info` tier specifically for transitive LOW:
without it, "transitive LOW gets dropped to nothing" would be
ambiguous (silently suppress? show as low? show but not gate?).
Naming the tier resolves the ambiguity and keeps the finding visible
under `--verbose` for users who want full audit trails.

**Schema impact:** `ScanReport` gains `infoCount: number` (additive
to JSON v2 — no v3 bump per non-goal). The `severity` field on
findings becomes `'high' | 'medium' | 'low' | 'info'` system-wide.
Other detectors (unicode, prompt-injection, MCP, trust) continue to
emit only high/medium/low; the `info` value is reserved for
`supply-chain.*` rules in M9 and any future rule that needs it.

### 5. Finding category, cache states, and exit semantics

**Category:** `supply-chain.osv-known-vulnerability` (per ADR 0015 §5,
confirmed).

**Finding shape** (`packages/core/src/findings.ts` gains
`SupplyChainFinding`):

```ts
export type SupplyChainSeverity = 'high' | 'medium' | 'low' | 'info';

export type SupplyChainFinding = {
  readonly ruleId: 'supply-chain.osv-known-vulnerability';
  readonly threatIds: ReadonlyArray<string>; // ['T6']
  readonly severity: SupplyChainSeverity;
  readonly ecosystem: 'npm' | 'PyPI' | 'crates.io';
  readonly packageName: string;
  readonly version: string;
  readonly position: 'direct' | 'transitive';
  readonly advisoryId: string;         // e.g. 'GHSA-mh6f-8j2x-4483'
  readonly advisoryUrl: string;        // references[0]
  readonly summary: string;            // first 200 chars
  readonly confidence: 'in-range' | 'version-unknown';
  // 0 for supply-chain findings: the offset would be the byte
  // location of the version string inside the lockfile, which
  // requires a lockfile tokenizer for citation accuracy. Deferred.
  readonly byteOffset: 0;
};
```

**Cache state behavior:**

| Cache state                              | Default mode                                | `--strict` mode                              |
|------------------------------------------|----------------------------------------------|----------------------------------------------|
| Absent (`~/.warden/ioc/manifest.json` missing) | Skip IOC checks; emit stderr once: `warden: ioc cache not initialized; run 'warden ioc sync' to enable supply-chain checks`. Scan continues offline-pure. Exit code unaffected. | **Exit 2** (config error) before scanner runs. Stderr: `warden: --strict requires ioc cache; run 'warden ioc sync'`. CI integrations must wire sync before strict scan. |
| Present, fresh (<7d per `staleness_warning_hours`) | Run IOC checks normally. | Run IOC checks normally. |
| Present, stale (≥7d)                     | Run IOC checks; emit stderr warning per ADR 0015 §3: `warning: ioc cache is N days old; run 'warden ioc sync' to refresh`. | Run IOC checks; same warning. (Stale-as-error under strict deferred — see ISSUES #012 if it surfaces.) |

Hard invariants preserved:

- `warden scan` **never** calls the network (ADR 0011 §2; ADR 0015
  §7). Cache reads only. Air-gapped CI behaves correctly.
- Failed cache reads (corrupt JSON, partial write, permission error)
  produce stderr `warden: ioc cache unreadable: <path>: <reason>` and
  skip IOC checks. Default exits 0 (degraded but functional); strict
  exits 2 (config error).

### 6. Cross-category collateral preserved

ARCHITECTURE.md §7 holds: every file passes through every detector.
Lockfiles are no exception. Concretely:

- A `package-lock.json` whose advisory metadata embedded in
  `_warden`-free description fields contains override-prior-context
  phrasing fires `scanPromptInjection` on the raw JSON.
- A `poetry.lock` with invisible Unicode in a description string
  fires `scanUnicode`.
- Cargo.lock is rarely textual (no description fields), but if a
  future Cargo.lock format adds them, the same collateral coverage
  applies automatically — no code change.

A `supply-chain-fixture` marker (see §7) suppresses **only**
supply-chain findings. A prompt-injection payload planted inside a
lockfile description field still fires its prompt-injection rule.
This is the same cross-category-poisoning property M3.1 codified.

### 7. Marker syntax — `supply-chain-fixture` family + TOML extension

**New marker family** in `packages/core/src/marker.ts`:

```ts
'supply-chain-fixture': ['supply-chain'],
```

The `'supply-chain'` finding category joins the existing union:
`'unicode' | 'prompt-injection' | 'mcp' | 'supply-chain'`.

**Path restriction** (same shape as `trapdoor-unicode` /
`prompt-injection-pattern` got in ADR 0010):

```ts
'supply-chain-fixture': {
  regex: /^tests\/fixtures\/supply-chain\//,
  display: 'tests/fixtures/supply-chain/**',
},
```

A `supply-chain-fixture` marker outside that directory is a hard
parse error (exit 2), same posture as broad-scope families.

**TOML marker syntax (new):** ADR 0011 §6 established JSON marker
syntax via a top-level `_warden` string property. Cargo.lock and
the PyPI lockfiles are TOML, which has no native equivalent. M9
introduces:

```toml
_warden = "payload-fixture supply-chain-fixture -- known event-stream advisory for parser fixture"

[[package]]
name = "event-stream"
version = "3.3.6"
# ...
```

Rules (mirroring the JSON marker rules from ADR 0011 §6):

- The `_warden` key MUST be the first non-comment, non-whitespace
  line of the file. Markers later in the document are ignored. This
  prevents an attacker who can append to a lockfile (e.g. malicious
  PR adding a transitive dep) from also planting a suppression.
- Grammar from the sentinel onwards is identical to ADR 0010 §2.
- Unknown keys at root: TOML naturally permits them, so `_warden`
  coexists with `[[package]]` blocks without parser changes in the
  consumer (Cargo, poetry, uv all tolerate unknown top-level keys).
- Empty `_warden` value or malformed grammar → exit 2 with file:line
  citation, same as JSON / markdown markers.

**Why top-level string key over comment:** TOML comments are `#` (not
`//` like JSON's pseudo-comment convention) and the marker parser
would need to learn TOML-specific comment grammar. A top-level key
is uniform across JSON and TOML — same parser concept (find the
declared marker field at the file's top), different syntax sugar.

### 8. Subcommand surface — no new commands

M9 does NOT add a new `warden ...` subcommand. The work is entirely
in `warden scan`:

- `packages/core/src/scan-supply-chain.ts` — new pure function:
  `scanSupplyChain(lockfileBytes, ecosystem, manifestBytes?, index) → SupplyChainFinding[]`.
- `packages/core/src/scan-path.ts` — extended to call
  `scanSupplyChain` per detected lockfile kind, after loading the
  ecosystem's IOC index (if cache exists).
- `packages/ioc/src/index-store.ts` (existing) — gains the read API
  M9 consumes. No write changes.
- `packages/cli/src/index.ts` — extended to report `info` count in
  summary, gate exit-1 on `info` under `--strict`, emit
  cache-state stderr messages.

`warden ioc lookup` (existing, M8) keeps its current behavior — it
remains the debug surface; M9's scanner wiring is a separate code
path with its own integration tests.

### 9. Non-goals (explicit)

- ❌ **Yarn v1, pnpm-lock.yaml, bun.lockb.** Deferred to M9.1+ or
  later. Each is its own parser; bundling dilutes quality.
- ❌ **`requirements.txt`, `Pipfile.lock`, pip-tools `*.lock`.**
  Deferred. `requirements.txt` is not a real lockfile.
- ❌ **Second IOC source** (Socket, GHSA-direct, MalwareBazaar). M9
  stays OSV-only per ADR 0015 §1.
- ❌ **Auto-fix / remediation suggestions.** Warden reports; users
  decide. No `npm audit fix` equivalent.
- ❌ **SBOM / aibom generation.** Separate Layer 3 work (post-M9 list
  in ROADMAP).
- ❌ **Direct manifest scanning** (`package.json`, `pyproject.toml`,
  `Cargo.toml` for declared *ranges*). M9 reads manifests only to
  enumerate root-level dep *names* for direct/transitive
  classification — never as a source of versions to check. Versions
  always come from lockfiles (resolved pins).
- ❌ **PEP 440 epoch (`N!N`) and local versions (`+local`).** Return
  `version-unknown`; advisory still emits with that confidence flag.
- ❌ **Cargo `git` and `path` deps.** Return `version-unknown` —
  these have no semver-comparable identity.
- ❌ **Dev vs prod severity tiering.** Modulator uses only direct vs
  transitive. Dev/prod distinction deferred (ISSUES #010); revisit
  if M9 produces too much noise on dev deps.
- ❌ **Auto-sync on first scan** (lazy fetch after N days). ADR 0015
  §3 rejected this; M9 holds the line.
- ❌ **JSON v3 schema bump.** `infoCount` field + `severity: 'info'`
  enum value are additive to v2. SARIF output already supports
  arbitrary severity levels via `result.level`.
- ❌ **Marker pattern-aware suppression inside lockfiles.** A
  `supply-chain-fixture` marker suppresses all supply-chain findings
  in the file's declared scope (ADR 0010 grammar). Deferred per
  ISSUES #002.
- ❌ **Per-finding suppression citation** (which advisory was
  suppressed and why). Verbose output lists suppressed findings under
  the marker; that's the M3.1 contract and M9 honors it without
  extending.

### 10. Performance budget

Per-scan cost added by M9, measured against a lockfile with N
entries:

| Lockfile size | Lookups | Target cost added |
|---------------|---------|-------------------|
| 500 entries   | 500     | <100ms            |
| 2000 entries  | 2000    | <500ms            |
| 5000 entries  | 5000    | <1500ms           |

Hard cap: **integration test fails the build if a 2000-entry
lockfile scan adds >1s** to baseline. The per-ecosystem JSON index
loads once per scan (not per file); per-entry cost is parseVersion
(~µs) + matchOsvRange (~µs over typical 2-4 events). Index load
dominates first-lookup latency (~10-50ms for a ~5MB npm index);
subsequent lookups are O(1) hashmap reads.

Performance regression test lives in `packages/core/tests/perf/`
under a `--perf` flag (excluded from default `bun test` to avoid
flakiness on shared CI runners; runnable manually and from a
nightly job).

### 11. Threat model — no T-update needed

M9 consumes the IOC cache that T6 (ADR 0015 §9) protects. The threat
surface is unchanged: a compromised OSV feed causes
false-negatives (missed advisories) or false-positives (fake
advisories) at scan time, with the same blast radius and the same
mitigations (TLS + host pinning + SHA-256 logging + diff-on-sync +
`warden ioc verify`).

What M9 *doesn't* change about T6:

- No new sources (still OSV-only).
- No new persistence (cache layout unchanged).
- No new network surface (scan stays offline-pure).
- No new trust boundary.

M9 *does* increase the *cost* of a T6 compromise: a false advisory
now fires a `warden scan` finding (was previously only visible via
`warden ioc lookup`). This shifts the user-facing blast from "users
who specifically queried the malicious advisory" to "every user who
scans a project using the targeted package." THREAT_MODEL.md gets a
short note in T6 §"Blast radius" reflecting the shift; no new T-ID.

### 12. Resolved decisions (at acceptance)

The four open questions surfaced during planning were resolved by
the user at acceptance time. Recorded here so future readers see the
decision and its reason in one place.

1. **PyPI lockfiles = `poetry.lock` + `uv.lock`.** Covers the two
   dominant 2026 Python lockfile shapes. `requirements.txt` rejected
   (not a real lockfile — accepts ranges); other shapes deferred.
   Reason: opinionated narrow scope ships ahead of mass coverage.

2. **Severity tiering = direct vs transitive only (no dev/prod).**
   Lockfile-shape-only inputs to severity modulation — keeps the
   parser surface minimal (no dev-dependency walk through manifest).
   Reason: dev/prod adds parser complexity without proven signal;
   ISSUES #010 tracks the revisit if M9 produces dev-noise.

3. **Cache absent under `--strict` = exit 2** (config error before
   scan runs). CI integrations must wire `warden ioc sync` before
   `warden scan --strict`. Default mode (no `--strict`) keeps the
   skip-with-stderr-warning behavior. Reason: strict mode's contract
   is "no degraded state tolerated" — coherent with M5 trust
   `--strict` posture in ADR 0012.

4. **TOML marker syntax = top-level `_warden` string key.** Mirrors
   ADR 0011 §6 JSON syntax. Uniform "find the declared marker field
   at file top" concept across JSON and TOML. Reason: comment-based
   markers would require TOML-specific (`#`) comment parsing in
   `marker.ts`; key-based markers reuse the same field-discovery
   logic across formats.

5. **Acceptance criterion fixture = `event-stream@3.3.6`** (not
   `left-pad`). Real npm supply-chain attack, real
   `GHSA-mh6f-8j2x-4483`, canonical 2018 maintainer-handover →
   Copay-wallet-credential-theft incident. Reason: left-pad has no
   CVE (the 2016 incident was unpublish-drama, not compromise);
   fixtures must reference real advisories so the test is
   representative, not synthetic.

6. **Transitive LOW = `info` (new severity tier).** Resolves the
   ambiguity in §4's matrix (transitive LOW one tier below LOW =
   what?). Visible under `--verbose`, doesn't gate exit-1 by default,
   gates under `--strict`. Resolves the deferred-`info` note from
   ADR 0011 §4. Reason: naming the tier preserves audit-trail
   visibility without polluting the default exit gate.

---

## Consequences

Positive:

- Supply-chain awareness reaches `warden scan`. The cache built in
  M8 starts producing findings; the loop from sync → scan → finding
  closes.
- Direct/transitive modulation reduces noise on long transitive
  trees while keeping direct-dep CVEs loud.
- `--strict` gains a meaningful IOC contract: CI pipelines can fail
  closed on missing cache.
- The `info` severity tier ships with a real consumer, resolving the
  ADR 0011 §4 placeholder.
- TOML marker syntax establishes the third format-family marker
  contract (after markdown/comment per ADR 0010 and JSON per ADR
  0011 §6), so future TOML-based context files (e.g. `.warden.toml`
  itself if ever needed as fixture) have a precedent.
- Zero new external deps. Dep count for `packages/core` stays under
  the CLAUDE.md target (under 10).

Negative:

- `info` is a system-wide severity addition. Every reporter
  (terminal, JSON, SARIF) gains an `info` bucket. Risk: future
  detectors over-use `info` to avoid hard severity calls. Mitigation:
  ADR 0016 §4 names `info`'s intended use ("transitive LOW supply
  chain"); future rules emitting `info` need explicit ADR
  justification.
- Direct vs transitive logic depends on manifest reads
  (`pyproject.toml`, `Cargo.toml`) for poetry/cargo. Manifest absent
  → treat all as direct (louder); manifest present-but-wrong (rare
  but possible: workspace member misconfigured) → mis-classification.
  Acceptable failure mode — louder beats silent.
- Larger lockfiles (5000+ entries) push past the 1s budget on
  underprovisioned CI runners. Documented; users who hit the cap can
  scope scan by directory or by lockfile path.
- The `info` tier in `--strict` mode escalates transitive LOW
  advisories to a gate. CI pipelines on dependency-heavy projects
  may need an allow-list mechanism — currently the only escape is
  the marker family (which suppresses *all* supply-chain findings
  in scope, not just `info`). Per-advisory allow-list deferred to
  ISSUES #013 if demand surfaces.

---

## Sources

- OSV Schema specification —
  `https://ossf.github.io/osv-schema/` (verified 2026-05-25). Source
  of advisory shape consumed by `supply-chain.osv-known-vulnerability`.
- npm `package-lock.json` format —
  `https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json`
  (verified 2026-05-25). Source of the `packages[""]` root-entry
  contract for direct-vs-transitive detection.
- PEP 440 — Version Identification and Dependency Specification —
  `https://peps.python.org/pep-0440/` (verified 2026-05-25). Source
  of the parser grammar implemented in `version-pep440.ts`.
- Cargo Book — The Lockfile —
  `https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html`
  (verified 2026-05-25). Source of the `[[package]]` shape and the
  workspace-root identification rule.
- uv lockfile format —
  `https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile`
  (verified 2026-05-25). Source of the project-virtual entry
  convention for direct-vs-transitive detection.
- Poetry lockfile —
  `https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock`
  (verified 2026-05-25). Confirms poetry.lock does not flag direct
  packages — pyproject.toml read is mandatory.
- GHSA-mh6f-8j2x-4483 — `event-stream` malicious dependency
  (`flatmap-stream`) targeting Copay wallet credentials —
  `https://github.com/advisories/GHSA-mh6f-8j2x-4483` (verified
  2026-05-25). Source of the M9 acceptance criterion fixture.
- ADR 0015 — IOC sync foundation; §5 severity mapping, §7 network
  isolation, §9 T6 threat model, §12 resolved decisions.
- ADR 0011 §2 — no-network-on-hot-path invariant (preserved
  unchanged by M9).
- ADR 0011 §4 — deferred `info` severity tier (resolved by M9 §4).
- ADR 0011 §6 — JSON marker syntax (extended to TOML by M9 §7).
- ADR 0010 — payload-fixture marker convention (extended with
  `supply-chain-fixture` family in M9 §7).
- ADR 0012 — trust signing `--strict` semantics (precedent for M9's
  `--strict` cache-absent contract in §5).
- OWASP A06:2021 — Vulnerable and Outdated Components — primary
  citation for the user-facing threat M9 detects.
