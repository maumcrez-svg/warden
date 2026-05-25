# ADR 0015 — `warden ioc sync` (M8)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M8 design pass
**Threat:** new T6 (compromised vulnerability feed); existing T1–T5 unchanged
**Extends:** `docs/ARCHITECTURE.md` §2 (new `packages/ioc` boundary), §4 (hot-path policy — codified here)
**Extends:** ADR 0011 §2 (no-network-on-hot-path invariant — preserved by isolating network to `warden ioc sync`)
**Closes:** ISSUES #005 (introduces the `.warden.toml` schema that #005 was blocked on, minimally)
**Threat-model update:** `docs/THREAT_MODEL.md` gains §T6 ("Compromised IOC feed") — drafted in §9 below

---

## Context

M1–M7 covered the AT-REST detection surface (Unicode, prompt injection,
MCP configs, trust signing) plus the RUNTIME tool-call boundary
(Claude + Cursor hook adapters). The remaining structural gap is
**supply-chain awareness**: when a `package.json` (or `requirements.txt`,
`go.sum`, `Cargo.toml`, …) declares `left-pad@1.3.0`, Warden today has
no opinion about whether `1.3.0` is a known-vulnerable version, an
actively-malicious release, or a typosquat.

The remediating data is public — OSV.dev, GitHub Security Advisories,
Socket's published research, MalwareBazaar — but it lives upstream and
changes daily. Bringing it into the scanner means crossing two
boundaries Warden has so far refused to cross:

1. **Network.** ADR 0011 §2 codified "no network on the hot path."
   Pulling IOC data means *some* part of Warden must call out.
2. **Persistence.** Today's scanner is stateless across runs (Trust
   manifest excepted; that's user-curated, not synced). An IOC index
   is a cache the tool maintains on the user's machine.

The M8 mission is to introduce both surfaces in a way that does not
regress the existing invariants. The strategy is **strict isolation**:
a new `packages/ioc` package owns all network code and all cache
state; `warden scan` remains offline-pure; the network call is a
separate, explicit subcommand the user runs when they want it.

The new threat ID is **T6 — Compromised vulnerability feed** (added to
THREAT_MODEL.md in the same commit that lands M8 implementation). See
§9.

---

## Decision

### 1. Anchor feed: OSV.dev (single source for M8)

For M8, the single supported source is OSV.dev. Rationale:

- **Coverage breadth.** OSV aggregates 20+ ecosystems (npm, PyPI, Go,
  Maven, RubyGems, NuGet, crates.io, Packagist, Linux distros,
  Hex/Erlang, Pub/Dart, Conan/C++, …). The major OSS package
  ecosystems are all here, and GHSA records flow into OSV
  automatically.
- **Bulk download.** OSV publishes ZIPs at
  `https://storage.googleapis.com/osv-vulnerabilities/all.zip` (full)
  and `https://storage.googleapis.com/osv-vulnerabilities/<ecosystem>/all.zip`
  (per ecosystem), verified 2026-05-25 at
  `https://google.github.io/osv.dev/data/`. Per-ecosystem downloads
  let M8 ship a "sync only the npm advisories" path for users who
  don't need the full ~200MB.
- **Schema.** OSV Schema is well-defined and versioned
  (`https://ossf.github.io/osv-schema/`), so the parser has a stable
  contract.
- **License.** Data is CC-BY 4.0 — redistribution and local caching
  are unambiguously permitted.
- **No auth, no rate limits on bulk.** Public GCS bucket; no API key,
  no throttling on whole-bucket downloads.

Sources explicitly **not** included in M8, with reason:

| Candidate                  | Status in M8 | Reason                                                                                                                                              |
|----------------------------|--------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| GitHub Security Advisories | Skip         | Already mirrored into OSV via the `GHSA-*` ID space — adding GHSA directly would be redundant and would force cross-source dedup logic in M8.        |
| Socket public feeds        | Defer        | No documented free bulk-download surface (free read-only API is per-package lookup, rate-limited). Adding it requires a different fetch strategy — a separate ADR when M9 reopens the question. |
| MalwareBazaar              | Skip         | File-hash IOCs, not package IOCs. Different use case (post-compromise forensics, not pre-install screening). Out of Warden's mission scope.        |
| PyPI advisory DB           | In OSV       | Flows into OSV under the `PYSEC-*` ID space.                                                                                                         |
| RustSec                    | In OSV       | Flows into OSV under the `RUSTSEC-*` ID space.                                                                                                       |
| Go vuln DB                 | In OSV       | Flows into OSV under the `GO-*` ID space.                                                                                                            |

The single-source posture is intentionally conservative. Adding a
second source means designing the merge / consensus / contradiction-
resolution logic (does an advisory in source A AND not source B mean
"unverified" or "high-confidence"?), and that design is its own ADR.
M9+ work, not M8.

### 2. Local schema: per-ecosystem JSON indexes (no SQLite, no DB)

After sync, the cache layout is:

```
~/.warden/ioc/
├── manifest.json                       # global state: last-sync time, sources, ecosystems present
├── osv/
│   ├── npm.json                        # index keyed by package name
│   ├── PyPI.json
│   ├── Go.json
│   ├── crates.io.json
│   └── …                                # one file per ecosystem the user synced
└── history/
    ├── 2026-05-25T12-00-00Z.json       # diff log; last N retained (default 10)
    └── …
```

`manifest.json`:

```json
{
  "schema": "warden-ioc/v1",
  "synced_at": "2026-05-25T12:00:00Z",
  "warden_version": "0.0.0-m8",
  "sources": [
    {
      "name": "osv",
      "url": "https://storage.googleapis.com/osv-vulnerabilities",
      "synced_at": "2026-05-25T12:00:00Z",
      "ecosystems": ["npm", "PyPI", "Go"],
      "advisory_count": 8421,
      "zip_sha256": "ab12…",
      "zip_size_bytes": 12345678
    }
  ]
}
```

Per-ecosystem index `osv/npm.json`:

```json
{
  "schema": "warden-ioc/v1",
  "ecosystem": "npm",
  "source": "osv",
  "synced_at": "2026-05-25T12:00:00Z",
  "advisory_count": 3127,
  "packages": {
    "left-pad": [
      {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "severity": "high",
        "summary": "Description (first 200 chars).",
        "ranges": [{ "introduced": "0.0.0", "fixed": "1.1.1" }],
        "references": ["https://github.com/.../advisories/GHSA-xxxx"]
      }
    ]
  }
}
```

Choices justified:

- **JSON over SQLite.** SQLite would give O(log N) indexed lookups
  and a single-file footprint, but it adds either `better-sqlite3`
  (a native C++ dep, painful to vet) or `bun:sqlite` (Bun-only,
  fine but couples the cache format to runtime choice). Per-ecosystem
  JSON is O(1) to load the ecosystem the scan needs, and lookups
  are O(1) on the package-name key. Dep count stays the same as M7.
- **JSON over TOML.** TOML is excellent for hand-edited config files;
  for machine-written 50MB datasets it's the wrong tool (verbose,
  no streaming parser, sub-second parse only with extra work).
  Indexes are machine-generated, not hand-edited.
- **Per-ecosystem, not single file.** A single 50MB index loaded for
  every scan would waste RAM. Most projects target one ecosystem;
  loading only `npm.json` keeps the working set under 5MB.
- **Pruned fields.** We do not retain the full OSV record (every
  field documented in the OSV schema). We keep `id`, `severity`,
  `summary[:200]`, `ranges`, `references[:1]` — enough to produce a
  scan finding with a citation, nothing more. Users who need the
  full record can `curl https://api.osv.dev/v1/vulns/<id>` themselves.

Volume estimate (sanity check against OSV's 2026 size):

| Ecosystem | Advisories | Pruned JSON size |
|-----------|------------|-------------------|
| npm       | ~3,000     | ~5 MB            |
| PyPI      | ~5,000     | ~8 MB            |
| Go        | ~1,500     | ~3 MB            |
| RubyGems  | ~700       | ~1.2 MB          |
| Maven     | ~3,200     | ~6 MB            |
| crates.io | ~800       | ~1.3 MB          |
| (full set)| ~30,000    | ~50 MB           |

`history/` retention is 10 manifests by default (configurable), so the
worst-case cache footprint is ~100 MB. Acceptable for a developer
machine; absurd to commit to a repo (hence §4's user-local default).

### 3. Sync strategy: manual only (`warden ioc sync`)

Three patterns were considered:

| Pattern                              | Verdict in M8 | Reason                                                                                                                                              |
|--------------------------------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| Lazy on first scan after N hours     | **Reject**    | Violates ADR 0011 §2: the scanner would do network I/O. Users would not expect `warden scan` to phone home; making it conditional makes the behavior less predictable, not more. |
| Background daily cron / systemd timer| **Reject**    | Warden does not install schedulers. Setting up a daemon to keep IOC data fresh is the user's call; we provide the command, they wire the schedule.   |
| Manual only via `warden ioc sync`    | **Accept**    | One subcommand, one network surface. `warden scan` stays offline-pure. The user controls when (and whether) the sync happens.                        |

The scanner reports staleness as a warning, never as a hard error:

```
warden scan: 58 files scanned, 0 with findings.
  clean — no threats detected.
summary: 0 finding(s) — 0 high, 0 medium, 0 low
warning: ioc cache is 14 days old; run `warden ioc sync` to refresh
```

The warning fires only when the IOC cache exists and is older than
the configured TTL (default 7 days). No cache = no warning (Warden
without IOC features works exactly as it did in M7).

Staleness is reported, never enforced. Hard-failing a scan because
the IOC cache is two weeks old would punish users who deliberately
work offline — the opposite of what an offline-pure scanner should
do.

### 4. Cache location: `~/.warden/ioc/` (user-local), XDG-aware

Default: `~/.warden/ioc/`. Rationale:

- **Project-local `.warden/ioc/` rejected.** Either it gets committed
  (50 MB blob in git, churn on every sync) or it's `.gitignore`d
  (every developer re-syncs independently — pointless duplication
  and forced first-scan network call when CI cold-starts).
- **User-local is the natural fit.** One sync per machine, shared
  across all projects.
- **XDG override.** If `$XDG_CACHE_HOME` is set, use
  `$XDG_CACHE_HOME/warden/ioc/` instead. Standard hygiene on Linux.
- **Project override via `.warden.toml`.** Org repos that pin a
  curated subset of advisories can set
  `ioc.cache_path = ".warden/ioc"` and commit a pruned cache. Fully
  opt-in — the default behavior is unchanged.

Staleness check: the scanner reads `~/.warden/ioc/manifest.json`,
compares `synced_at` to current time, emits a stderr warning if older
than TTL. No network I/O, no enforcement.

### 5. Scanner integration: M8 is sync-only — findings deferred to M9 (default recommendation; open question)

This is the largest scope decision in M8. Two readings:

- **(A) Narrow M8.** Ship `warden ioc sync`, `warden ioc status`,
  `warden ioc lookup`, `warden ioc verify`. No scanner change. The
  cache populates but does not yet fire findings. M9 adds lockfile
  parsing and wires the IOC index into `scanPath`.
- **(B) Broad M8.** Sync + lockfile parser + scanner integration in
  one milestone.

**Recommendation: narrow (A).** Reasons:

- Lockfile parsing is its own design space (which lockfiles —
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` v1/v2,
  `requirements.txt` with hashes, `go.sum`, `Cargo.lock`,
  `Gemfile.lock`, `composer.lock`? what version-range semantics?
  how to handle dev dependencies? transitive vs direct?). Each
  lockfile is a separate parser with its own edge cases.
- The version-matching logic ("does package X@1.4.2 fall in advisory
  range `>= 1.0.0 <1.5.0`?") needs semver-compatible per-ecosystem
  comparators. npm semver, PyPI PEP 440, Go pseudo-versions, Cargo
  caret/tilde — five distinct grammars.
- Findings severity, suppression, allowlist integration with M3.1
  marker semantics, SARIF output format extension, JSON v2 → v3 bump
  decision — every one of these is a non-trivial choice that
  deserves its own M9 thinking pass.
- Bundling all of it into M8 produces a milestone that either drags
  for weeks or ships shallow versions of every sub-decision.

M8 ships the *foundation* — sync works, cache is queryable, threats
to the foundation (T6) are named. M9 builds on it.

`warden ioc lookup <ecosystem>:<package>@<version>` ships in M8 as a
debug/validation tool, with structure:

```bash
$ warden ioc lookup npm:left-pad@1.0.0
GHSA-xxxx-yyyy-zzzz  high  Description first line...
  range: >=0.0.0 <1.1.1
  ref:   https://github.com/.../advisories/GHSA-xxxx

$ warden ioc lookup --json npm:left-pad@1.0.0
{ "schema": "warden/ioc-lookup/v1", "matches": [ ... ] }
```

This is enough to prove the index works end-to-end, lets adventurous
users wire it into their own CI ahead of M9, and gives M9 a stable
read API to build on.

**Severity mapping (when M9 fires findings):**

| OSV `database_specific.severity` (or CVSS-derived) | Warden severity |
|----------------------------------------------------|-----------------|
| `CRITICAL`                                         | high            |
| `HIGH`                                             | high            |
| `MODERATE` / `MEDIUM`                              | medium          |
| `LOW`                                              | low             |
| unset / `UNKNOWN`                                  | medium          |

Documented in M8 for the lookup output; consumed by M9 for findings.

Finding category (M9): `supply-chain.osv-known-vulnerability`.
Citation: the OSV advisory ID + the URL in `references[0]`. No
synthesis, no embellishment — same posture as the M3 prompt-injection
rule pack ("each rule has a source URL and date verified").

### 6. `.warden.toml` schema (minimal — covers IOC, nothing more)

This is the first project-level Warden config file. The schema is
intentionally small. Growing it for unrelated features is a separate
decision per added section.

Location: `<project-root>/.warden.toml`. Optional; absent file =
defaults. When `[ioc]` section exists, the values listed below
override the defaults.

```toml
schema = "v1"

[ioc]
# Optional. Overrides ~/.warden/ioc/ for this project.
cache_path = "~/.warden/ioc"

# Optional. TTL in hours before scan warns about staleness. 0 disables
# the warning entirely (offline-first projects). Default: 168 (7 days).
staleness_warning_hours = 168

# Optional. Source list. M8 supports "osv" only; future ADRs add more.
# Omitting the section = all known sources enabled.
[[ioc.feeds]]
source = "osv"
# Optional. Subset of ecosystems to sync. Omit = sync all OSV ecosystems.
# Names match OSV's ecosystem identifiers (case-sensitive).
ecosystems = ["npm", "PyPI"]
```

Strictness rules (mirror manifest.toml / allow.toml conventions):

- `schema = "v1"` required as the first non-comment line. Unknown
  schemas → exit 1 with the line number; never silently downgrade.
- Unknown keys at any level → exit 1. Forward-compatibility comes
  from explicit schema bumps, not silent tolerance.
- `[ioc]` section is fully optional. A `.warden.toml` containing
  only `schema = "v1"` is valid and means "use defaults for
  everything."
- File is **not** required when IOC features are used. Defaults
  apply. The file exists for projects that need to override.

This addresses #005 (which required a `.warden.toml` to land before
transport-tier MCP rules could be made user-configurable) by
introducing the schema; the actual MCP-transport keys remain
deferred (#005's resolution path doesn't change, it just unblocks).

It does **not** address #002 — broad-scope marker file allowlist is
a different config-shape decision and would need its own section
when it lands.

### 7. Network access policy — `packages/ioc` is the only network boundary

ADR 0011 §2 said: "no network on the hot path." M8 extends that
invariant rather than weakening it:

- **`warden scan` remains offline-pure.** No network imports
  reachable from `packages/core/src/scan-*.ts`.
- **`packages/ioc` is the ONLY package allowed to import network
  modules.** The Biome `noRestrictedImports` rule (currently scoped
  to `packages/core/src/scan-mcp.ts`) extends to forbid `node:http`,
  `node:https`, `node:net`, `node:dgram`, `globalThis.fetch` in
  every `packages/*/src/` file *except* `packages/ioc/src/sync.ts`.
- **Network code is hand-rolled on `node:https`.** No `node-fetch`,
  `undici`, `axios`, or similar dep is added. Reasons:
  - Bun ships `node:https` built-in. Zero new dep.
  - The fetch surface we need is single-URL, single-method, no
    retry middleware, no streaming consumer — trivial to write.
  - Vetting a network dep's transitive tree is more work than the
    50-line fetch helper.
- **Network is HTTPS-only.** Refuse `http://`, refuse redirects to
  any host outside `*.googleapis.com`. The hardcoded host is
  documented and enforced — substitution requires a code change,
  not a config edit.

Architecture diagram update (lands with M8 implementation):

```
packages/
├── cli/                (no network)
├── core/               (no network — enforced by lint)
├── rules/              (no network — pure data)
├── hooks-claude/       (no network)
├── hooks-cursor/       (no network)
└── ioc/                ← network ALLOWED here, and nowhere else
    └── src/
        ├── sync.ts     ← only file in the repo that may use node:https
        ├── index-store.ts
        ├── lookup.ts
        └── manifest.ts
```

### 8. Subcommand surface

```
warden ioc sync [--source osv] [--ecosystem <name>...] [--force]
  Download (or refresh) the IOC cache. Default: sync all configured
  sources and all ecosystems. --force re-downloads even if the last
  sync was within the staleness TTL.

warden ioc status [--json]
  Print cache state: last-sync timestamp per source, ecosystem list,
  advisory counts, days since last sync.

warden ioc lookup <ecosystem>:<package>@<version> [--json]
  Print matching advisories (zero or more). Exit 0 if zero matches,
  exit 1 if one or more matches found (so CI can gate on it). --json
  emits warden/ioc-lookup/v1.

warden ioc verify [--source osv]
  Re-download and SHA-256 compare against the previously-cached ZIP.
  Surfaces feed-content drift between syncs. Exit 0 if matches, exit
  1 if differs (with the diff printed).
```

`warden ioc sync` exit codes:

| Outcome                               | Exit | Notes |
|---------------------------------------|------|-------|
| Sync succeeded                        | 0    | Logs `synced N advisories from osv` on stderr; silent on stdout. |
| Network unreachable                   | 1    | Stderr names the URL that failed. Cache untouched. |
| HTTP non-2xx                          | 1    | Stderr includes status code. Cache untouched. |
| ZIP parse failure                     | 1    | Stderr includes the offending entry. Cache untouched. |
| Disk full / write failure             | 1    | Stderr names the path. |
| Config error (bad `.warden.toml`)     | 2    | Same posture as other Warden config errors. |

Cache invariant: **failed sync never leaves the cache in a partial
state.** Sync writes to a temp dir, atomically renames into place on
success, leaves the previous cache intact on any failure path.

### 9. Threat model — T6: Compromised vulnerability feed

New T-entry for `docs/THREAT_MODEL.md`. Stated explicitly here so
M8 implementation has the threat language to cite.

**T6 — Compromised IOC feed**

**Vector:** Warden trusts OSV.dev to publish accurate vulnerability
data. An attacker who can modify what `storage.googleapis.com` serves
(or who can MITM the connection) can either:

1. **Drop records** for known-malicious packages → false negatives
   (user installs the malicious package; Warden says nothing).
2. **Inject false advisories** for popular legitimate packages →
   false positives (CI fires; dev disables Warden or excludes the
   noise; real signal is lost).
3. **Targeted exclusion** — strip the advisory for one specific
   compromised release while leaving the rest intact → silent
   exemption of the package the attacker controls.

Blast radius: every Warden user who runs `warden ioc sync` against
the compromised source between the compromise and its detection.

**Warden mitigations (in M8):**

- **HTTPS-only with host pinning.** The only allowed host is
  `storage.googleapis.com`; redirects to other hosts are rejected.
  TLS trust chain validated through the OS trust store. Mitigates
  passive MITM.
- **Per-sync SHA-256 logging.** Every sync records the SHA-256 of
  the downloaded ZIP in `manifest.json`. The previous N manifests
  are retained in `history/`.
- **`warden ioc verify`.** Re-downloads and compares against the
  last cached hash. A change between syncs that the user did not
  expect (e.g., advisory count dropped by 50%) surfaces in the
  verify output.
- **Diff-on-sync.** `warden ioc sync` prints a summary line:
  `synced osv: +12 new / -3 dropped / 8421 total`. A sudden large
  drop is a red flag the user can investigate.
- **No auto-disable on missing data.** If OSV starts returning an
  empty `npm.json`, M9 finding rules produce no findings — but the
  fact that the cache is empty is loudly logged. We do not silently
  trust an empty result.

**Warden does NOT mitigate (named in THREAT_MODEL.md update):**

- **Signed feeds.** OSV does not currently publish signed bulk
  ZIPs. If a future ADR adds Sigstore / Cosign verification for
  OSV releases, we adopt it then; today's mitigation is TLS + diff.
- **Compromise of the OSV ingestion pipeline upstream of the
  bucket.** If a malicious advisory is accepted into OSV's
  ingestion before it reaches our cache, we have no way to detect
  it from inside Warden. Same trust posture as `npm install`
  trusting the npm registry.
- **Coordinated multi-source poisoning.** Once we add a second
  source (M9+), cross-source consensus becomes a defense. For M8's
  single source, this defense doesn't exist.
- **Compromise of the user's `~/.warden/ioc/` directory.** A local
  attacker who can write the cache can plant or strip advisories
  directly. Same trust assumption as every other tool that caches
  state on the user's machine (npm cache, pip cache, …).

Citation: this T6 entry mirrors the framing of T1–T5: vector, blast
radius, what we detect, what we don't. The full update lands in
`docs/THREAT_MODEL.md` in the M8 implementation commit.

### 10. Atomicity guarantees

The sync is a transaction: either the cache atomically updates to a
new consistent state, or it stays at its previous consistent state.
There is no observable partial state. Without this guarantee, the
first network failure or process kill corrupts the cache and the
next `warden ioc lookup` returns nonsense.

Implementation contract:

1. **Stage to tempdir.** All sync writes go to
   `~/.warden/ioc/.tmp-<unix-millis>/`. The previous cache
   (`~/.warden/ioc/osv/`, `~/.warden/ioc/manifest.json`,
   `~/.warden/ioc/history/`) is never modified during the staging
   phase. A reader running `warden ioc lookup` in parallel sees only
   the previous cache.

2. **Parse before commit.** The OSV ZIP is fully downloaded, fully
   inflated, fully parsed, and fully pruned-into-indexes inside the
   tempdir before any rename happens. A malformed ZIP, a malformed
   JSON entry, a network error mid-stream, or a disk-full event all
   leave the previous cache intact and surface a stderr message
   identifying the failed step. Exit 1.

3. **Atomic directory swap.** On success, the previous `osv/`
   directory is renamed to `osv.prev-<unix-millis>/`, then the staged
   tempdir is renamed to `osv/`, then `osv.prev-*/` is deleted.
   POSIX `rename(2)` on the same filesystem is atomic.

4. **Manifest written last.** `manifest.json` is the last file
   written and is the single source of truth for "what version of
   the cache is current." It uses the same temp-then-rename pattern
   (write `manifest.json.tmp-<millis>`, fsync, rename to
   `manifest.json`) so a half-written manifest cannot exist on disk.

5. **Crash safety.** If the process is killed at any point:
   - During download / parse / prune → tempdir is orphaned, previous
     cache intact; next sync GCs `.tmp-*` orphans older than 1 hour
     before staging.
   - During the swap (`osv/` → `osv.prev-*/` → tempdir-to-`osv/`) →
     POSIX rename is atomic on same filesystem; either the new
     directory or the old one is in place, never both, never
     neither. If the second rename fails mid-sequence, the old
     `osv.prev-*/` is renamed back to `osv/` and the sync reports
     a failure.
   - During manifest write → the manifest is the last write; if it
     fails, the indexes are already in place but the manifest still
     points at the previous sync's metadata. `warden ioc status`
     detects this (manifest's advisory counts disagree with on-disk
     index counts) and prints a recovery hint: re-run `warden ioc
     sync` to reconcile.

6. **History append is best-effort.** After the swap succeeds, the
   previous manifest is copied (not moved) to
   `history/<old-timestamp>.json`. History write failures are
   non-fatal — the new cache is already the current state; history
   loss is logged on stderr but does not roll back. Keeping history
   inside the same filesystem boundary as the rest of the cache
   means this is rarely a failure mode in practice.

7. **No cross-filesystem atomic rename.** If `~/.warden/ioc/` lives
   on a different filesystem than the system temp directory (e.g.
   `~/.warden` on tmpfs, cache on NFS, exotic XDG setups), POSIX
   rename refuses to cross filesystem boundaries. The sync falls
   back to copy-then-delete with an explicit stderr warning naming
   the FS boundary. The window of inconsistency in the fallback
   path is bounded by the copy time (sub-second for the 50 MB cache)
   and the previous cache is preserved until the copy completes
   successfully, so the worst-case outcome is "old cache + new cache
   briefly coexist," not "neither exists."

Verified by an integration test (`packages/ioc/tests/sync.test.ts`):

- Setup: pre-existing cache populated by a known-good fixture sync.
- Action: run a sync against a fixture ZIP that deliberately throws
  inside the parser on the third record.
- Assert: previous cache is byte-identical to its pre-sync state.
- Assert: no `.tmp-*` orphan remains after a follow-up successful
  sync (GC ran on staging).
- Assert: stderr names the failed step.
- Assert: exit code is 1.

This atomicity contract is the load-bearing reason the `~/.warden/ioc/`
cache is safe to share between concurrent `warden scan` and
`warden ioc sync` invocations: scan only ever reads the committed
manifest + indexes, sync only ever writes to a side directory until
the swap.

---

### 11. Non-goals (explicit)

- **No live network calls during `warden scan`.** Hard invariant.
- **No lockfile parsing in M8.** Deferred to M9.
- **No scanner findings in M8.** The cache populates and is
  queryable via `warden ioc lookup`, but no new finding category
  fires from `warden scan`. M9 wires this up alongside the lockfile
  parser.
- **No multi-source consensus.** Single source (OSV) only.
- **No signed-feed verification.** Waiting on OSV upstream.
- **No automated scheduling.** No cron, no systemd timer, no
  background daemon. Sync is manual; users wire their own schedule
  if they want one.
- **No SBOM generation.** `warden report --aibom` is a separate
  Layer 3 work, tracked in the post-M7 list.
- **No vulnerability remediation suggestions.** Warden reports
  findings; it does not propose `npm audit fix`-style auto-upgrades.
- **No Socket / MalwareBazaar / GHSA-direct sources.** Single source
  for M8; second source is M9+ and gets its own design pass.
- **No retroactive cache encryption.** The cache is public OSV data
  in a user-readable directory. No secrets, no need to protect
  confidentiality.

---

## 12. Resolved decisions (at acceptance)

The six open questions raised during the planning pass were resolved
by the user at acceptance time. Recorded here so future readers see
the decision and the reason in one place rather than chasing
conversation history.

1. **M8 scope = narrow.** Sync + lookup + status + verify only. No
   lockfile parsing, no scanner findings. M9 wires findings into
   `warden scan` alongside per-ecosystem semver comparators. Reason:
   each ecosystem's lockfile + version-range grammar is a separate
   design decision that deserves its own pass; bundling them produces
   a milestone that either drags or ships shallow versions of every
   sub-decision.

2. **Default ecosystems = all.** `warden ioc sync` with no flags
   pulls every OSV ecosystem. ~50 MB worst-case is negligible on a
   developer machine, and "safe defaults > small defaults" is the
   project posture (a Rust developer surprised by missing Cargo
   coverage is a worse outcome than 50 MB of unused PyPI data).
   Users who want a subset opt in via `--ecosystem` or `.warden.toml`.

3. **Cache format = per-ecosystem JSON.** SQLite revisited when
   volume exceeds ~500 MB, not before. Today's volume (~50 MB) does
   not justify the dep (`bun:sqlite` couples cache format to runtime
   choice; `better-sqlite3` is a native dep that needs vetting). The
   M9 lockfile scanner's lookups are O(1) by package name on
   already-loaded indexes; no indexed query layer required.

4. **`warden ioc lookup` exit code = 1 on hits.** CI integration
   requires this (no other way to gate). Exit 0 = zero matches; exit
   1 = one or more matches. A general error (cache missing, malformed
   ecosystem name) is exit 2.

5. **Staleness TTL = 7 days.** 1-day warnings become noise CI
   pipelines learn to ignore; 30-day warnings let a critical CVE land
   silently. 7 days is the equilibrium between "fresh enough to
   matter" and "loud enough to act on."

6. **History retention = 10 manifests.** At one sync per week (the
   default cadence implied by the 7-day TTL), 10 manifests cover
   ~2 months of `warden ioc verify` lookback — enough to investigate
   "when did this advisory appear?" for the typical incident window.
   1 retains too little (no comparison surface); 100 retains
   ~2 years and inflates the cache directory pointlessly.

---

## Consequences

Positive:

- Supply-chain awareness arrives. Warden goes from "scan the bytes
  the agent reads" to "scan the bytes plus know which dependencies
  are knife-edge dangerous."
- Network surface is isolated to one package and one subcommand;
  the scanner's offline-pure invariant survives.
- The cache format and `.warden.toml` schema land in M8 in their
  minimum-viable shape, ready to grow in M9 without churn.
- T6 is named explicitly with mitigations and known limits — no
  hand-waving about feed trust.

Negative:

- First user-visible coupling to an external service (OSV.dev). If
  OSV's bucket goes down, `warden ioc sync` fails. The scanner is
  unaffected, but users running `--strict` IOC pipelines in CI
  will see flaky runs on OSV outages.
- A new package adds boilerplate (package.json, README pointer,
  CODEOWNERS coverage). Dep count: still zero new external deps;
  one new internal package.
- The cache occupies disk space (~50 MB worst-case). Some CI runners
  will need an explicit cache directive to avoid re-syncing on
  every job. Documented in M8's README addition.
- Single source = single point of failure. M9+ adds consensus once
  a second source is justified.

---

## Sources

- OSV.dev data downloads documentation —
  `https://google.github.io/osv.dev/data/` (verified 2026-05-25).
  Source of the bulk-ZIP URLs, per-ecosystem ZIPs, and
  `modified_id.csv` incremental-sync hint.
- OSV Schema specification —
  `https://ossf.github.io/osv-schema/` (verified 2026-05-25).
  Source of the per-advisory field shape (id, severity, ranges,
  references, ecosystem).
- OSV data license — Creative Commons Attribution 4.0
  (`https://creativecommons.org/licenses/by/4.0/`). Permits local
  caching and redistribution.
- ADR 0011 §2 — no-network-on-hot-path invariant preserved here
  by isolating network to `packages/ioc/src/sync.ts`.
- ADR 0013 §6 / ADR 0014 §7 — the `.warden/` config-file
  governance posture (`schema = "v1"`, CODEOWNERS coverage) M8
  follows for `.warden.toml` and `~/.warden/ioc/`.
- OWASP A06:2021 — Vulnerable and Outdated Components
  (`https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/`)
  — primary citation for the T6 vector (supply-chain risk from
  known-vulnerable dependencies).
