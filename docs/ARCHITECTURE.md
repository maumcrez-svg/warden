# Warden — Architecture

**Status:** Draft, M0
**Last updated:** 2026-05-24

This document describes the static structure of the Warden codebase, the data flow at scan time, and the deliberate boundaries between deterministic and heuristic logic. Implementation detail belongs in package READMEs landed in later milestones, not here.

---

## 1. Data Flow

```
                  +------------------+
                  |   filesystem     |
                  +--------+---------+
                           |
                           v
                  +------------------+
                  |   file walker    |    (respects .gitignore)
                  |  packages/core   |
                  +--------+---------+
                           |  candidate paths
                           v
                  +------------------+
                  | format detector  |    (CLAUDE.md, .cursorrules,
                  |  packages/core   |     mcp.json, AGENTS.md, ...)
                  +--------+---------+
                           |  typed file refs
                           v
   +------------------+    |       +------------------+
   |   rule pack      |---->-------|  scanner engine  |
   | packages/rules   |  (data)    |  packages/core   |
   |  (pure data)     |            | (pure functions) |
   +------------------+            +--------+---------+
                                            |  findings[]
                                            v
                                   +------------------+
                                   |     reporter     |
                                   |  packages/cli    |
                                   +--------+---------+
                                            |
              +-----------------------------+-----------------------------+
              v                             v                             v
       +-------------+             +------------------+         +---------------+
       |   stdout    |             |  JSON report     |         |  SARIF file   |
       |  (pretty)   |             |  (--json flag)   |         |  (--sarif)    |
       +-------------+             +------------------+         +---------------+
```

The pipeline is **single-pass, offline, and deterministic**. The scanner engine is a set of pure functions; the rule pack is data. There is no shared state, no global config singleton, no network I/O on the hot path.

---

## 2. Package Boundaries

| Package                  | Responsibility                                                       | May depend on                          | Network |
|--------------------------|----------------------------------------------------------------------|----------------------------------------|---------|
| `packages/core`          | File walker, format detector, scanner engine, finding types          | `packages/rules`                       | no      |
| `packages/rules`         | Threat rule data only (Unicode ranges, regex patterns, citations)    | (nothing)                              | no      |
| `packages/cli`           | Argument parsing, reporter, exit-code policy                         | `packages/core`, `packages/ioc`        | no      |
| `packages/hooks-claude`  | Claude Code PreToolUse hook installer + runtime interceptor          | `packages/core`                        | no      |
| `packages/hooks-cursor`  | Cursor adapter                                                       | `packages/core`, `packages/hooks-claude` | no      |
| `packages/ioc`           | IOC sync + lookup (OSV.dev). Cache state in `~/.warden/ioc/`.        | (nothing)                              | **yes** — only `packages/ioc/src/sync.ts` (ADR 0015 §7) |

**`packages/rules` depends on nothing.** It is data with type wrappers. This makes the rule pack auditable as a flat artifact and makes signed rule-pack distribution (post-MVP) clean.

**`packages/core` never imports `packages/cli`.** The scanner must be usable from a non-CLI context (programmatic API, future LSP, future CI action).

---

## 3. Determinism Boundaries

| Layer                                  | Determinism                  | Why                                                            |
|----------------------------------------|------------------------------|----------------------------------------------------------------|
| File walker                            | Deterministic (sorted output) | Reproducible reports; reviewer trust.                          |
| Format detector                        | Deterministic (path + magic) | No probabilistic content sniffing.                             |
| Unicode scanner (M1)                   | Deterministic                | Codepoint inclusion is a set test.                             |
| Unicode density threshold              | Heuristic (tunable, cited)   | Distinguishes legit emoji selectors from attack-grade saturation. |
| Prompt-injection pattern match (M3)    | Deterministic per rule       | Each rule is a regex with documented intent.                   |
| Prompt-injection severity scoring (M3) | Heuristic (rule-weighted)    | Composite of how many high-confidence rules fired.             |
| MCP config analysis (M4)               | Deterministic                | Parse + structural check. No execution, no sniffing.           |

All heuristics expose their thresholds as constants in `packages/rules/data/thresholds.ts` (added in M1) so a user can override and a reviewer can audit.

---

## 4. Hot Path vs Cold Path

**Hot path** — every byte read during `warden scan`:
- File walker, format detector, scanner engine, rule pack lookups.
- Constraints: no allocations per byte where avoidable; no network calls (ever); no async beyond filesystem reads.

**Cold path** — initialization, reporting, signing, IOC sync:
- Argument parsing, terminal capability detection, output formatting, SSH signing via `ssh-keygen -Y sign|verify` subprocess (post-M5; see ADR 0012), `warden ioc sync|verify` network calls to OSV.dev (post-M8; see ADR 0015).
- Constraints: correctness > performance.

**Network is allowed in exactly one place: `packages/ioc/src/sync.ts`.** Codified by ADR 0015 §7 and enforced at lint time by the `noRestrictedImports` rule in `biome.json` (which forbids `node:https` / `http` / `net` / `dgram` / `tls` everywhere under `packages/**/src/` *except* `packages/ioc/src/sync.ts`). The scanner's offline-pure invariant from ADR 0011 §2 is preserved by isolation, not weakened by exception.

This boundary informs the future Rust-rewrite decision (see ADR 0001): only hot-path code is a candidate for rewrite, and only if telemetry justifies it.

---

## 5. Why the Scanner Never Calls the Network

Three reasons, in priority order:

1. **Air-gapped CI environments must work.** Crypto custodians, gov contractors, and audit firms run CI offline. A scanner that fails-closed on missing network is unusable for them.
2. **The scanner must not be a vector itself.** A scanner that calls home is a scanner whose call-home endpoint can be coerced, spoofed, or used to fingerprint targets. We do not own that risk.
3. **Determinism.** A scan run on the same input at two different moments must produce the same findings, regardless of upstream feed availability.

Layer 3 features that *do* require network are isolated in a separate command surface and never invoked by `warden scan`. As of M8, `warden ioc sync` and `warden ioc verify` are the only network-bound subcommands; their implementation lives in `packages/ioc/src/sync.ts` (the single file in the repo where network imports are allowed — see §4 and ADR 0015 §7). Future `warden report --aibom` work follows the same isolation pattern.

---

## 6. Sandboxing — `warden scan --sandbox` (default)

The flagship differentiator. When scanning MCP configurations, Warden parses the JSON/YAML statically — it never spawns the configured stdio servers or the configured network servers. This is a deliberate departure from inspection tools that spawn-to-introspect (and inherit the risk of executing attacker-controlled binaries).

Implementation pattern (planned for M4):
- The MCP parser is a pure function: `(configBytes) => McpAnalysis`.
- The analysis surface includes: server count, transport types, command paths, version pins (or absence), declared scopes, declared environment variables.
- The parser never calls `child_process.spawn`, never `fs.write*`, never `net.connect`. These are linted out at PR review via a Biome `noRestrictedImports` rule added in M4 alongside the parser.

---

## 7. Cross-category collateral scanning

All context files pass through all detectors in sequence, not just the
detector for their declared format. A `.cursorrules` file runs through
`scanUnicode` AND `scanPromptInjection`. An `mcp.json` file runs
through `scanUnicode` AND `scanPromptInjection` AND `scanMcp`.

This is defense-in-depth: a payload that escapes one detector's
category can be caught by another. An MCP config whose
`description` field contains override-prior-context phrasing is caught
by `scanPromptInjection` on the raw JSON content, even though no
dedicated MCP rule inspects description fields. Invisible Unicode in
any string value of an MCP config is caught by `scanUnicode` on the
same raw content.

Trade-off: findings on the same logical issue may appear under
multiple rule IDs from different detectors. Reporters dedupe by
file + byte-offset + rule-id, but cross-detector overlap is accepted
as additional signal rather than noise — the JSON-shape signal
(`mcp.command-not-pinned`) and the textual signal
(`prompt-injection.override-prior-instructions`) describe different
properties of the same file and reviewers benefit from seeing both.

The collateral coverage is **load-bearing** for threats deliberately
left out of dedicated rules. ADR 0011 §1 keeps the MCP rule set
narrow; ISSUES #004 (MCP tool description scanning) documents that
inline description injection in MCP configs relies on this property,
not on a dedicated MCP rule.

---

## 8. Open Architectural Questions (tracked in ADRs)

- ADR 0001: Bun over Rust for MVP — **Accepted**.
- ADR 0002: Domain name — **Deferred** (placeholder `warden.dev`).
- ADR 0003: Trust key bootstrap — **Accepted** (reopened in M5; SSH-based, maintainer key as bootstrap). Full spec in ADR 0012.
- ADR 0004: GitHub org name — **Tentative** (placeholder `warden-sh`).
- (Future) ADR 000N: rule-pack distribution and signing.
- (Future) ADR 000N: telemetry policy if we ever add it (currently: never, in OSS core).
