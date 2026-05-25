# Warden — Roadmap

**Status:** Draft, M6
**Last updated:** 2026-05-25

Milestones are atomic units of work. Each one is executed in a fresh Claude Code session via `/milestone N` (see `.claude/commands/milestone.md`).

**Status legend:** 🟦 planned · 🟨 in progress · ✅ done · ⬜ deferred / out of MVP

---

## M0 — Skeleton ✅

**Scope:** Establish the repository structure, documentation baseline, hook-based discipline, and slash-command workflow. No runtime code.

**In-scope:**
- `CLAUDE.md`, `README.md`, `LICENSE` (MIT), `.gitignore`.
- `package.json` (Bun workspace root), `biome.json`, `tsconfig.json`.
- `.claude/settings.json`, hooks (`pre-commit-secrets.sh`, `pre-write-paths.sh`, `post-edit-format.sh`), commands (`/milestone`, `/verify`).
- `docs/PRD.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`.
- `docs/DECISIONS/0001`, `0002`, `0003`, `0004`.
- Empty `packages/*/src/` skeletons for `cli`, `core`, `rules`, `hooks-claude`, `hooks-cursor`.

**Out-of-scope:** Any TypeScript source. Any test. Any rule data.

**Acceptance criteria:**
- `tree -a -I 'node_modules|.git'` matches the layout in `CLAUDE.md`.
- All three hooks are executable.
- `/verify` runs (it will report no tests and no scanner; that is expected at M0).

**Demo command:** `tree -a -I 'node_modules|.git' /home/lumen/Documentos/warden`

---

## M1 — Unicode threat detector ✅

**Landed:** see `git log --grep="feat(core): M1"`.

**Scope:** A pure function that takes a string and returns a list of findings, each with codepoint, range name, severity, and byte offset. Covers the codepoints abused by TrapDoor (T1) and GlassWorm (T2).

**In-scope:**
- Codepoint ranges:
  - Variation Selectors Supplement (U+E0100–U+E01EF).
  - Tag chars (U+E0000–U+E007F).
  - Bidi overrides (U+202A–U+202E, U+2066–U+2069).
  - Zero-width chars (U+200B, U+200C, U+200D, U+FEFF).
  - Hangul filler (U+3164).
- Density heuristic: legitimate emoji uses 1–2 selectors per glyph; attacks use dozens-to-hundreds per file. Threshold lives in `packages/rules/data/thresholds.ts`.
- API surface: `scanUnicode(input: string): UnicodeFinding[]` exported from `packages/core`.
- Fixtures (minimum 8): 4 malicious (TrapDoor-style payload variants) + 4 benign (legit emoji ZWJ sequence, legit RTL Arabic paragraph, legit Korean Hangul, mixed-script README).

**Out-of-scope:** File walking (M2). MCP configs (M4). Output formatters (M2). CLI wiring (M2).

**Acceptance criteria:**
- 100% true-positive on the 4 malicious fixtures.
- 0 false-positives on the 4 benign fixtures.
- Each codepoint range cited in a code comment with the Unicode block name.
- `/verify` passes.

**Demo command:** `bun test packages/core` printing the finding count for each fixture.

---

## M2 — File walker + format detection ✅

**Landed:** commit `6d0117b` — see `git log --grep="feat(cli): M2"`.

**Scope:** Walk a directory, identify agent context files, output a typed JSON report and a pretty terminal report. Wire the CLI entry point.

**In-scope:**
- File walker respecting `.gitignore` and `.wardenignore` (small in-tree parser; see ADR 0006).
- Format detection for: `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`, `.aider.conf.yml`, `.github/copilot-instructions.md`, `mcp.json`, generic skill files. Generic markdown fallback (`.md`, `.mdc`, `.markdown`) is also scanned — see ADR 0006 §"Generic-markdown fallback".
- CLI: `warden scan [path]` with flags `--json`, `--sarif`, `--quiet`, `--no-color`.
- Reporter: pretty terminal output with file-grouped findings, ANSI color (off when not a TTY or `--no-color`).

**Out-of-scope:** Prompt-injection patterns (M3). MCP analysis (M4). Trust signing (M5). Hook adapters (M6).

**Acceptance criteria:**
- `warden scan .` on the Warden repo itself produces 0 high-severity findings (exit 0).
- `warden scan tests/fixtures/trapdoor/` produces 211 findings (95 tag-char + 2 bidi + 64 VS-supplement + 50 zero-width), matching the M1 fixture totals.
- SARIF output is structurally compliant with SARIF 2.1.0 (validation strategy in ADR 0007 §2).

**Demo command:** `bun packages/cli/src/index.ts scan tests/fixtures/trapdoor/ --quiet`

---

## M3 — Prompt-injection pattern detector ✅

**Landed:** commit `13799fa` — see `git log --grep="feat(rules): M3"`.
Design rationale in `docs/DECISIONS/0008-prompt-injection-rule-pack.md`;
JSON v1→v2 bump in `docs/DECISIONS/0009-json-v2-prompt-injection-findings.md`.

**Sealed with caveat (closed by M3.2):** the `.wardenignore`-based
exclusion of rule data and detector tests was identified in review as
the canonical SAST anti-pattern (whole-file glob exclusion turns the
exclusion list into an attacker entry point). See M3.1 for the
corrected design and M3.2 for the governance follow-up that names the
residual broad-scope subcase and adds CODEOWNERS.

**Scope:** Rule-based pattern detector (data in `packages/rules/src/data/prompt-injection.ts`). Not an LLM. Each rule cites its source.

**In-scope:**
- Known phrasing families (full pattern text in `packages/rules/src/data/prompt-injection.ts`):
  - override-prior-context imperatives (ignore/disregard/forget/override × previous/prior/above/system × instructions/prompts/directives/messages/rules/context);
  - persona-shift "you are now {persona}" prompts (DAN, developer-mode, jailbroken, unrestricted, uncensored, free-from-restrictions);
  - ChatML role-control tokens (the `im_start` / `im_end` family);
  - role-confusion control tokens (Llama 2 `INST` markers, `SYS` blocks, named-role pipe tokens);
  - leading line-anchored `system` role prefixes followed by imperative or persona verbs.
- Severity tiers: stylistic / suspicious / verbatim-known-payload.
- Each rule documented with source URL and date verified.

**Out-of-scope:** Novel pattern learning. LLM-based classification. False-positive suppression based on context (deferred).

**Acceptance criteria:**
- Fixtures: at least one positive per rule, at least 3 false-positive-prone benign cases (academic paper on prompt injection that *describes* attacks; fictional dialogue containing "you are now"; security advisory body quoting CVE-2025-53773).
- 0 false-positives on the benign set.

**Demo command:** `warden scan tests/fixtures/prompt-injection/ --quiet | wc -l`

---

## M3.1 — Marker-based fixture exclusion (correction of M3) ✅

**Landed:** commit `461d468` — see `git log --grep="feat(core): M3.1"`. Design in
`docs/DECISIONS/0010-payload-fixture-marker-convention.md`. ADR 0008 §4
gets a leading "superseded" note; ADR 0009 gets a v2-absorbed-suppression
footnote.

**Scope:** Replace the whole-file `.wardenignore` entries introduced in
M3 (plus the M1-inherited `tests/fixtures/` glob exclusion) with an
inline payload-fixture marker convention. The scanner continues to read
every file; markers suppress findings only for the declared finding
categories. Cross-category poisoning — a planted prompt-injection
payload inside a fixture marked `trapdoor-unicode` — still fires.

**In-scope:**
- ADR 0010: grammar
  `warden: payload-fixture <family>[ <family>...] [scope:file|scope:lines:N-M] -- <reason>`
  with ASCII `--` separator (em-dash rejected), four families
  (`trapdoor-unicode`, `prompt-injection-pattern`, `rules-data`,
  `detector-test`), path restrictions on broad-scope families, and
  malformed-marker-is-exit-2 semantics.
- `packages/core/src/marker.ts` parser with header-zone walk, markdown
  fenced-code-block awareness, and full unit-test coverage.
- Suppression wired into `scanPath`; per-file `marker`,
  `suppressedFindings`, `suppressedPromptInjectionFindings`, and
  top-level `suppressedCount` + `suppressedByCategory` surfaced in
  `ScanReport` (additive to JSON v2 — no v3 bump).
- `--verbose` CLI flag listing suppressed findings under the marker.
- SARIF `result.suppressions[]` per §3.27.23 (suppressed findings emit
  with `kind: "external"` rather than being dropped).
- `.wardenignore` purged of the three M3-era exclusions plus
  `tests/fixtures/`; the M1 dogfood test's parallel ignore list goes
  with it. Markers placed on the rule data file, both detector test
  files, every malicious trapdoor fixture, and every positive
  prompt-injection fixture. Benign fixtures get no marker (they pass
  clean naturally; the dogfood asserts this).

**Out-of-scope (deferred to M4 with operational guard in ADR 0010 §7):**
JSON/YAML/TOML marker syntax. No fixture of those types exists today;
when one appears before M4 lands, a new ADR specifies the syntax —
`.wardenignore` does NOT grow back as the easy bypass.

**Out-of-scope (deferred indefinitely with documented rationale):**
Pattern-aware suppression (suppress only findings inside declared regex
literals; everything else fires) — a future-ADR candidate if a real
attack on the `rules-data` broad-scope family is observed.

**Acceptance criteria:**
- Every `.wardenignore` entry added during M0–M3 for "payload-bearing
  fixture" reasons is removed; the file is back to listing only files
  that are not agent context (binary lockfile, bootstrap-prompt).
- Cross-category poisoning test: a fixture marked `trapdoor-unicode`
  with a planted prompt-injection payload reports the prompt-injection
  finding (does not suppress it). Covered by
  `scan-path.test.ts → "trapdoor-unicode marker does NOT suppress a
  planted prompt-injection finding"`.
- Malformed marker → exit 2 with stderr message citing file:line.
  Covered by `cli.test.ts → "marker errors"`.
- `/verify` passes; `warden scan .` exits 0 with summary
  `0 finding(s)` and a `suppressed: N unicode + M prompt-injection`
  line listing the M3.1 markers' work.

**Demo command:** `bun packages/cli/src/index.ts scan tests/fixtures/trapdoor/ --verbose | head -20`

**Sealed by M3.2:** the only open caveat after M3.1 was the residual
broad-scope subcase (new-file-plus-new-marker in a single PR). M3.2
named the subcase in ADR 0010, added CODEOWNERS for the path-restricted
directories, and tracked the technical-mitigation decision in
`docs/ISSUES.md` #002. No code-path changes; M3.1's marker semantics
remain the runtime contract.

---

## M3.2 — Marker governance + threat-model honesty pass ✅

**Landed:** commit `46d4fe2` — see `git log --grep="docs(governance): M3.2"`.
No runtime changes; the marker parser is unchanged.

**Scope:** Close the residual M3.1 caveat through documentation and
governance, not through more code. The subcase that motivated M3.2
("new-file-plus-new-marker in a single PR") was *mentioned* in ADR
0010 §"Open after M3.1" but not named, not enforced, and not tracked
for follow-up. M3.2 fixes all three.

**In-scope:**
- ADR 0010 §"Open after M3.1" gets an explicit
  **new-file-plus-new-marker** entry calling the subcase by name and
  pointing at the active mitigations (CODEOWNERS, CLAUDE.md, review)
  plus the deferred technical mitigations (file allowlist vs
  pattern-aware suppression).
- `.github/CODEOWNERS` forces maintainer review on
  `packages/rules/src/data/`, `packages/core/src/marker.ts`,
  `docs/DECISIONS/`, and `.github/` itself. Owner is the placeholder
  `@warden-sh/maintainers` team pending ADR 0004 resolution.
- `docs/ISSUES.md` #002 — "Broad-scope marker families lack explicit
  file allowlist" — open, severity medium, milestone pre-1.0. Includes
  the placeholder-team sub-task.
- `docs/THREAT_MODEL.md` gains a "Self-defense against trusted
  contributors" subsection making the trust model explicit: Warden is
  not a defense against your own committers; mitigations are
  governance, not technical. Same framing as
  `eslint-disable-next-line` or `# noqa`.

**Out-of-scope:**
- No changes to `packages/core/src/marker.ts` or any other runtime
  code. M3.1 semantics stand.
- No fixture changes, no test changes beyond what documentation
  edits require.
- File allowlist and pattern-aware suppression are tracked in #002
  and deferred until a real second attacker scenario surfaces or M4
  fixture requirements force the decision.
- No ADR 0011. The limitation was already in ADR 0010 — M3.2 names
  it explicitly in the same section, preserving the document's
  position as the single source of truth for marker design.

**Acceptance criteria:**
- ADR 0010 §"Open after M3.1" contains the
  "new-file-plus-new-marker" subsection verbatim.
- `.github/CODEOWNERS` exists with the four required path entries.
- `docs/ISSUES.md` #002 exists with status `open`.
- `docs/THREAT_MODEL.md` "Detection coverage and known limitations"
  contains the "Self-defense against trusted contributors"
  subsection.
- `/verify` passes (tests unchanged; only docs and one config file).
- ROADMAP M3.1 entry no longer carries the open caveat; this M3.2
  entry stands in its place.

**Demo command:** `grep -ni 'new-file-plus-new-marker' docs/DECISIONS/0010-payload-fixture-marker-convention.md && head -5 .github/CODEOWNERS`

---

## M4 — MCP config static analyzer ✅

**Landed:** commit `99c2ec3` — see `git log --grep="feat(core): M4"`.
Design in `docs/DECISIONS/0011-mcp-config-static-analyzer.md` (covers
the analyzer **and** the JSON marker syntax that ADR 0010 §7 deferred).

**Scope:** Parse `mcp.json` and equivalents **without spawning** any defined server. The flagship `warden scan --sandbox` capability.

**In-scope:**
- Parsers for: Claude Code MCP config, Cursor MCP config, generic `claude_desktop_config.json` (all three use the `mcpServers` top-level shape; Cursor's alternate `servers` shape is deferred).
- Static checks: stdio vs HTTP transport, command-path absoluteness, version-pin presence, shell-exec command detection, declared tool-name patterns. Environment-variable scope folds into M5 (credential blocklist) once real-world false-positive shapes are observed.
- Findings: severity-tiered (low / med / high — `info` deferred until a rule needs it; see ADR 0011 §4), each with a cited rationale.
- Biome `noRestrictedImports` rule scoped to `packages/core/src/scan-mcp.ts`: forbids `child_process`, `net`, `node:dgram`, `fs/promises`. Sandbox guarantee enforced at lint time, not just documented.
- JSON marker syntax (ADR 0011 §6): top-level `_warden` string property carries the payload-fixture marker, mirroring ADR 0010 grammar from the sentinel onwards.

**Out-of-scope:** Actually spawning servers to verify they match their config (this is the whole point of NOT doing it). Network reachability checks.

**Acceptance criteria:**
- Fixture pack: 1 minimal-correct config, 1 missing-version-pin config, 1 absolute-path-to-untrusted-binary config, 1 declares-network-egress-tool config (+ 1 bonus shell-exec-command fixture exercising the fifth rule).
- All four classified correctly (covered by `scanPath — MCP fixtures (T2, M4)` in `packages/core/tests/scan-path.test.ts`).
- `/verify` passes; `warden scan .` exits 0 with a `suppressed: … + 4 mcp` line.

**Demo command:** `bun packages/cli/src/index.ts scan tests/fixtures/mcp/network-egress-tool/mcp.json --json --verbose`

**Sealed by M4.1:** post-M4 review named three coverage gaps that were
not explicit in ADR 0011 — path discovery, tool-description scanning,
and transport-tier uniformity. M4.1 documented all three with
resolution paths in `docs/ISSUES.md` #003-#005, articulated the
"cross-category collateral scanning" design property in
`docs/ARCHITECTURE.md` §7 (so reviewers see the load-bearing
defense-in-depth), and added a "Known limitations" section to
ADR 0011. No runtime changes; the M4 detection contract stands.

---

## M4.1 — MCP coverage gaps named + governance pass ✅

**Landed:** commit `905015a` — see `git log --grep="docs(governance): M4.1"`.
No runtime changes; the MCP analyzer is unchanged.

**Scope:** Close the post-M4 review gaps through documentation and
governance, not through more code. M4 shipped a working analyzer but
ADR 0011 was light on "what we explicitly do NOT detect" — three
limitations (path coverage, tool-description scanning, transport-tier
uniformity) were known to the implementer in review but not named in
the artifact trail. M4.1 names them.

**In-scope:**
- `docs/ISSUES.md` gains #003 (path discovery gaps), #004 (tool
  description scanning not a dedicated rule), #005 (transport-tier
  uniformity in `mcp.http-transport-external`). Each entry includes
  origin, severity, resolution path, and revisit trigger.
- `docs/ARCHITECTURE.md` gains §7 "Cross-category collateral
  scanning" articulating the design property that every file passes
  through every detector — so MCP description-field coverage via
  `scanPromptInjection` on raw JSON is named as architectural, not
  accidental. The previous §7 ("Open Architectural Questions") is
  renumbered to §8.
- ADR 0011 gains a "Known limitations (named by M4.1)" section with
  three bullets pointing at ISSUES #003-#005.
- `docs/THREAT_MODEL.md` "Detection coverage and known limitations"
  gains a "MCP-specific coverage and gaps" subsection making the
  no-runtime-tool-poisoning-detection stance explicit (same framing
  as the existing T-table entries).
- ROADMAP M4 entry no longer carries the open caveat (it has a
  "Sealed by M4.1" note instead); this M4.1 entry stands in its
  place.

**Out-of-scope:**
- No changes to `packages/core/src/scan-mcp.ts`,
  `packages/core/src/detect-format.ts`, or
  `packages/rules/src/data/mcp.ts`. M4 runtime semantics stand.
- No new MCP rule for tool descriptions. Issue #004 explains why
  (collateral coverage already exists; dedicated rule risks duplicate
  findings without clear severity tier).
- No transport-aware tiering. Issue #005 explains why (depends on
  `.warden.toml` config schema, which is a v1.0 concern).
- No `.warden.toml` schema. Separate work.
- No ADR 0012. The limitations were already implicit in ADR 0011 — M4.1
  names them in the same section, preserving the document's position
  as the single source of truth for MCP analyzer design.

**Acceptance criteria:**
- `docs/ISSUES.md` contains #003, #004, #005 with status `open`.
- `docs/ARCHITECTURE.md` §7 "Cross-category collateral scanning"
  exists; the previous §7 is now §8.
- `docs/DECISIONS/0011-mcp-config-static-analyzer.md` contains the
  "Known limitations (named by M4.1)" section with three bullets
  citing ISSUES #003-#005.
- `docs/THREAT_MODEL.md` "Detection coverage and known limitations"
  contains the "MCP-specific coverage and gaps" subsection.
- `/verify` passes with the same 208-test count as M4 (runtime
  intact).

**Demo command:** `grep -n 'MCP-specific coverage' docs/THREAT_MODEL.md && grep -c '^## #00[345]' docs/ISSUES.md`

---

## M5 — `warden trust` (signing) ✅

**Landed:** commit `eec31a4` — see `git log --grep="feat(trust): M5"`.
Full specification: `docs/DECISIONS/0012-m5-trust-signing.md`.

**Scope:** `warden trust sign|verify|list|unlock` subcommands. **SSH
signatures via `ssh-keygen -Y sign`** (no GPG, no embedded crypto). All
trust state in a single manifest at `.warden/trust/manifest.toml`.
Crypto-choice and vendor-key resolution: `docs/DECISIONS/0003-trust-gpg-key-deferred-to-m5.md`
§Resolution.

**In-scope:**
- `sign <path>` — produces a signature via `ssh-keygen -Y sign` (default
  key from `git config user.signingkey` when `gpg.format = ssh`, else
  `~/.ssh/id_ed25519`, else `~/.ssh/id_rsa`); appends/replaces a
  `[[trust]]` entry in `.warden/trust/manifest.toml`. Replacement
  emits an audit line to stderr.
- `verify [path]` — offline-pure; checks declared hash and SSH
  signature against `.warden/trust/allowed_signers` (+ optional
  additive `~/.warden/extra_allowed_signers`). Three failure
  categories: `trust.unsigned`, `trust.signature-mismatch`,
  `trust.untrusted-signer`. Plus `trust.orphan-entry` (warning by
  default, medium in `--strict`).
- `list` — read-only table; `--verify` adds a status column;
  `--json` emits `warden/trust-list/v1`.
- `unlock <path> --reason "<text>"` — writes `[[unlock]]` block;
  suppresses **only** `trust.unsigned` (never mismatch or untrusted-signer);
  ignored entirely under `--strict`.
- `keys list` — read-only inventory of `allowed_signers`. **No
  `keys add|remove`** by design: trust-root edits stay manual to force
  visual review (same lesson as `gh codeowner add` not existing).
- Trust root: hybrid model. `.warden/trust/allowed_signers` (committed,
  primary) + `~/.warden/extra_allowed_signers` (per-machine, additive,
  ignored in `--strict`).
- Sentinel: `.warden/trust-required` (empty/comment-only, committed).
  When present, `warden scan` exits 1 on missing manifest even without
  `--strict`.
- Default-behavior matrix (context-dependent): scan / verify / strict /
  sentinel each have distinct semantics — see ADR 0012 §3.
- Marker × signature interaction: orthogonal at the mechanism level,
  correlated at risk-scoring (broad-scope marker + unsigned →
  `trust.unsigned` HIGH, not medium).
- Bootstrap key: project maintainer's SSH public key in
  `.warden/trust/allowed_signers`; not a vendor identity, not a CA
  (ADR 0003 §Resolution).
- CODEOWNERS gains `.warden/trust/*` entries (same governance posture
  as M3.2 `new-file-plus-new-marker` mitigation).
- CI-friendly: structured stderr; verify exits 1 on findings, 2 on
  setup errors; zero TTY requirements on any path.

**Out-of-scope (deferred or rejected, per ADR 0012 §Non-goals):**
- Key rotation automation (manual `allowed_signers` edit; v1.0).
- CRL / revocation lists (remove from `allowed_signers` instead).
- Signature expiration (no native `ssh-keygen -Y sign` support without
  cert wrapping).
- Multi-signature M-of-N threshold (ISSUES #006).
- Sigstore / keyless signing (ISSUES #006).
- TOFU + URL pinning — **rejected**, not deferred (planning §6.4).
- Hardware-token specific workflows (touch policies, FIDO2 attestation).
- Generic non-agent-context file signing (use git-sign).
- Manifest encryption (contents are public by design).
- Reusable GitHub Action template (`warden-sh/trust-verify-action`) —
  v1.0 alongside ADR 0004 resolution.
- `.warden.toml` config schema (v1.0; also blocks ISSUES #005).

**Acceptance criteria:**
- Round-trip: `warden trust sign CLAUDE.md` → mutate one byte →
  `warden trust verify CLAUDE.md` emits `trust.signature-mismatch`
  HIGH, exit 1.
- Unmodified signed file: `warden trust verify CLAUDE.md` exits 0
  with no stdout (CLAUDE.md §Style "successful operations are silent").
- Fixture pack under `tests/fixtures/trust/` (signed-clean,
  signature-mismatch, untrusted-signer, unsigned-with-manifest,
  unsigned-with-unlock, orphan-entry, sentinel-no-manifest) — all
  classified correctly by `scanPath` and the trust verify path. The
  broad-marker + unsigned interaction (ADR 0012 §7) is covered by a
  unit test rather than a fixture; see ADR 0012 §"Fixtures" Note for
  rationale.
- `warden scan` on a pre-M5 repo (no manifest, no sentinel) behaves
  identically to M4: trust does not enforce, no regressions.
- Unlock suppresses only `trust.unsigned`. Mismatch and
  untrusted-signer remain unsuppressible (negative test).
- `MockSigner` unit tests cover the `Signer`/`Verifier` interface;
  CI fixture tests exercise the real `ssh-keygen` subprocess path.
- `/verify` passes; `warden scan .` exits 0 with the new
  `suppressed: …` line accounting for any trust suppressions.

**Demo command:** `bun packages/cli/src/index.ts trust sign CLAUDE.md && bun packages/cli/src/index.ts trust verify CLAUDE.md`

---

## M6 — Claude Code PreToolUse hook adapter ✅

**Landed:** see `git log --grep="feat(hooks-claude): M6"`.
Design: `docs/DECISIONS/0013-claude-code-hook-adapter.md`.
Threat: T5 added to `docs/THREAT_MODEL.md` in the same commit.

**Scope:** Installable hook that intercepts Claude Code tool calls and blocks credential-reading patterns. Ships as `warden hooks install claude`.

**In-scope:**
- Installer subcommand that writes/merges into `~/.claude/settings.json` and drops the runtime hook script.
- Runtime interceptor examining `tool_input.file_path` (for Read / Edit / Write / MultiEdit) and `tool_input.command` (for Bash) against a credential-path blocklist: `~/.ssh/id_*` (and `*_rsa` / `*_ed25519` / `*_ecdsa` siblings), `~/.aws/credentials`, `~/.aws/config`, `.env`, `.env.*` (excluding `*.example` / `*.sample` / `*.template`), wallet files (`*.wallet`, `wallet.json`, `mnemonic*`, `seed.txt`), GPG private keyring (`~/.gnupg/private-keys-v1.d/**`, `~/.gnupg/secring.gpg`), `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`. Public-half files (`.pub`, `~/.ssh/config`, `known_hosts`, `authorized_keys`) and template files (`*.example`, `*.sample`, `*.template`) are explicit carve-outs.
- Three credential rules in `packages/rules/src/data/credentials.ts`, all citing T5: `hooks.credential-file-read` (path-based), `hooks.credential-shell-read` (Bash + read-verb), `hooks.credential-pipe-network` (Bash + egress verb).
- Allowlist override via `.warden/hooks/allow.toml` for explicit per-project exceptions. Schema mirrors `manifest.toml` (`schema = "v1"`, `[[allow]]` blocks, `reason` required).
- CLI surface: `warden hooks install claude [--force]` and `warden hooks run claude [--json-output]`.

**Out-of-scope:** Cursor / Cline / Aider adapters (separate milestones, not numbered yet). Network egress blocking on socket APIs (deferred — process isolation; see T5 §"Warden does NOT detect"). Process-level isolation (out of Warden's scope; would require an EDR). Live secret detection in arbitrary file content (gitleaks / trufflehog territory).

**Acceptance criteria:**
- Installer is idempotent (running twice produces the same `settings.json` and the same wrapper script — covered by `install.test.ts → "is idempotent"`).
- Fixture: a synthetic Claude tool-call JSON requesting `~/.ssh/id_rsa` is blocked with exit 2 and a `warden: blocked by hooks.credential-file-read …` stderr message (covered by `run.test.ts → "Read ~/.ssh/id_rsa → exit 2"`).
- Allowlist fixture: a project with `.warden/hooks/allow.toml` permitting one path lets it through (covered by `interceptor.test.ts → "allow.toml entry permits the otherwise-blocked path"` and `run.test.ts → "allowlist override … lets the call through"`).
- `/verify` passes (310 tests across 25 files); `warden scan .` exits 0.

**Demo command:** `echo '{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}' | bun packages/cli/src/index.ts hooks run claude`

---

## Beyond M6 (post-MVP, no commitment)

- Cursor / Cline / Aider / Windsurf hook adapters.
- Layer 3: `warden ioc sync` (OSV + curated IOC feeds, offline-cacheable).
- Layer 3: `warden report --aibom` (CycloneDX AI Bill of Materials generation).
- Layer 3: lockfile-drift detection for Shai-Hulud-style resurrections.
- Pro / Team / Enterprise tier code (separate private repo).
- Rule-pack signing infrastructure.
- VS Code extension surfacing findings inline.

Each becomes its own milestone with the same template the day it gets prioritized.
