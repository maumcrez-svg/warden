# Warden — Roadmap

**Status:** Draft, M3
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

## M4 — MCP config static analyzer 🟦

**Scope:** Parse `mcp.json` and equivalents **without spawning** any defined server. The flagship `warden scan --sandbox` capability.

**In-scope:**
- Parsers for: Claude Code MCP config, Cursor MCP config, generic `claude_desktop_config.json`.
- Static checks: stdio vs HTTP transport, command-path absoluteness, version-pin presence, environment-variable scope, declared tool-name patterns.
- Findings: severity-tiered (info / low / med / high), each with a cited rationale.
- Biome `noRestrictedImports` rule: the MCP parser package may not import `child_process`, `net`, `fs/promises#write*`, `node:dgram`.

**Out-of-scope:** Actually spawning servers to verify they match their config (this is the whole point of NOT doing it). Network reachability checks.

**Acceptance criteria:**
- Fixture pack: 1 minimal-correct config, 1 missing-version-pin config, 1 absolute-path-to-untrusted-binary config, 1 declares-network-egress-tool config.
- All four classified correctly.

**Demo command:** `warden scan tests/fixtures/mcp/ --json | jq '.findings[].severity' | sort | uniq -c`

---

## M5 — `warden trust` (signing) 🟦

**Scope:** `warden trust sign|verify|unlock` subcommands. GPG-based. Signatures stored next to the signed file under `.warden/trust/<filename>.sig`.

**In-scope:**
- `sign <file>` — detached signature using the configured GPG key.
- `verify <file>` — succeeds if a valid signature exists and matches a trusted key.
- `unlock <file>` — temporarily marks a file as "intentionally unsigned" with a reason string, for review workflows.
- Configuration: `.warden/trust/keys.toml` lists trusted key fingerprints with optional notes.
- CI-friendly: structured errors to stderr; non-zero exit on the unhappy path.

**Out-of-scope:** Generating the GPG key itself (see ADR 0003 — decision deferred). Threshold signatures. Sigstore / keyless signing (separate ADR, deferred).

**Acceptance criteria:**
- Round-trip: sign a `CLAUDE.md`, modify a byte, verify fails.
- `verify` on an unmodified signed file succeeds with 0 output and exit 0.

**Demo command:** `warden trust sign CLAUDE.md && warden trust verify CLAUDE.md`

---

## M6 — Claude Code PreToolUse hook adapter 🟦

**Scope:** Installable hook that intercepts Claude Code tool calls and blocks credential-reading patterns. Ships as `warden hooks install claude`.

**In-scope:**
- Installer subcommand that writes/merges into `~/.claude/settings.json` and drops the runtime hook script.
- Runtime interceptor examining `tool_input.file_path` (for Read) and `tool_input.command` (for Bash) against a credential-path blocklist: `~/.ssh/*`, `~/.aws/credentials`, `~/.aws/config`, `.env`, `.env.*`, wallet files (`*.wallet`, `wallet.json`, mnemonic files), GPG private keyring.
- Allowlist override via `.warden/hooks/allow.toml` for explicit per-project exceptions.

**Out-of-scope:** Cursor / Cline / Aider adapters (separate milestones, not numbered yet). Network egress blocking (deferred). Process-level isolation (out of Warden's scope; would require an EDR).

**Acceptance criteria:**
- Installer is idempotent (running twice produces the same `settings.json`).
- Fixture: a synthetic Claude tool-call JSON requesting `~/.ssh/id_rsa` is blocked with exit 2 and a stderr message.
- Allowlist fixture: a project with `.warden/hooks/allow.toml` permitting one path lets it through.

**Demo command:** `echo '{"tool_input":{"file_path":"~/.ssh/id_rsa"}}' | bun run packages/hooks-claude/src/index.ts`

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
