# CLAUDE.md — Warden Project Context

This file is loaded by Claude Code at the start of every session inside this repo. Read it before touching anything.

---

## Identity & Mission

**Warden is a local firewall for AI coding agents.** It scans what an AI agent is about to read — `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, MCP configs, skills — and blocks what it should never run.

You are working on a security-critical OSS CLI. Discipline and correctness beat velocity. Default behavior: ask before assuming.

---

## Current Status

**Milestone:** M7 — Cursor hook adapter (complete). Next: Cline / Aider / Windsurf adapters, MCP-call runtime interception (cross-adapter), or post-MVP Layer 3 work — see `docs/ROADMAP.md` §"Beyond M7".

Authoritative source: `docs/ROADMAP.md`.

---

## Stack Constraints (LOCKED)

- **Runtime:** Bun (>= 1.1.0).
- **Language:** TypeScript (ES2022 target, strict mode, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`).
- **CLI framework:** `commander`. Not oclif, not yargs.
- **Lint + format:** Biome 1.9.4 only. Not ESLint, not Prettier.
- **Test:** Bun's built-in `bun:test`.
- **Markdown:** `remark` + `remark-frontmatter` when needed.
- **Source parsing:** `tree-sitter` only when a real AST is required. Pure string iteration for Unicode codepoint scanning.
- **License:** MIT for the OSS core.
- **Layout:** Bun workspaces monorepo (`packages/*`).

Adding a dependency requires: (a) justification in the PR description, (b) `--exact` pin, (c) review of the dep's own dep tree, (d) cited use case in the threat model if it's a parser. Target dep count for `packages/core`: under 10.

The decision to use Bun over Rust is recorded in `docs/DECISIONS/0001-bun-over-rust.md`. Read it before proposing a runtime change.

---

## Repo Layout

```
warden/
├── CLAUDE.md                       (this file)
├── README.md
├── LICENSE                         (MIT)
├── .gitignore
├── package.json                    (Bun workspace root)
├── biome.json
├── tsconfig.json
├── .claude/
│   ├── settings.json               (hooks wiring)
│   ├── hooks/                      (executable bash, deterministic enforcement)
│   │   ├── pre-commit-secrets.sh
│   │   ├── pre-write-paths.sh
│   │   └── post-edit-format.sh
│   └── commands/
│       ├── milestone.md            (/milestone <N>)
│       └── verify.md               (/verify)
├── docs/
│   ├── PRD.md
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md                  (the source of truth for what to build next)
│   └── DECISIONS/                  (ADRs, append-only)
│       ├── 0001-bun-over-rust.md
│       ├── 0002-domain-name.md
│       ├── 0003-trust-gpg-key-deferred-to-m5.md  (resolved by 0012)
│       ├── 0004-github-org-placeholder.md
│       └── 0012-m5-trust-signing.md  (and 0005–0011 between)
├── packages/
│   ├── cli/                        (warden binary entry)
│   ├── core/                       (scanner engine, pure functions)
│   ├── rules/                      (threat rule data only — no logic)
│   ├── hooks-claude/               (Claude Code PreToolUse adapter)
│   └── hooks-cursor/               (Cursor adapter)
└── tests/
    └── fixtures/                   (one folder per threat scenario)
```

Domain `warden.dev` and org `warden-sh` are placeholders. See ADRs 0002 and 0004.

---

## Commit Conventions

- **Conventional Commits** required: `feat(scope): subject`, `fix(scope): subject`, `chore(scope): subject`, `docs(scope): subject`, `test(scope): subject`.
- Subject line: imperative, no trailing period, under 72 chars.
- Sign release commits (`git commit -S`). Day-to-day commits don't need GPG; releases do.
- One milestone = one commit (squash before merge if necessary).
- Body explains the *why* and cites the threat ID (T1–T4 from `docs/THREAT_MODEL.md`) for any detection-rule change.

---

## Verification Policy

Every PR that changes scanner behavior requires:
1. Unit test in the package that owns the change.
2. Fixture file under `tests/fixtures/<threat-name>/` showing the threat detected OR the benign case passed cleanly.
3. One-line CLI demo in the PR description proving the change end-to-end.

`/verify` (see `.claude/commands/verify.md`) runs the full check — lint, tests, dogfood scan — and must pass before any commit is created.

---

## What NOT to Touch Without Asking

- `packages/rules/data/*` — threat rule data. Changes production detection behavior. Always paired with a fixture and a primary-source citation.
- `tests/fixtures/*` — golden files. Renaming or deleting silently breaks coverage of a real-world threat.
- `docs/DECISIONS/*` — ADRs are append-only. Status flips ("Accepted" → "Superseded by ADR-N") are fine; rewriting history is not.
- `.claude/settings.json` and `.claude/hooks/*` — changing these changes the security posture of the dev environment itself.
- `.warden/trust/*` — trust manifest and `allowed_signers`. Edits change which keys can sign agent context files (ADR 0012 §5). Trust-root substitution is the M5 mirror of the M3.2 `new-file-plus-new-marker` cenário — CODEOWNERS forces maintainer review, but PR authors should still ask before editing.
- `.warden/hooks/allow.toml` — credential-blocklist exceptions for the M6 hook adapter (ADR 0013 §6). Same trust-of-committer property as `.warden/trust/allowed_signers`; CODEOWNERS forces maintainer review, but PR authors should still ask before editing.

---

## Style

- Biome is the only style authority. The post-edit hook auto-formats. Do not negotiate style.
- No emoji in source files (rules, tests, code, CLI output). No decorative ASCII banners. No marketing copy in code comments.
- Comments explain *why*, not *what*. Citation-only comments (CVE numbers, Unicode block names, threat report URLs) are encouraged.
- Error messages: precise, no chatty wrapping, no "oops".
- Successful operations: silent (exit 0, no stdout) unless explicitly asked for output.

---

## Anti-Patterns (Refuse)

- Do **not** add telemetry that phones home. Ever. In the OSS core.
- Do **not** add background network calls in the core scanner. The scanner is deterministic and offline.
- Do **not** add LLM calls inside the scanner. Detection is rule-based by design.
- Do **not** add a "just in case" rule without a fixture and a cited threat.
- Do **not** commit without running `/verify`.
- Do **not** bypass hooks with `--no-verify`, `--no-gpg-sign`, or equivalent.
- Do **not** include hand-rolled real secrets in fixtures meant to demo secret detection. Use the conventional fake formats (`AKIAIOSFODNN7EXAMPLE`, etc.).
- Do **not** spawn untrusted MCP servers to introspect them. The MCP analyzer is *static-only* — see `docs/ARCHITECTURE.md` §6.

---

## Session Discipline

- **One milestone per session.** Open fresh for each `/milestone N`.
- **Compact ruthlessly.** At ~50% context, `/clear` and resume from the relevant `docs/ROADMAP.md` section.
- **Repo is the source of truth, chat is not.** Decisions go to `docs/DECISIONS/`; requirements to `docs/PRD.md`.
- **Ask, don't assume.** Ambiguity is a question, not an invention.
- **Reject scope creep in the same turn it appears.** Defer it to a new milestone.

---

## When You're Stuck

- Detection rule is firing on benign content → add the benign case as a new fixture under `tests/fixtures/<rule>/benign-*`, then tune the rule's threshold in `packages/rules/data/thresholds.ts`.
- A new threat doesn't fit the existing rule taxonomy → propose a new threat ID (T5+) in `docs/THREAT_MODEL.md` first, then build the rule.
- A milestone feels too big → it is. Split it in `docs/ROADMAP.md` and call out the split in the PR.
