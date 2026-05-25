# Warden

> A local firewall for AI coding agents. Scans what your agent is about to read, blocks what it should never run.

**Status:** `M2 — File walker + format detection` · MIT licensed · **Not yet installable**

Warden is a local, offline static analyzer for context files consumed by AI coding agents (Claude Code, Cursor, Cline, Aider, Windsurf, Codex CLI). It flags invisible Unicode, prompt-injection patterns, and suspicious MCP configurations *before* your agent loads them — and refuses to spawn untrusted MCP servers in order to inspect them.

---

## Install

> The commands below are **placeholders**. Warden is not yet published. Package scope `@warden-sh` and domain `warden.dev` are provisional — see `docs/DECISIONS/0002-domain-name.md` and `docs/DECISIONS/0004-github-org-placeholder.md`. Track progress in [`docs/ROADMAP.md`](docs/ROADMAP.md).

```sh
# 1. npm (recommended once published)
npm i -g @warden-sh/cli

# 2. bunx (zero-install)
bunx warden scan .

# 3. Single binary (no Node/Bun required)
curl -fsSL https://warden.dev/install.sh | sh
```

---

## Quick Start

```sh
warden scan .
```

Scans the current directory for context files (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `mcp.json`, etc.), reports findings to stdout, and exits non-zero on any high-severity hit. Use `--json` or `--sarif` for machine-readable output.

---

## Threats Detected

| Threat                                    | Milestone | Notes                                                                |
|-------------------------------------------|-----------|----------------------------------------------------------------------|
| Invisible Unicode (TrapDoor, GlassWorm)   | M1        | Variation selectors, tag chars, bidi overrides, zero-width, Hangul filler |
| Agent-config format detection             | M2        | `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `mcp.json`, skills, …      |
| Prompt-injection patterns                 | M3        | Rule-based, cited, severity-tiered. No LLM in the loop.              |
| Suspicious MCP configs                    | M4        | Static parse only — Warden never spawns the servers it inspects.     |
| Signed-context drift                      | M5        | `warden trust sign\|verify\|unlock` (GPG-based).                     |
| Credential-read interception              | M6        | `warden hooks install claude` — PreToolUse blocker.                  |

Full threat model with citations: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Why Warden

Enterprise AI-security platforms (Snyk Agent Security, Endor AURI, Cycode AI Guardrails) are arriving heavy, expensive, and SaaS-first. Warden is the opposite: local, OSS, installable in 30 seconds, sandbox-by-default. Think *ESLint for agentic context security*.

Two technical differentiators that aren't marketing:

1. **`warden scan --sandbox` (default).** The MCP analyzer parses configurations statically. It never `child_process.spawn`s the declared servers — a meaningful departure from spawn-to-introspect tools.
2. **`warden trust sign CLAUDE.md`.** GPG-signed context files. The agent loads only verified context. Drift is a warning or a block depending on policy. This is the `git commit -S` of context engineering.

---

## Project Layout

```
.claude/    hooks + slash commands enforcing project discipline
docs/       PRD, threat model, architecture, roadmap, ADRs
packages/   cli · core · rules · hooks-claude · hooks-cursor
tests/      fixtures, one folder per threat scenario
```

See [`CLAUDE.md`](CLAUDE.md) for repo conventions and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design.

---

## Contributing

Not yet open for external PRs (pre-M2). Once M2 ships, every detection-rule PR must include a fixture and cite a primary-source threat report. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §"Citation Policy".

---

## License

MIT. See [`LICENSE`](LICENSE).
