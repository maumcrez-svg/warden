# Warden

> Local firewall for AI coding agents.

Warden is an offline static analyzer for the context files AI coding agents read before they act — `CLAUDE.md`, `.cursorrules`, `AGENTS.md`, `mcp.json`, skills, lockfiles. It flags invisible Unicode payloads, prompt-injection patterns, suspicious MCP configurations, runtime credential-read attempts, and known-vulnerable dependencies. The scanner is pure-offline by design: no telemetry, no LLM in the loop, no spawning of untrusted MCP servers to inspect them.

The motivation is not theoretical. **TrapDoor** (May 2026, disclosed by [Socket Security](https://socket.dev/blog)) embedded hundreds of variation-selector codepoints in instructional markdown to smuggle hidden directives past human review while remaining fully visible to language models. **GlassWorm** (October 2025, [disclosed by Koi Security](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace)) used the same Unicode-tag-character technique against VS Code extensions on the OpenVSX marketplace, with 35,800+ compromised installations and Solana-blockchain-based C2 infrastructure. The **Mini Shai-Hulud** worm (May 2026, [attributed to threat actor TeamPCP](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)) compromised hundreds of npm and PyPI packages through self-replicating worm logic that hijacked OIDC tokens in GitHub Actions release pipelines — even packages with valid SLSA Build Level 3 provenance. The common thread: the attack surface is the bytes an agent or extension reads before it executes — bytes humans rarely audit at the codepoint level.

Warden treats those bytes as untrusted input and runs deterministic checks before the agent does. The scanner is built around three invariants: every detection rule cites a primary source; the scanner never calls the network; rules are pure functions over input bytes, not LLM judgments.

---

## Threats detected

| Threat                                             | Milestone | What it catches                                                                                          |
|----------------------------------------------------|-----------|----------------------------------------------------------------------------------------------------------|
| Invisible Unicode (TrapDoor / GlassWorm class)     | M1        | Variation selectors, tag characters, bidi overrides, zero-width chars, Hangul filler — with density thresholds |
| File walking + format detection                    | M2        | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`, `.aider.conf.yml`, Copilot instructions, skills, generic markdown |
| Prompt-injection patterns                          | M3        | Override-prior-context imperatives, persona-shift jailbreaks, ChatML/Llama role tokens, leading `system:` prefixes — rule-based, each rule cited |
| Suspicious MCP configurations                      | M4        | Static parse of `mcp.json` and equivalents — version-pin absence, untrusted binary paths, shell-exec commands, network-egress tool declarations. Warden never spawns the configured servers. |
| Signed context drift                               | M5        | `warden trust sign\|verify\|list\|unlock` — SSH signatures via `ssh-keygen -Y sign`, no embedded crypto. Catches tampering between sign and scan. |
| Runtime credential reads (Claude Code)             | M6        | PreToolUse hook adapter blocking Read/Edit/Bash attempts against `~/.ssh/id_*`, `~/.aws/credentials`, `.env`, wallet files, kubeconfig, npmrc, pypirc, netrc, GPG private keyrings |
| Runtime credential reads (Cursor 1.7+)             | M7        | `beforeReadFile` + `beforeShellExecution` adapter — same rule pack as M6, Cursor's native hook contract  |
| Supply-chain IOC sync (OSV.dev)                    | M8        | `warden ioc sync\|status\|lookup\|verify` — local cache of OSV vulnerability data, queryable offline. The first network-bound subcommand; scanner stays offline-pure. |

Full threat model with citations: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Quick start

> Warden is not yet published to a package registry. Commands below are the intended surface; for now, run the CLI directly via `bun packages/cli/src/index.ts` from a clone of this repo.

```sh
# Scan a directory for agent-context threats.
bunx warden scan .

# Sign a context file so drift becomes a finding.
warden trust sign CLAUDE.md

# Sync the OSV vulnerability cache (manual, offline-pure thereafter).
warden ioc sync

# Install the runtime credential-read hook for your agent.
warden hooks install claude
warden hooks install cursor
```

Output is silent on success (exit 0). Findings print to stdout with file-grouped severity and exit non-zero. Use `--json` or `--sarif` for machine-readable output.

---

## Status

**Active development.** M8 complete — 393 tests passing, dogfood scan clean. **M9** (lockfile parsing + `supply-chain.osv-known-vulnerability` findings wired into `warden scan`) in progress; design recorded in [`docs/DECISIONS/0016-m9-lockfile-scanner.md`](docs/DECISIONS/0016-m9-lockfile-scanner.md).

Roadmap and milestone history: [`docs/ROADMAP.md`](docs/ROADMAP.md).

Not yet open for external PRs. The MVP is on a single-maintainer track; that changes after M9 lands and the contribution conventions in [`CLAUDE.md`](CLAUDE.md) are formalized in a `CONTRIBUTING.md`.

---

## Documentation

- [`docs/PRD.md`](docs/PRD.md) — product requirements and scope
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — threat IDs T1–T6 with mitigations and named gaps
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — package boundaries, hot/cold path, network policy
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones M0–M8 (done) and M9+ (in flight)
- [`docs/DECISIONS/`](docs/DECISIONS) — architectural decision records, append-only
- [`docs/ISSUES.md`](docs/ISSUES.md) — tracked open issues with severity and revisit triggers
- [`CLAUDE.md`](CLAUDE.md) — repo conventions (loaded by Claude Code at session start)

---

## License

MIT. See [`LICENSE`](LICENSE).
