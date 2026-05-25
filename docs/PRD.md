# Warden — Product Requirements Document

**Status:** Draft, M0
**Owner:** TBD (placeholder — see ADR 0004)
**Last updated:** 2026-05-24

---

## 1. Problem

AI coding agents (Claude Code, Cursor, Cline, Aider, Windsurf, Codex CLI) ingest project-local context files (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, MCP configs, skills, rules) before executing tool calls. These files are treated as trusted instructions even when they originate from untrusted sources — cloned repos, npm packages, agent marketplaces, copy-pasted snippets.

A new class of supply-chain attack exploits this trust:

- **TrapDoor** (May 2026, reported by Socket) compromised 34 npm packages across 384+ versions, embedding zero-width Unicode codepoints in `.cursorrules` and `CLAUDE.md`. Visible text was benign; the invisible payload coerced agents into exfiltrating credentials, modifying lockfiles, and piping shell output to attacker infrastructure.
- **GlassWorm** — invisible Unicode in VS Code extensions with blockchain-based command-and-control.
- **Mini Shai-Hulud** — dormant package resurrection combined with stolen npm tokens.
- **CVE-2025-53773** — hidden prompt injection in PR descriptions hijacking GitHub Copilot.

(All four citations are recorded in `docs/THREAT_MODEL.md` under §"Citation Verification — Pending" and must be confirmed against primary sources before any detection rule references them as authoritative.)

Today there is no tool a developer can install in 30 seconds that:
- Runs locally and offline.
- Scans every context file an agent will read.
- Detects invisible Unicode, prompt-injection patterns, and suspicious MCP configurations.
- Refuses to spawn untrusted MCP servers in order to inspect them.

Enterprise platforms (Snyk Agent Security, Endor AURI, Cycode AI Guardrails) are arriving heavy, expensive, and SaaS-first. They are not the answer for a solo crypto dev who installs a Cursor extension at midnight and wonders, the next morning, why their wallet is drained.

---

## 2. Users (priority order)

### 2.1 Crypto / DeFi developers — primary persona
Using Claude Code or Cursor on Mac/Linux. Hold wallet keys, SSH keys to validator nodes, API keys with money attached. Primary TrapDoor target. Highest urgency, highest willingness to install on day one. **Primary persona for v1 marketing.**

### 2.2 AI-native indie devs and small studios
Ship with agents daily. Already feel exposed after TrapDoor / GlassWorm / Mini Shai-Hulud headlines. Want a defensible "yes" when asked "is this safe to use".

### 2.3 Mid-size dev shops (5–50 engineers)
No dedicated security team. Looking for a credible answer to "are we safe running Cursor on client code?" before legal asks.

Enterprise (>50 eng, dedicated SecOps) is **inbound only** once the OSS tool reaches critical adoption. Not a launch target.

---

## 3. Jobs to be Done

| When                                                | I want to…                                              | So that…                                                  |
|-----------------------------------------------------|---------------------------------------------------------|-----------------------------------------------------------|
| I clone a new repo                                  | Scan its context files before opening Cursor on it      | A poisoned `.cursorrules` never reaches my agent          |
| I update npm dependencies                           | Diff the context files that came in with the update     | I notice a resurrected dormant package                    |
| I install an MCP server                             | Statically inspect its config without spawning it       | An untrusted stdio server never executes on my machine    |
| I edit my own `CLAUDE.md`                           | Sign it so my agent only loads the verified version     | A tampered `CLAUDE.md` produces a visible warning         |
| I run Claude Code on a sensitive project            | Block the agent from reading `~/.ssh`, `~/.aws`, `.env` | A compromised context cannot exfiltrate credentials       |

---

## 4. Success Metrics

**M0–M3 (pre-traction):**
- Time from `npm i -g @warden-sh/cli` to first finding: < 60 seconds on a sample dirty repo.
- False-positive rate on the Anthropic Cookbook + top-50 starred AGENTS.md repos: < 2%.
- True-positive rate on the TrapDoor fixture set: 100%.

**M4–M6 (early adoption):**
- 1,000 GitHub stars within 90 days of HN launch.
- 100 weekly active CLI users (measured via opt-in `warden share-stats`, post-launch only, **never** in core).
- 3 published "Warden caught this" incident writeups by external users.

**Pricing-tier metrics (post-MVP):**
- Free-to-Pro conversion: target 2% of WAU.
- Team-tier MRR: not modeled in M0.

---

## 5. Scope

### 5.1 In Scope (MVP, M0–M6)
- Static scan of context files for invisible Unicode, bidi overrides, zero-width chars, Hangul filler, prompt-injection patterns.
- File walker that respects `.gitignore` and identifies agent-specific config formats.
- MCP config static analyzer (no spawning).
- GPG-based signing/verification of context files (`warden trust`).
- Claude Code PreToolUse hook adapter for blocking credential reads.
- Output formats: pretty terminal, JSON, SARIF 2.1.0.

### 5.2 Out of Scope (MVP)
- Runtime egress allowlisting (deferred to v2).
- Network-based threat-intel feeds (deferred to Layer 3, post-MVP).
- AI Bill of Materials generation (deferred to Layer 3).
- GUI / web dashboard.
- Hosted SaaS variant.
- LLM-based detection (the scanner is deterministic by design).
- Telemetry of any kind in the OSS core.

---

## 6. Pricing (documented, NOT implemented in MVP)

| Tier          | Price                         | Includes                                                                 |
|---------------|-------------------------------|--------------------------------------------------------------------------|
| **OSS Core**  | Free, MIT                     | All Layer 1 + Layer 2 features. Single-machine use. Community support.   |
| **Pro**       | $19 / developer / month       | Layer 3 (IOC feeds, AIBOM diff), signed rule packs, priority support.    |
| **Team**      | $49 / developer / month       | Pro + central policy distribution, shared trust roots, audit log export. |
| **Enterprise**| Custom                        | Team + SSO, on-prem feed mirror, contractual SLA, prioritized rule R&D.  |

Pricing is **not** implemented in MVP. The OSS Core is the only buildable artifact through M6. Pro/Team/Enterprise code lives in a separate private repo, created the day there is a first paying customer.

---

## 7. Distribution

Launch plan (post-M6, not in scope for this PRD revision):
- **Hacker News** launch post, timed to a fresh supply-chain incident.
- **X (Twitter)** thread by maintainer, technical breakdown of one detected attack.
- **Reddit:** r/ClaudeAI, r/cursor, r/LocalLLaMA, r/netsec.
- **PT-BR angle:** dedicated post on r/brasil and PT-BR Twitter for the LATAM crypto crowd (high concentration of TrapDoor-target users).
- **Install paths in launch material:** npm first, bunx second, curl-binary third.

No paid acquisition pre-launch. No press outreach until 500 stars.
