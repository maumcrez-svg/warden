# Warden — Threat Model

**Status:** Draft, M0
**Last updated:** 2026-05-24

This document defines what Warden defends against, how it detects each class of threat, and what it explicitly does **not** defend against. Every detection rule landed in `packages/rules/data/` must cite back to a threat documented here.

---

## In Scope — Threats Warden Detects

### T1 — TrapDoor: Invisible Unicode in agent context files

**Reported:** May 2026. Primary source: Socket. *Citation verification pending — see §"Citation Verification" below.*

**Vector:** 34 npm packages across 384+ versions shipped `.cursorrules` and `CLAUDE.md` files containing zero-width Unicode codepoints (Variation Selectors Supplement, Tag chars, bidi overrides). The visible Markdown read like normal project guidance; the invisible payload instructed the agent to read credential files, write modified lockfiles, or pipe shell output to attacker-controlled endpoints.

**Warden detects:**
- Codepoints in Variation Selectors Supplement (U+E0100–U+E01EF) above legitimate-use density thresholds.
- Tag chars (U+E0000–U+E007F) — essentially never legitimate in source files.
- Bidi override controls (U+202A–U+202E, U+2066–U+2069).
- Zero-width characters (U+200B, U+200C, U+200D, U+FEFF) above density thresholds.
- Hangul filler (U+3164) — historically abused for homoglyph attacks.

**Landed in:** M1 (planned). See `docs/ROADMAP.md`.

**Warden does NOT detect (and does not claim to):**
- Visible homoglyph attacks (Cyrillic 'а' vs Latin 'a') — deferred to a future "lookalike domain" rule pack.
- Steganography hidden in image alt-text rendered by the agent's preview pane.

---

### T2 — GlassWorm: Invisible Unicode in VS Code extensions

**Vector:** VS Code extensions shipped with invisible Unicode in their package manifests and command palette entries. Blockchain-based C2 channel for command retrieval.

**Warden detects:** Same Unicode patterns as T1, applied to `package.json`, `mcp.json`, and any Markdown surfaced to the agent.

**Landed in:** M1 (Unicode patterns) + M4 (MCP config analysis).

**Warden does NOT detect:**
- The blockchain C2 traffic itself (out of Warden's filesystem-only scope; would require an EDR).
- Compromised VS Code extension binaries (Warden does not analyze compiled extension code).

---

### T3 — Mini Shai-Hulud: Dormant package resurrection

**Vector:** Long-dormant npm packages republished under the same name with malicious content, exploiting trust accumulated by the original package. Coupled with npm token theft to bypass maintainer review.

**Warden detects (Layer 3, post-MVP):**
- Lockfile diff: packages unchanged for > 12 months that suddenly bump.
- AIBOM cross-reference: packages whose maintainer email or repo URL changed without a major version bump.

**Landed in:** Layer 3 (post-M6). Out of MVP scope.

**Warden does NOT detect:**
- The initial token-theft event (happens off the developer's machine).
- Packages compromised on first publish (no dormancy signal).

---

### T4 — CVE-2025-53773: Prompt injection in PR descriptions

**Vector:** Hidden prompt injection in GitHub PR descriptions consumed by GitHub Copilot. Reported under CVE-2025-53773. Full advisory details to be verified against NVD in M3 work.

**Warden detects (M3, planned):**
- Rule-based regex/heuristic match against known injection phrasing families — override-prior-context imperatives, "you are now {persona}" persona-shift prompts, ChatML role-control tokens (the `im_start`/`im_end` family), Llama 2 `INST` markers and `SYS` blocks, leading line-anchored `system` role prefixes — applied to any context file or git-supplied text Warden is asked to scan. Authoritative pattern text lives in `packages/rules/src/data/prompt-injection.ts`; the docs intentionally describe the families rather than reproduce the trigger strings so the docs themselves pass the dogfood scan.
- Severity-tiered: stylistic matches → low; verbatim known payloads → high.

**Landed in:** M3 (planned).

**Warden does NOT detect:**
- Novel zero-day injection phrasings not yet pattern-matched. Rule data is updated on a recurring cadence, not learned.

---

### T5 — Agent-tool credential exfiltration

**Vector:** The agent itself (Claude Code, Cursor, Cline, Aider) issues a `Read`-class or `Bash`-class tool call against a credential file or pipes its contents off the machine. The triggering instruction can come from a poisoned context file (T1/T2/T4 in transit), from a user message that the agent interprets too literally, or from a transitively-included MCP tool description. By the time the agent is about to call the tool, the file-at-rest detectors (T1-T4) have already passed; the only remaining choke point is the runtime hook surface.

The blast radius is high and the surface is small: `~/.ssh/id_*`, `~/.aws/credentials`, `~/.aws/config`, project-local `.env` / `.env.*`, GPG private keyring (`~/.gnupg/private-keys-v1.d/*`), and wallet/mnemonic files. None of these have any legitimate reason to be read by an AI coding agent on the *agent's* hot path — when a developer needs to inspect them, they do so themselves.

**Warden detects (M6, planned):**
- A `PreToolUse`-hook adapter that runs **before** the agent executes the tool call and inspects the structured tool input. For Claude Code the contract is the `PreToolUse` hook event documented at `https://docs.anthropic.com/en/docs/claude-code/hooks` (verified 2026-05-25). For other agents the adapters are separate milestones.
- A path-and-shell rule pack (`packages/rules/src/data/credentials.ts`, cites this T5) covering:
  - File-path matches: `~/.ssh/id_*`, `~/.ssh/*_rsa`, `~/.ssh/*_ed25519`, `~/.ssh/*_ecdsa`, `~/.aws/credentials`, `~/.aws/config`, `**/.env`, `**/.env.*` (excluding `*.example` and `*.sample`), `**/wallet.json`, `**/*.wallet`, `**/mnemonic*`, `~/.gnupg/private-keys-v1.d/**`, `~/.gnupg/secring.gpg`.
  - Shell-pattern matches: any of `cat|less|more|head|tail|grep|od|hexdump|xxd|base64|openssl` reading the above; `curl|wget` invoked against `file://` URLs pointing at credential paths; `scp|rsync|sftp` egressing them.
- An allowlist override at `.warden/hooks/allow.toml` for explicit, per-project exceptions (e.g., a project whose Bash workflows legitimately read `~/.aws/credentials` for an SDK test). The allowlist is opt-in and carries a `reason` field for review-time traceability — same governance posture as ADR 0010's payload-fixture markers.

**Landed in:** M6 (Claude Code adapter only). Cursor, Cline, and Aider adapters are deferred to post-M6 follow-ups.

**Warden does NOT detect:**
- Network egress not transiting `curl`/`wget`/`scp`/`rsync`/`sftp` — an agent that opens a TCP socket through a custom MCP tool to ship credentials sidesteps the shell-pattern layer. Detection of that path is process-level isolation, which is out of scope (the threat model's "Out of Scope" §"Kernel-level rootkits" applies the same logic — Warden is not an EDR).
- An agent that ignores its hook contract. The PreToolUse hook is a cooperative defense, not a kernel one; a fork of the agent binary or a compromised CLI can skip the hook entirely. Same trust assumption as `gh codeowner` or any other governance-by-convention layer.
- Credentials embedded in environment variables already loaded into the agent's process. Warden filters at the tool-call boundary, not at memory.

**Primary sources cited:**
- OWASP LLM02:2025 Sensitive Information Disclosure — `https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/` (verified 2026-05-25).
- TrapDoor (T1) and GlassWorm (T2) reports already cited above — both attack chains terminated in credential-file exfiltration.

---

## Out of Scope — Threats Warden Does NOT Defend Against

Stated explicitly to set honest expectations:

- **Network-layer attacks:** MITM on agent HTTPS, DNS hijacking, rogue Wi-Fi. Use a VPN or a network firewall.
- **Kernel-level rootkits:** anything below userspace. Use Linux audit, macOS XProtect, or commercial EDR.
- **Hardware attacks:** evil-maid, USB drop, supply-chain firmware. Out of any software-only tool's scope.
- **Compromised agent binaries:** if `claude`, `cursor`, etc. are themselves malicious, Warden cannot help — Warden runs after they are already executing on your machine.
- **Live LLM jailbreaks:** prompts crafted at inference time inside the model. Warden inspects files at rest, not in-flight tokens. Use a runtime guardrail (Llama Guard, etc.) if that is your threat.
- **Social engineering of the developer:** Warden cannot stop you from running `curl … | sh` from a Discord link.
- **Backdoors in Bun, Node, or TypeScript itself:** Warden trusts its own runtime. Pinning + lockfile + dep review (`packages/core` < 10 deps) is our mitigation; we do not pretend to detect such backdoors.

---

## Detection coverage and known limitations

Honest statement of what Warden's M1 detector catches, what it does not, and
where the boundaries are drawn intentionally. Coverage policy: ship the
catchable, document the gap, sequence the rest. Full derivation of
thresholds and severity tiers in `docs/DECISIONS/0005-unicode-detection-thresholds.md`.

### Confirmed coverage (M1)

- **TrapDoor (T1) carriers** — Tag chars (U+E0000–U+E007F) and Variation
  Selectors Supplement (U+E0100–U+E01EF). Tag chars fire on every
  occurrence; VS Supplement fires when per-input count > 16. Validated
  against 4 malicious fixtures under `tests/fixtures/trapdoor/`.
- **GlassWorm (T2) carriers** — same Unicode families as T1; the same rules
  apply once M2's file walker reaches `package.json` and `mcp.json`.
- **Trojan Source (CVE-2021-42574)** — Bidi override controls
  (U+202A–U+202E, U+2066–U+2069). Severity is **always HIGH, regardless of
  count**. The published PoCs reordered source with as few as two
  codepoints (RLO + PDF); count is not a proxy for risk for this family.
  Tag chars get the same treatment for the same reason: zero legitimate use
  in source.
- **Zero-width saturation** — ZWSP/ZWNJ/ZWJ/BOM (U+200B–U+200D, U+FEFF) when
  per-input count > 16. ZWJ in legitimate emoji sequences and a leading
  BOM stay well below the threshold.
- **Hangul Filler (U+3164)** — flagged at MEDIUM severity; homoglyph-adjacent
  rather than the central agent-instruction exfiltration vector.

### Known gaps (deliberately deferred)

These codepoints are documented Unicode-abuse carriers but are **not**
flagged in M1. They are sequenced, not ignored. Each will receive its own
threshold, fixtures, and threat-ID promotion (T5+) before shipping.

- **U+FE00–U+FE0F (Variation Selectors VS-1..16)** — VS-16 (U+FE0F) is the
  legitimate emoji presentation selector and is extremely common in normal
  text. Needs its own density calibration distinct from VS Supplement.
- **U+2060 (Word Joiner)** — has rare legitimate use in typography. Needs
  an empirical baseline before shipping.
- **U+180E (Mongolian Vowel Separator)** — reclassified in Unicode 6.3
  (2013); lost `Default_Ignorable_Code_Point` and is no longer treated as
  invisible by conformant renderers. Low observed attack frequency is
  downstream of this reclassification, not coincidence. Tracking only.
- **U+2061–U+2064 (Invisible mathematical operators)** — legitimate in
  LaTeX/mathjax content; needs a content-type gate.
- **Sub-threshold distributed payloads** — an attacker keeping per-file
  count ≤ 16 across many files defeats M1's absolute density rule. Relative
  density (`count/total > 0.02 AND count > 8`) is registered in ADR 0005 as
  the planned evolution, deferred until the post-M2 corpus is available.

### Severity policy at a glance

| Family                          | Mode    | Severity | Why                                                |
|---------------------------------|---------|----------|----------------------------------------------------|
| Tag chars                       | always  | high     | Zero legitimate use in source files.               |
| Bidi overrides                  | always  | high     | Two codepoints reorder code (Trojan Source PoC).   |
| Variation Selectors Supplement  | density | high     | Saturation is the attack signal.                   |
| Zero-width characters           | density | high     | Saturation is the attack signal.                   |
| Hangul Filler                   | always  | medium   | Homoglyph-adjacent; central rule pack lives elsewhere. |

### MCP-specific coverage and gaps

Warden's MCP static analyzer (M4) detects four structural categories:

- **Command pinning** (`mcp.command-not-pinned`) — package runners
  without an `@version` pin.
- **Suspicious binary paths**
  (`mcp.absolute-path-untrusted-binary`) — absolute paths outside
  system trust prefixes.
- **Network transport** (`mcp.http-transport-external`) — HTTP / SSE /
  streamable-http URLs that resolve to a non-loopback host.
- **Shell exec in args** (`mcp.shell-exec-command`) — `sh`/`bash`/
  `powershell` invoked with `-c`/`-Command` (arbitrary string
  execution).

Plus a defensive `mcp.invalid-json` so malformed configs stay visible
rather than silently dropping.

**Warden does NOT detect (and the gap is named):**

- **Runtime tool poisoning via the `tools/list` protocol response.**
  A malicious MCP server advertises a tool whose `description` field
  contains attack phrasing only when the agent calls `tools/list` at
  runtime. The description is never in the static config. Detecting
  this would require spawning the server, which is structurally
  incompatible with the no-exec invariant (`docs/ARCHITECTURE.md` §6
  and ADR 0011 §2). Out of scope.
- **Inline tool description injection as a dedicated MCP rule.**
  Some non-standard configs declare tool metadata inline. Warden does
  not have a dedicated MCP rule for description fields; coverage
  comes from `scanPromptInjection` and `scanUnicode` running on the
  raw JSON content (see `docs/ARCHITECTURE.md` §7 "Cross-category
  collateral scanning"). This is defense-in-depth by architecture,
  not by named rule. Promoting it to a dedicated rule is tracked in
  `docs/ISSUES.md` #004 and deferred until real attack data warrants
  the second tier.
- **Transport-tier differentiation between `stdio` / `sse` /
  `streamable-http`.** The current rule treats all three uniformly:
  any non-loopback URL fires HIGH. Refinement to allowlist-aware
  tiering depends on the `.warden.toml` config schema (v1.0). Tracked
  in `docs/ISSUES.md` #005.

See `docs/ISSUES.md` #003-#005 for full resolution paths.

### Self-defense against trusted contributors

Warden's broad-scope marker families (`rules-data`, `detector-test` —
see ADR 0010) assume that contributors with write access to
path-restricted directories are trusted. A malicious contributor with
write access can defeat broad-scope suppression by adding a new file
under a restricted path with a fresh marker (the
"new-file-plus-new-marker" subcase in ADR 0010 §"Open after M3.1").

This is the same trust model as `eslint-disable-next-line` or
`# noqa`: the tool is not a defense against your own committers.
Mitigations are **governance, not technical** — `.github/CODEOWNERS`
forces maintainer review on the path-restricted directories, and
`CLAUDE.md` §"What NOT to Touch Without Asking" tells AI agents to
ask before editing. Tightening to file-level allowlist or
pattern-aware suppression is tracked in `docs/ISSUES.md` #002 and
deferred until either a real attack scenario surfaces or M4 MCP
fixtures motivate new path restrictions.

---

## Citation Policy

Every detection rule in `packages/rules/data/` must include:
- The threat ID from this document (T1–T4, or a new Tn added here first).
- A primary-source URL (vendor advisory, CVE entry, security-firm report).
- The date the citation was verified by a human maintainer.

Rules without verified citations do not ship. "Just in case" rules are refused at PR review.

---

## Citation Verification — Pending

The following citations from the project bootstrap prompt are recorded here but **not yet independently verified by a maintainer**. They must be confirmed against primary sources before any detection rule in M1+ references them as authoritative:

- [ ] **TrapDoor (May 2026)** — Socket disclosure URL pending.
- [ ] **GlassWorm** — vendor advisory pending.
- [ ] **Mini Shai-Hulud** — incident report URL pending.
- [ ] **CVE-2025-53773** — NVD entry verification pending.

Verification tracking: TBD — open a tracking issue when the GitHub org is finalized (see ADR 0004).
