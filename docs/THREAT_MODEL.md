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
