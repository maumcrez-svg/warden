# ADR 0005 — Unicode detection thresholds and coverage scope

**Status:** Accepted
**Date:** 2026-05-24
**Deciders:** M1 implementation review

---

## Context

M1 ships `scanUnicode(input: string): UnicodeFinding[]` in `packages/core`,
backed by codepoint-range data and density thresholds in `packages/rules`.
The density thresholds are a single magic number (`16`) for both the
Variation Selectors Supplement family and the Zero-width family. The number
was justified informally in the M1 review but never written down. This ADR
fixes that and records the scope decisions made along the way.

Primary threats covered:

- **T1 — TrapDoor** (Socket disclosure, May 2026): invisible Unicode payloads
  in `CLAUDE.md` and `.cursorrules`, primarily Tag chars and saturated
  Variation Selectors Supplement.
- **T2 — GlassWorm**: same codepoint families in VS Code extension manifests.
- **CVE-2021-42574 "Trojan Source"** (Boucher & Anderson, 2021,
  <https://trojansource.codes/>): bidi-override reordering attacks.
  Two codepoints (RLO + PDF) were sufficient in every published PoC.

---

## Decision

### 1. Density threshold of 16 for VS Supplement and Zero-width

Both `unicode.variation-selectors-supplement` and `unicode.zero-width`
fire only when the per-input count exceeds **16**.

Numerical derivation:

| Quantity                                        | Value | Source                                                          |
|-------------------------------------------------|-------|-----------------------------------------------------------------|
| Selectors per legitimate emoji glyph            | 1–2   | Unicode TR#51 (Emoji)                                           |
| Emoji glyphs in a "heavy" README                | ≤ 8   | Empirical baseline from popular OSS READMEs                     |
| Legitimate ceiling = 2 × 8                      | 16    | Product                                                         |
| Lower edge of "dozens" (attack baseline)        | ≈ 24  | Common English usage of "dozens" (≥ 2 × 12)                     |
| TrapDoor observed payload size                  | 50+   | Socket disclosure, May 2026                                     |

A file with the maximum reasonable legitimate count (16) lands exactly at
the threshold — and the rule fires on **strictly greater than**, so 16 still
passes. The first count that fires (17) is still below the lower edge of
the attack regime (~24), leaving a defensive margin. TrapDoor-grade payloads
(50+) clear the threshold by 3×.

Zero-width chars get the same threshold by the same construction:
ZWJ family-emoji sequences use up to ~7 ZWJs per family; 16 covers two such
sequences plus headroom, while TrapDoor-style saturation easily exceeds it.

Both numbers live in `packages/rules/src/data/thresholds.ts` and may be
tuned without code changes; the inline comment there points at this ADR.

### 2. Bidi overrides are always HIGH severity, count-independent

`unicode.bidi-overrides` is `mode: 'always'`, not density-gated. **Count
is not a proxy for risk here.** The Trojan Source paper demonstrated full
source-code reordering with as few as 2 codepoints (one RLO, one PDF). A
single bidi override in a context file already meets the threshold of
"reviewer-visible text disagrees with parsed text", which is the attack.

The same logic applies to Tag chars (U+E0000–U+E007F): legitimate use in
source files is effectively zero, so any occurrence is reported.

### 3. Hangul Filler is MEDIUM, not HIGH

`unicode.hangul-filler` (U+3164) is reported at `medium`. Reason: its
documented abuse is homoglyph/IDN spoofing (Unicode TR#36), which is
adjacent to Warden's threat model but not the central agent-instructions
exfiltration vector. Flagging at high would crowd out the T1/T2 signals in
a reporter that sorts by severity. A future "lookalike domain" rule pack
(deferred, see THREAT_MODEL §Out of scope) is the proper home for
homoglyph severity tuning.

### 4. Out-of-scope codepoints, deliberately deferred

The following codepoints are **known carriers** for the same family of
attacks but are not flagged in M1:

| Codepoint(s)       | Name                            | Why deferred                                                                                  |
|--------------------|---------------------------------|-----------------------------------------------------------------------------------------------|
| U+FE00–U+FE0F      | Variation Selectors (VS-1..16)  | Legitimate emoji presentation selector (VS-16) is extremely common; needs its own threshold.  |
| U+2060             | Word Joiner                     | Rare-but-legitimate in typography; needs an empirical density baseline before shipping.       |
| U+180E             | Mongolian Vowel Separator       | Obscure; low observed attack frequency. Track but do not pre-emptively flag.                  |
| U+2061–U+2064      | Invisible mathematical operators| Legitimate in LaTeX/mathjax-style content; needs a content-type gate.                         |

These will be tracked in `docs/THREAT_MODEL.md` under
"Detection coverage and known limitations" and revisited in a future
threat-ID bump (T5+) with their own fixtures and thresholds. They are not
ignored — they are sequenced.

### 5. Future evolution: relative-density mode (deferred)

The current density rule is absolute (`count > 16`). An attacker who knows
the threshold can stay just below it (`count = 16`) and split the payload
across multiple files, evading per-file detection. A more robust formulation
is **relative density**:

```
fire if (count / total_codepoints) > 0.02 AND count > 8
```

This requires a sub-threshold absolute floor (8) to avoid flagging tiny
files with one stray codepoint, and a ratio (2%) calibrated against the
TrapDoor corpus. We are not shipping this in M1 because:

1. The Socket TrapDoor sample sizes have not been independently verified
   yet (see `docs/THREAT_MODEL.md` §Citation Verification — Pending).
2. The relative formulation requires a second-pass corpus calibration that
   is a milestone of its own, not a one-line constant change.
3. It is honest to ship the simple rule first and tune from real false-
   positive reports than to over-engineer pre-emptively.

Deferred to a future milestone tied to T5 (sub-threshold distributed
payload detection). Tracked here so a future maintainer knows the option
existed and why it was not taken yet.

---

## Consequences

**Positive:**
- The number `16` is now defensible. Reviewers can audit the derivation
  against the cited primary sources without re-deriving it from scratch.
- Severity policy is no longer implicit. A finding's severity reflects the
  attack semantics of its codepoint family, not just its count.
- Known limitations are written down. We are honest about what M1 does
  and does not catch.

**Negative:**
- A sub-threshold distributed attack (≤ 16 codepoints per file, spread
  across many files) is undetected by M1. Acceptable risk for MVP given
  that the M2 file walker plus future relative-density rule will close
  the gap; calling it out explicitly here so it does not get forgotten.
- The VS-1..16 gap means a TrapDoor variant that uses the original VS
  block instead of VS Supplement bypasses M1. Likelihood: low (VS
  Supplement is more efficient per byte), but non-zero.

---

## Revisit triggers

Reopen this ADR if any of:

- A real-world TrapDoor variant ships with a sub-16 per-file count
  distributed across multiple files (sub-threshold attack realized).
- A user reports a false positive on a file with ≤ 16 codepoints of either
  density family that is genuinely legitimate.
- VS-1..16, Word Joiner, or Mongolian VS becomes a documented carrier in
  a published incident — promote to in-scope and add fixtures.
- Citation verification of the Socket TrapDoor sample completes and the
  observed payload size is materially different from the 50+ assumed here.

Otherwise: leave the threshold at 16 and the severities as written.
