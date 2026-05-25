# ADR 0009 — JSON output: v1 → v2 for prompt-injection findings

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M3 implementation review

---

## Context

M3 adds a second class of findings (prompt-injection) to the
`scanPath()` pipeline. The per-file `FileReport` shape now carries both
`findings: UnicodeFinding[]` and `promptInjectionFindings:
PromptInjectionFinding[]`. The summary counts on `ScanReport`
(`findingCount`, `highCount`, `mediumCount`, `lowCount`) now reflect
totals across both finding classes.

The JSON reporter contract `warden/scan/v1` was frozen by ADR 0007:
"The fields in this version are frozen for the lifetime of v1; additive
fields require v2." Both of the M3 changes above are additive — a new
field appears on each file object, and the meaning of the summary
counts widens — so the contract requires a bump.

---

## Decision

### 1. Version string flips to `warden/scan/v2`

`toJsonReport()` emits `version: 'warden/scan/v2'`. The leading
discriminator is the contract consumers branch on; v1 consumers see the
new discriminator and can either upgrade or refuse the payload, per the
strategy already documented in ADR 0007 §1.

### 2. Diff between v1 and v2

Additive only — no field is renamed or removed:

| Change                                              | Where                                        |
|-----------------------------------------------------|----------------------------------------------|
| `promptInjectionFindings: PromptInjectionFinding[]` | new field on each entry in `files[]`         |
| `findingCount` now sums both finding classes        | `ScanReport` summary                         |
| `highCount` / `mediumCount` / `lowCount` likewise   | `ScanReport` summary                         |

The `findings: UnicodeFinding[]` field is unchanged. v1 consumers that
read only `findings` continue to see exactly the Unicode findings they
saw before; they will simply miss prompt-injection data and may
disagree with summary totals.

### 3. Why not a separate v1.1 or a sidecar payload

Considered and rejected:

- **Sidecar field at the top level** (`promptInjectionFiles[]` alongside
  `files[]`). Forces JSON consumers to cross-reference two arrays by
  path. Per-file grouping is the entire reason `files[]` exists.
- **Keep v1 and emit prompt-injection only via SARIF.** Splits the
  output contract across formats; SARIF and JSON should report the same
  findings, just shaped differently.
- **Stay on v1 and treat the per-file extension as a "tolerated"
  additive change.** Violates the freeze rule recorded in ADR 0007 §1
  and removes the contract's value.

### 4. SARIF and pretty are unaffected by version semantics

SARIF has no Warden-defined version field; its version is the SARIF
version itself (2.1.0). Pretty output is not a stable contract — see
ADR 0007 §1. Both reporters now surface prompt-injection findings
inline alongside Unicode findings; no consumer-visible "v1 / v2"
distinction exists for either.

---

## Consequences

**Positive:**
- Consumers get prompt-injection data through the same JSON shape, in
  the same per-file location they already parse for Unicode findings.
- The bump is mechanical: switch the version literal, add a field, no
  reshape. Tests assert the new discriminator and the populated field.
- The ADR-0007 procedure for evolving the JSON contract is exercised
  once, which sets the precedent for M4+ additions (MCP-config findings
  almost certainly motivate a v3 bump under the same procedure).

**Negative:**
- v1 consumers must update. The discriminator makes the break loud, not
  silent, which is the design intent.
- Summary counts (`findingCount` etc.) now mix two finding classes.
  Consumers that want per-class counts must enumerate the per-file
  arrays. Adding `unicodeHighCount` / `promptInjectionHighCount`
  rollups is deferred until a real consumer asks.

---

## Revisit triggers

Reopen this ADR if any of:

- A consumer reports that mixed summary counts are unworkable. The
  right response is to add per-class rollup fields (`unicodeFindingCount`,
  `promptInjectionFindingCount`, ...) in v3, not to split the per-file
  shape.
- M4 (MCP-config findings) lands and prefers a different addition shape
  than this per-file extension. If so, document the divergence here and
  in the new ADR; the v2 shape is the precedent.
- The JSON v1 → v2 transition causes a real-world consumer breakage
  that could have been mitigated by emitting `version: 'warden/scan/v1'`
  with a sidecar field instead. (We do not currently believe this is
  likely; the freeze rule exists precisely to make the break loud.)

Otherwise: leave the contract at v2 with the additive shape as written.
