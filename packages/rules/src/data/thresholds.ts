// Density thresholds for Unicode codepoint families that have legitimate uses
// at low counts. A finding is emitted only when the total count of a family
// across a single input strictly exceeds its threshold.
//
// Derivation of 16 (full rationale in docs/DECISIONS/0005-unicode-detection-thresholds.md):
//   - Legitimate ceiling: 2 selectors/emoji (Unicode TR#51) × ≤ 8 emoji in a
//     "heavy" README = 16. Files at exactly 16 still pass (rule fires on >).
//   - Attack floor: "dozens" begins at ~24; TrapDoor's observed payloads are 50+
//     (Socket disclosure, May 2026). The first firing count (17) sits in the
//     defensive margin between legitimate ceiling and attack floor.
//
// Bidi overrides are NOT density-gated — see ADR 0005 §2: two codepoints
// (RLO + PDF) were sufficient in every Trojan Source PoC, so count is not
// a proxy for risk. That rule lives in unicode-ranges.ts with mode: 'always'.

export type UnicodeDensityKey = 'unicode.variation-selectors-supplement' | 'unicode.zero-width';

export const UNICODE_DENSITY_THRESHOLDS: Readonly<Record<UnicodeDensityKey, number>> = {
  'unicode.variation-selectors-supplement': 16,
  'unicode.zero-width': 16,
};
