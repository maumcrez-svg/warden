// Density thresholds for Unicode codepoint families that have legitimate uses
// at low counts. A finding is emitted only when the total count of a family
// across a single input exceeds its threshold.
//
// Legitimate use baselines:
//   - Variation Selectors Supplement: 1–2 selectors per emoji glyph.
//   - Zero-width chars: 1–2 per emoji ZWJ sequence; occasional BOM at file start.
//
// Attack baselines (TrapDoor / GlassWorm): dozens to hundreds per file.

export type UnicodeDensityKey = 'unicode.variation-selectors-supplement' | 'unicode.zero-width';

export const UNICODE_DENSITY_THRESHOLDS: Readonly<Record<UnicodeDensityKey, number>> = {
  'unicode.variation-selectors-supplement': 16,
  'unicode.zero-width': 16,
};
