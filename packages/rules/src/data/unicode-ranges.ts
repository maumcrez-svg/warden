// Unicode codepoint ranges abused by TrapDoor (T1) and GlassWorm (T2).
//
// T1 — TrapDoor: 34 npm packages across 384+ versions shipped CLAUDE.md and
//      .cursorrules containing invisible Unicode that instructed the agent to
//      exfiltrate credentials. Primary source: Socket disclosure, May 2026.
// T2 — GlassWorm: VS Code extensions shipped invisible Unicode in package
//      manifests and command palette entries. Same codepoint families as T1.
//
// Each range is annotated with its Unicode block name and the reason it is
// dangerous in agent context files. Density-mode ranges (variation selectors,
// zero-width characters) are also tracked against thresholds.ts so the rule
// does not fire on legitimate emoji ZWJ sequences.

export type UnicodeRangeMode = 'always' | 'density';
export type UnicodeSeverity = 'low' | 'medium' | 'high';

export type UnicodeRange = {
  readonly id: string;
  readonly threatIds: ReadonlyArray<'T1' | 'T2'>;
  readonly name: string;
  readonly citation: string;
  readonly ranges: ReadonlyArray<readonly [number, number]>;
  readonly mode: UnicodeRangeMode;
  readonly severity: UnicodeSeverity;
};

export const UNICODE_RANGES: ReadonlyArray<UnicodeRange> = [
  {
    id: 'unicode.tag-chars',
    threatIds: ['T1', 'T2'],
    name: 'Tag chars',
    // Unicode block "Tags" (U+E0000–U+E007F). These were deprecated for their
    // original use and have no legitimate role in source code or documentation.
    // TrapDoor used them as the primary invisible carrier for agent payloads.
    citation: 'Unicode block "Tags" (U+E0000–U+E007F); abused by TrapDoor (Socket, May 2026)',
    ranges: [[0xe0000, 0xe007f]],
    mode: 'always',
    severity: 'high',
  },
  {
    id: 'unicode.bidi-overrides',
    threatIds: ['T1', 'T2'],
    name: 'Bidi overrides',
    // Explicit bidirectional override controls. CVE-2021-42574 "Trojan Source"
    // demonstrated that LRO/RLO/PDF/LRI/RLI/FSI/PDI can reorder source code so
    // the rendered text disagrees with the parsed tokens.
    citation: 'CVE-2021-42574 "Trojan Source" — bidi controls U+202A–U+202E, U+2066–U+2069',
    ranges: [
      [0x202a, 0x202e],
      [0x2066, 0x2069],
    ],
    mode: 'always',
    severity: 'high',
  },
  {
    id: 'unicode.hangul-filler',
    threatIds: ['T1'],
    name: 'Hangul filler',
    // Hangul Filler. Renders as nothing in many fonts while occupying a
    // codepoint, historically used in homoglyph/IDN spoofing.
    citation: 'Hangul Filler U+3164 — documented homoglyph carrier (Unicode TR#36)',
    ranges: [[0x3164, 0x3164]],
    mode: 'always',
    severity: 'medium',
  },
  {
    id: 'unicode.variation-selectors-supplement',
    threatIds: ['T1', 'T2'],
    name: 'Variation Selectors Supplement',
    // VS Supplement (U+E0100–U+E01EF). Legitimate uses pair one or two
    // selectors with an emoji base. TrapDoor saturated files with dozens to
    // hundreds, encoding bytes in the selector index.
    citation: 'Variation Selectors Supplement U+E0100–U+E01EF; saturation encoding per TrapDoor',
    ranges: [[0xe0100, 0xe01ef]],
    mode: 'density',
    severity: 'high',
  },
  {
    id: 'unicode.zero-width',
    threatIds: ['T1', 'T2'],
    name: 'Zero-width characters',
    // ZWSP (U+200B), ZWNJ (U+200C), ZWJ (U+200D), BOM/ZWNBSP (U+FEFF).
    // ZWJ has legitimate use in emoji sequences; BOM has legitimate use as a
    // file-start marker. Density mode prevents false positives on normal text
    // while catching saturation payloads.
    citation: 'Zero-width controls U+200B–U+200D, U+FEFF; saturation per TrapDoor',
    ranges: [
      [0x200b, 0x200d],
      [0xfeff, 0xfeff],
    ],
    mode: 'density',
    severity: 'high',
  },
];
