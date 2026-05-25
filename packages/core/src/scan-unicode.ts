import { UNICODE_DENSITY_THRESHOLDS, UNICODE_RANGES, type UnicodeRange } from '@warden-sh/rules';
import type { UnicodeFinding } from './findings.ts';

function utf8ByteLength(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

function matchRange(codePoint: number, range: UnicodeRange): boolean {
  for (const [start, end] of range.ranges) {
    if (codePoint >= start && codePoint <= end) return true;
  }
  return false;
}

type DensityCandidate = {
  readonly range: UnicodeRange;
  readonly codepoint: number;
  readonly byteOffset: number;
};

// scanUnicode returns one finding per occurrence of a flagged codepoint.
// For ranges in 'always' mode, every occurrence is reported. For 'density'
// ranges, occurrences are reported only when the per-input count exceeds the
// configured threshold — this is what separates a legitimate emoji ZWJ
// sequence from a TrapDoor saturation payload.
export function scanUnicode(input: string): UnicodeFinding[] {
  const findings: UnicodeFinding[] = [];
  const densityCandidates: DensityCandidate[] = [];
  const densityCounts = new Map<string, number>();

  let byteOffset = 0;
  for (const ch of input) {
    const codePoint = ch.codePointAt(0);
    if (codePoint === undefined) continue;
    const advance = utf8ByteLength(codePoint);

    for (const range of UNICODE_RANGES) {
      if (!matchRange(codePoint, range)) continue;
      if (range.mode === 'always') {
        findings.push({
          ruleId: range.id,
          threatIds: range.threatIds,
          rangeName: range.name,
          codepoint: codePoint,
          byteOffset,
          severity: range.severity,
          kind: 'always-suspicious',
        });
      } else {
        densityCandidates.push({ range, codepoint: codePoint, byteOffset });
        densityCounts.set(range.id, (densityCounts.get(range.id) ?? 0) + 1);
      }
    }

    byteOffset += advance;
  }

  for (const candidate of densityCandidates) {
    const count = densityCounts.get(candidate.range.id) ?? 0;
    const threshold = (UNICODE_DENSITY_THRESHOLDS as Readonly<Record<string, number>>)[
      candidate.range.id
    ];
    if (threshold === undefined) continue;
    if (count <= threshold) continue;
    findings.push({
      ruleId: candidate.range.id,
      threatIds: candidate.range.threatIds,
      rangeName: candidate.range.name,
      codepoint: candidate.codepoint,
      byteOffset: candidate.byteOffset,
      severity: candidate.range.severity,
      kind: 'density-violation',
    });
  }

  return findings;
}
