// scanPromptInjection runs each rule pattern in PROMPT_INJECTION_RULES
// against the input string and emits one finding per match. Byte offsets
// are UTF-8 byte positions (matching scanUnicode's contract) so reporters
// can locate findings in the underlying file.
//
// Determinism: rules are evaluated in declaration order; matches within a
// rule are reported left-to-right; the returned array is sorted by
// byteOffset, with rule id as a tiebreaker. No global state.
//
// Threat coverage: T4 — CVE-2025-53773 family (indirect prompt injection
// in agent-visible files). See docs/THREAT_MODEL.md and the per-rule
// citations in packages/rules/src/data/prompt-injection.ts.

import { PROMPT_INJECTION_RULES } from '@warden-sh/rules';
import type { PromptInjectionFinding } from './findings.ts';

function utf8ByteLength(str: string): number {
  let len = 0;
  for (const ch of str) {
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;
    if (cp < 0x80) len += 1;
    else if (cp < 0x800) len += 2;
    else if (cp < 0x10000) len += 3;
    else len += 4;
  }
  return len;
}

// Char-offset → byte-offset table for the input string. Built once per scan
// so per-match offset translation is O(1). Indexed by JS UTF-16 code-unit
// position, which is what RegExp.exec returns.
function buildCharToByteTable(input: string): Uint32Array {
  const table = new Uint32Array(input.length + 1);
  let byteOffset = 0;
  for (let i = 0; i < input.length; i++) {
    table[i] = byteOffset;
    const code = input.charCodeAt(i);
    if (code < 0x80) {
      byteOffset += 1;
    } else if (code < 0x800) {
      byteOffset += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate: 4 bytes split across the surrogate pair. Attribute
      // all 4 bytes to the high-surrogate position and 0 to the low one.
      byteOffset += 4;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      // Low surrogate: bytes already counted on the high surrogate.
    } else {
      byteOffset += 3;
    }
  }
  table[input.length] = byteOffset;
  return table;
}

export function scanPromptInjection(input: string): PromptInjectionFinding[] {
  if (input.length === 0) return [];

  const table = buildCharToByteTable(input);
  const findings: PromptInjectionFinding[] = [];

  for (const rule of PROMPT_INJECTION_RULES) {
    // Force a fresh, global walk regardless of how the rule was authored.
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`;
    const re = new RegExp(rule.pattern.source, flags);

    let match: RegExpExecArray | null = re.exec(input);
    while (match !== null) {
      const matched = match[0];
      const charStart = match.index;
      const byteStart = table[charStart] ?? 0;
      const byteLen = utf8ByteLength(matched);

      findings.push({
        ruleId: rule.id,
        threatIds: rule.threatIds,
        ruleName: rule.name,
        tier: rule.tier,
        severity: rule.severity,
        byteOffset: byteStart,
        byteLength: byteLen,
        match: matched,
      });

      // Zero-length matches would loop forever; advance one position.
      if (re.lastIndex === match.index) re.lastIndex += 1;
      match = re.exec(input);
    }
  }

  findings.sort((a, b) => a.byteOffset - b.byteOffset || a.ruleId.localeCompare(b.ruleId));
  return findings;
}
