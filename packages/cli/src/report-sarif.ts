// SARIF 2.1.0 reporter for `warden scan --sarif`. Emits a minimal
// compliant document: see docs/DECISIONS/0007-output-formats-sarif-json.md
// for the schema strategy and severity mapping. Schema reference:
// https://json.schemastore.org/sarif-2.1.0.json
//
// M3: prompt-injection rules emitted alongside Unicode rules under the
// same SARIF run.
//
// M3.1: suppressed findings (per ADR 0010) emit the same as kept findings
// but with `result.suppressions[]` populated. This is the SARIF-conformant
// way to model "the tool found it but the user marked it as expected"
// (SARIF 2.1.0 §3.27.23) and avoids dropping evidence.

import type {
  McpFinding,
  PromptInjectionFinding,
  ScanReport,
  SupplyChainFinding,
  TrustFinding,
  TrustFindingCategory,
  UnicodeFinding,
} from '@warden-sh/core';
import {
  MCP_INVALID_JSON_RULE,
  MCP_RULES,
  PROMPT_INJECTION_RULES,
  UNICODE_RANGES,
} from '@warden-sh/rules';

// Trust rule metadata. Source of truth is ADR 0012 §3 (default-behavior
// matrix). Inlined here rather than under packages/rules because trust
// rules are not pattern data — they are pipeline outcomes.
const TRUST_RULES: ReadonlyArray<{
  readonly id: TrustFindingCategory;
  readonly name: string;
  readonly description: string;
}> = [
  {
    id: 'trust.unsigned',
    name: 'Unsigned context file',
    description:
      'Agent context file has no [[trust]] entry in .warden/trust/manifest.toml (ADR 0012 §3).',
  },
  {
    id: 'trust.signature-mismatch',
    name: 'Signature does not validate against current file bytes',
    description:
      'Manifest hash or signature does not validate against current file bytes (ADR 0012 §3).',
  },
  {
    id: 'trust.untrusted-signer',
    name: 'Signing key not in allowed_signers',
    description:
      'Signature is by a key whose fingerprint is not in .warden/trust/allowed_signers (ADR 0012 §3).',
  },
  {
    id: 'trust.orphan-entry',
    name: 'Manifest entry without matching file',
    description: 'Manifest declares a path that has no matching file on disk (ADR 0012 §3).',
  },
];

type Writer = { write(chunk: string): boolean | unknown };

const SARIF_SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const TOOL_INFORMATION_URI = 'https://github.com/warden-sh/warden';

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';
type AnySeverity =
  | UnicodeFinding['severity']
  | PromptInjectionFinding['severity']
  | McpFinding['severity']
  | TrustFinding['severity']
  | SupplyChainFinding['severity'];

function levelFor(severity: AnySeverity): SarifLevel {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    // `info` is the M9 transitive-LOW supply-chain severity (ADR 0016
    // §4). SARIF 2.1.0 §3.27.10 allows `none` for informational
    // findings that do not constitute a problem.
    case 'info':
      return 'none';
  }
}

function utf8ByteLengthOf(codePoint: number): number {
  if (codePoint < 0x80) return 1;
  if (codePoint < 0x800) return 2;
  if (codePoint < 0x10000) return 3;
  return 4;
}

function formatCodepoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

type SarifRule = {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  helpUri?: string;
  properties: { threatIds: ReadonlyArray<string>; citation: string };
};

type SarifSuppression = {
  kind: 'external';
  status: 'accepted';
  justification: string;
};

type SarifResult = {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: ReadonlyArray<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { byteOffset: number; byteLength: number };
    };
  }>;
  suppressions?: ReadonlyArray<SarifSuppression>;
  properties:
    | {
        codepoint: string;
        threatIds: ReadonlyArray<string>;
        findingKind: UnicodeFinding['kind'];
      }
    | {
        match: string;
        threatIds: ReadonlyArray<string>;
        tier: PromptInjectionFinding['tier'];
      }
    | {
        evidence: string;
        threatIds: ReadonlyArray<string>;
        serverName: string | null;
      }
    | {
        hint: string;
        threatIds: ReadonlyArray<string>;
      }
    | {
        threatIds: ReadonlyArray<string>;
        ecosystem: SupplyChainFinding['ecosystem'];
        packageName: string;
        version: string;
        position: SupplyChainFinding['position'];
        advisoryId: string;
        advisoryUrl: string;
        confidence: SupplyChainFinding['confidence'];
      };
};

type SarifDocument = {
  $schema: typeof SARIF_SCHEMA_URI;
  version: typeof SARIF_VERSION;
  runs: ReadonlyArray<{
    tool: {
      driver: {
        name: 'warden';
        version: string;
        informationUri: typeof TOOL_INFORMATION_URI;
        rules: ReadonlyArray<SarifRule>;
      };
    };
    results: ReadonlyArray<SarifResult>;
    originalUriBaseIds?: { ROOT: { uri: string } };
  }>;
};

function buildRules(usedRuleIds: ReadonlySet<string>): SarifRule[] {
  const out: SarifRule[] = [];
  for (const range of UNICODE_RANGES) {
    if (!usedRuleIds.has(range.id)) continue;
    out.push({
      id: range.id,
      name: range.name,
      shortDescription: { text: range.name },
      fullDescription: { text: range.citation },
      defaultConfiguration: { level: levelFor(range.severity) },
      properties: { threatIds: range.threatIds, citation: range.citation },
    });
  }
  for (const rule of PROMPT_INJECTION_RULES) {
    if (!usedRuleIds.has(rule.id)) continue;
    out.push({
      id: rule.id,
      name: rule.name,
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.citation },
      defaultConfiguration: { level: levelFor(rule.severity) },
      properties: { threatIds: rule.threatIds, citation: rule.citation },
    });
  }
  for (const rule of MCP_RULES) {
    if (!usedRuleIds.has(rule.id)) continue;
    out.push({
      id: rule.id,
      name: rule.name,
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.citation },
      defaultConfiguration: { level: levelFor(rule.severity) },
      properties: { threatIds: rule.threatIds, citation: rule.citation },
    });
  }
  if (usedRuleIds.has(MCP_INVALID_JSON_RULE.id)) {
    out.push({
      id: MCP_INVALID_JSON_RULE.id,
      name: MCP_INVALID_JSON_RULE.name,
      shortDescription: { text: MCP_INVALID_JSON_RULE.name },
      fullDescription: { text: MCP_INVALID_JSON_RULE.citation },
      defaultConfiguration: { level: levelFor(MCP_INVALID_JSON_RULE.severity) },
      properties: {
        threatIds: MCP_INVALID_JSON_RULE.threatIds,
        citation: MCP_INVALID_JSON_RULE.citation,
      },
    });
  }
  for (const rule of TRUST_RULES) {
    if (!usedRuleIds.has(rule.id)) continue;
    out.push({
      id: rule.id,
      name: rule.name,
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.description },
      defaultConfiguration: { level: 'error' },
      properties: { threatIds: ['M5-T4'], citation: 'docs/DECISIONS/0012-m5-trust-signing.md' },
    });
  }
  if (usedRuleIds.has('supply-chain.osv-known-vulnerability')) {
    out.push({
      id: 'supply-chain.osv-known-vulnerability',
      name: 'Known vulnerability in lockfile-pinned dependency',
      shortDescription: { text: 'OSV.dev advisory matches a pinned dependency in this project' },
      fullDescription: {
        text: 'A lockfile-pinned package version matches a known-vulnerability range published by the OSV.dev feed. See ADR 0016.',
      },
      // Effective severity is per-finding (direct vs transitive
      // modulation); the default-config level here reflects the most
      // common emitted level. SARIF consumers should read result.level.
      defaultConfiguration: { level: 'warning' },
      properties: {
        threatIds: ['T6'],
        citation: 'docs/DECISIONS/0016-m9-lockfile-scanner.md',
      },
    });
  }
  return out;
}

function unicodeResult(
  finding: UnicodeFinding,
  uri: string,
  suppressionJustification: string | null,
): SarifResult {
  const base: SarifResult = {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: {
      text: `${finding.rangeName}: ${formatCodepoint(finding.codepoint)} (${finding.kind})`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: {
            byteOffset: finding.byteOffset,
            byteLength: utf8ByteLengthOf(finding.codepoint),
          },
        },
      },
    ],
    properties: {
      codepoint: formatCodepoint(finding.codepoint),
      threatIds: finding.threatIds,
      findingKind: finding.kind,
    },
  };
  if (suppressionJustification !== null) {
    return {
      ...base,
      suppressions: [
        { kind: 'external', status: 'accepted', justification: suppressionJustification },
      ],
    };
  }
  return base;
}

function mcpResult(
  finding: McpFinding,
  uri: string,
  suppressionJustification: string | null,
): SarifResult {
  const base: SarifResult = {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: {
      text: `${finding.ruleName}: ${finding.evidence}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { byteOffset: 0, byteLength: 0 },
        },
      },
    ],
    properties: {
      evidence: finding.evidence,
      threatIds: finding.threatIds,
      serverName: finding.serverName,
    },
  };
  if (suppressionJustification !== null) {
    return {
      ...base,
      suppressions: [
        { kind: 'external', status: 'accepted', justification: suppressionJustification },
      ],
    };
  }
  return base;
}

function trustResult(
  finding: TrustFinding,
  uri: string,
  suppressionJustification: string | null,
): SarifResult {
  const base: SarifResult = {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { byteOffset: 0, byteLength: 0 },
        },
      },
    ],
    properties: {
      hint: finding.hint,
      threatIds: ['M5-T4'],
    },
  };
  if (suppressionJustification !== null) {
    return {
      ...base,
      suppressions: [
        { kind: 'external', status: 'accepted', justification: suppressionJustification },
      ],
    };
  }
  return base;
}

function supplyChainResult(
  finding: SupplyChainFinding,
  uri: string,
  suppressionJustification: string | null,
): SarifResult {
  const base: SarifResult = {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: {
      text: `${finding.advisoryId} affects ${finding.ecosystem}:${finding.packageName}@${finding.version} (${finding.position}): ${finding.summary}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { byteOffset: 0, byteLength: 0 },
        },
      },
    ],
    properties: {
      threatIds: finding.threatIds,
      ecosystem: finding.ecosystem,
      packageName: finding.packageName,
      version: finding.version,
      position: finding.position,
      advisoryId: finding.advisoryId,
      advisoryUrl: finding.advisoryUrl,
      confidence: finding.confidence,
    },
  };
  if (suppressionJustification !== null) {
    return {
      ...base,
      suppressions: [
        { kind: 'external', status: 'accepted', justification: suppressionJustification },
      ],
    };
  }
  return base;
}

function piResult(
  pi: PromptInjectionFinding,
  uri: string,
  suppressionJustification: string | null,
): SarifResult {
  const base: SarifResult = {
    ruleId: pi.ruleId,
    level: levelFor(pi.severity),
    message: {
      text: `${pi.ruleName} (${pi.tier}): ${pi.match}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: {
            byteOffset: pi.byteOffset,
            byteLength: pi.byteLength,
          },
        },
      },
    ],
    properties: {
      match: pi.match,
      threatIds: pi.threatIds,
      tier: pi.tier,
    },
  };
  if (suppressionJustification !== null) {
    return {
      ...base,
      suppressions: [
        { kind: 'external', status: 'accepted', justification: suppressionJustification },
      ],
    };
  }
  return base;
}

export function toSarifDocument(report: ScanReport, toolVersion: string): SarifDocument {
  const results: SarifResult[] = [];
  const usedRuleIds = new Set<string>();

  for (const file of report.files) {
    const uri = file.path.replaceAll('\\', '/');
    const suppressionReason =
      file.marker !== null
        ? `payload-fixture [${file.marker.families.join(', ')}]: ${file.marker.reason}`
        : null;

    for (const finding of file.findings) {
      usedRuleIds.add(finding.ruleId);
      results.push(unicodeResult(finding, uri, null));
    }
    for (const finding of file.suppressedFindings) {
      usedRuleIds.add(finding.ruleId);
      results.push(unicodeResult(finding, uri, suppressionReason));
    }

    for (const pi of file.promptInjectionFindings) {
      usedRuleIds.add(pi.ruleId);
      results.push(piResult(pi, uri, null));
    }
    for (const pi of file.suppressedPromptInjectionFindings) {
      usedRuleIds.add(pi.ruleId);
      results.push(piResult(pi, uri, suppressionReason));
    }

    for (const mcp of file.mcpFindings) {
      usedRuleIds.add(mcp.ruleId);
      results.push(mcpResult(mcp, uri, null));
    }
    for (const mcp of file.suppressedMcpFindings) {
      usedRuleIds.add(mcp.ruleId);
      results.push(mcpResult(mcp, uri, suppressionReason));
    }

    for (const t of file.trustFindings) {
      usedRuleIds.add(t.ruleId);
      results.push(trustResult(t, uri, null));
    }
    for (const t of file.suppressedTrustFindings) {
      usedRuleIds.add(t.ruleId);
      // Trust suppression is via unlock (ADR 0012 §4.4), not marker.
      results.push(trustResult(t, uri, `unlock: ${t.message}`));
    }

    for (const sc of file.supplyChainFindings) {
      usedRuleIds.add(sc.ruleId);
      results.push(supplyChainResult(sc, uri, null));
    }
    for (const sc of file.suppressedSupplyChainFindings) {
      usedRuleIds.add(sc.ruleId);
      results.push(supplyChainResult(sc, uri, suppressionReason));
    }
  }

  // Orphan trust findings have no associated file in the report list;
  // emit them with the manifest path as URI.
  for (const t of report.orphanTrustFindings) {
    usedRuleIds.add(t.ruleId);
    results.push(trustResult(t, t.path.replaceAll('\\', '/'), null));
  }

  return {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'warden',
            version: toolVersion,
            informationUri: TOOL_INFORMATION_URI,
            rules: buildRules(usedRuleIds),
          },
        },
        results,
        originalUriBaseIds: { ROOT: { uri: `file://${report.root}/` } },
      },
    ],
  };
}

export function printSarif(report: ScanReport, toolVersion: string, out: Writer): void {
  out.write(`${JSON.stringify(toSarifDocument(report, toolVersion), null, 2)}\n`);
}
