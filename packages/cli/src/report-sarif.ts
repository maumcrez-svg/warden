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
  UnicodeFinding,
} from '@warden-sh/core';
import {
  MCP_INVALID_JSON_RULE,
  MCP_RULES,
  PROMPT_INJECTION_RULES,
  UNICODE_RANGES,
} from '@warden-sh/rules';

type Writer = { write(chunk: string): boolean | unknown };

const SARIF_SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const TOOL_INFORMATION_URI = 'https://github.com/warden-sh/warden';

export type SarifLevel = 'error' | 'warning' | 'note';
type AnySeverity =
  | UnicodeFinding['severity']
  | PromptInjectionFinding['severity']
  | McpFinding['severity'];

function levelFor(severity: AnySeverity): SarifLevel {
  switch (severity) {
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
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
