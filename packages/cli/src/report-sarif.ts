// SARIF 2.1.0 reporter for `warden scan --sarif`. Emits a minimal
// compliant document: see docs/DECISIONS/0007-output-formats-sarif-json.md
// for the schema strategy and severity mapping. Schema reference:
// https://json.schemastore.org/sarif-2.1.0.json

import type { ScanReport, UnicodeFinding } from '@warden-sh/core';
import { UNICODE_RANGES } from '@warden-sh/rules';

type Writer = { write(chunk: string): boolean | unknown };

const SARIF_SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const TOOL_INFORMATION_URI = 'https://github.com/warden-sh/warden';

export type SarifLevel = 'error' | 'warning' | 'note';

function levelFor(severity: UnicodeFinding['severity']): SarifLevel {
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
  properties: {
    codepoint: string;
    threatIds: ReadonlyArray<string>;
    findingKind: UnicodeFinding['kind'];
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
  return out;
}

export function toSarifDocument(report: ScanReport, toolVersion: string): SarifDocument {
  const results: SarifResult[] = [];
  const usedRuleIds = new Set<string>();

  for (const file of report.files) {
    for (const finding of file.findings) {
      usedRuleIds.add(finding.ruleId);
      results.push({
        ruleId: finding.ruleId,
        level: levelFor(finding.severity),
        message: {
          text: `${finding.rangeName}: ${formatCodepoint(finding.codepoint)} (${finding.kind})`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: file.path.replaceAll('\\', '/') },
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
      });
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
