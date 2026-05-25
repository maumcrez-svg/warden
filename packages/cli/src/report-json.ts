// JSON reporter for `warden scan --json`. Emits a single object with a
// stable `version` discriminator. See docs/DECISIONS/0007-output-formats-sarif-json.md
// (initial v1 contract), docs/DECISIONS/0009-json-v2-prompt-injection-findings.md
// (the v1 -> v2 bump for the M3 prompt-injection findings field), and
// docs/DECISIONS/0010-payload-fixture-marker-convention.md §8 (the v2
// absorbed marker + suppression fields in M3.1 without a v3 bump).

import type { ScanReport } from '@warden-sh/core';

type Writer = { write(chunk: string): boolean | unknown };

export type JsonReport = {
  readonly version: 'warden/scan/v2';
  readonly tool: { readonly name: 'warden'; readonly version: string };
  readonly root: string;
  readonly scannedAt: string;
  readonly fileCount: number;
  readonly matchedCount: number;
  readonly findingCount: number;
  readonly highCount: number;
  readonly mediumCount: number;
  readonly lowCount: number;
  readonly suppressedCount: number;
  readonly suppressedByCategory: ScanReport['suppressedByCategory'];
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
  readonly markerErrors: ScanReport['markerErrors'];
  readonly files: ScanReport['files'];
};

export function toJsonReport(report: ScanReport, toolVersion: string): JsonReport {
  return {
    version: 'warden/scan/v2',
    tool: { name: 'warden', version: toolVersion },
    root: report.root,
    scannedAt: report.scannedAt,
    fileCount: report.fileCount,
    matchedCount: report.matchedCount,
    findingCount: report.findingCount,
    highCount: report.highCount,
    mediumCount: report.mediumCount,
    lowCount: report.lowCount,
    suppressedCount: report.suppressedCount,
    suppressedByCategory: report.suppressedByCategory,
    unsupportedGitignorePatterns: report.unsupportedGitignorePatterns,
    markerErrors: report.markerErrors,
    files: report.files,
  };
}

export function printJson(report: ScanReport, toolVersion: string, out: Writer): void {
  out.write(`${JSON.stringify(toJsonReport(report, toolVersion), null, 2)}\n`);
}
