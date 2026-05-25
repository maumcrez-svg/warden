// Pretty terminal reporter. File-grouped, severity-colored when stdout is
// a TTY. Layout is opinionated and stable so reviewers can diff two
// scans visually; machine consumers should use --json or --sarif instead.
//
// M3.1: when a file has a payload-fixture marker (ADR 0010), its findings
// are split into kept (reported) and suppressed (counted, mentioned in the
// summary, listed under --verbose). Marker errors are surfaced separately;
// they cause runScan to exit 2 regardless of finding counts.

import type {
  FileReport,
  McpFinding,
  PromptInjectionFinding,
  ScanReport,
  UnicodeFinding,
} from '@warden-sh/core';

const ESC = '\x1b';
const ANSI = {
  reset: `${ESC}[0m`,
  dim: `${ESC}[2m`,
  bold: `${ESC}[1m`,
  red: `${ESC}[31m`,
  yellow: `${ESC}[33m`,
  cyan: `${ESC}[36m`,
  green: `${ESC}[32m`,
};

export type PrettyOptions = {
  readonly color?: boolean;
  readonly quiet?: boolean;
  readonly verbose?: boolean;
};

type Writer = { write(chunk: string): boolean | unknown };
type AnySeverity = 'low' | 'medium' | 'high';

function paint(text: string, code: string, color: boolean): string {
  if (!color) return text;
  return `${code}${text}${ANSI.reset}`;
}

function severityLabel(severity: AnySeverity, color: boolean): string {
  const code = severity === 'high' ? ANSI.red : severity === 'medium' ? ANSI.yellow : ANSI.cyan;
  return paint(severity.padEnd(6), code, color);
}

function formatCodepoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

function formatUnicodeFinding(f: UnicodeFinding, color: boolean): string {
  const sev = severityLabel(f.severity, color);
  const rule = f.ruleId.padEnd(40);
  const cp = formatCodepoint(f.codepoint).padEnd(8);
  const offset = `byte ${f.byteOffset}`.padEnd(10);
  const kind = paint(`(${f.kind})`, ANSI.dim, color);
  return `  ${sev}  ${rule}  ${cp}  ${offset}  ${kind}`;
}

function snippet(text: string, max = 60): string {
  const collapsed = text.replace(/\s+/g, ' ').trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 1)}…` : collapsed;
}

function formatPromptInjectionFinding(f: PromptInjectionFinding, color: boolean): string {
  const sev = severityLabel(f.severity, color);
  const rule = f.ruleId.padEnd(40);
  const tier = `[${f.tier}]`.padEnd(13);
  const offset = `byte ${f.byteOffset}`.padEnd(10);
  const match = paint(`"${snippet(f.match)}"`, ANSI.dim, color);
  return `  ${sev}  ${rule}  ${tier}  ${offset}  ${match}`;
}

function formatMcpFinding(f: McpFinding, color: boolean): string {
  const sev = severityLabel(f.severity, color);
  const rule = f.ruleId.padEnd(40);
  const evidence = paint(snippet(f.evidence, 80), ANSI.dim, color);
  return `  ${sev}  ${rule}  ${evidence}`;
}

function keptCount(file: FileReport): number {
  return file.findings.length + file.promptInjectionFindings.length + file.mcpFindings.length;
}

function suppressedCount(file: FileReport): number {
  return (
    file.suppressedFindings.length +
    file.suppressedPromptInjectionFindings.length +
    file.suppressedMcpFindings.length
  );
}

function formatFileHeader(file: FileReport, color: boolean): string {
  const kind = paint(`[${file.kind}]`, ANSI.dim, color);
  const path = paint(file.path, ANSI.bold, color);
  const count = keptCount(file);
  const tally = paint(`${count} finding${count === 1 ? '' : 's'}`, ANSI.dim, color);
  return `${path}  ${kind}  ${tally}`;
}

function formatMarkerLine(file: FileReport, color: boolean): string | null {
  if (file.marker === null) return null;
  const fams = file.marker.families.join(', ');
  const scope =
    file.marker.scope.kind === 'file'
      ? 'file'
      : `lines ${file.marker.scope.start}-${file.marker.scope.end}`;
  const label = paint('marker', ANSI.dim, color);
  return `  ${label}: payload-fixture [${fams}] scope:${scope} — ${file.marker.reason}`;
}

export function printPretty(report: ScanReport, out: Writer, opts: PrettyOptions = {}): void {
  const color = opts.color === true;
  const quiet = opts.quiet === true;
  const verbose = opts.verbose === true;

  const withFindings = report.files.filter((f) => keptCount(f) > 0);
  const withSuppressions = report.files.filter((f) => suppressedCount(f) > 0);

  if (!quiet) {
    out.write(
      `warden scan: ${report.matchedCount} file${report.matchedCount === 1 ? '' : 's'} scanned, ${withFindings.length} with findings.\n`,
    );

    if (withFindings.length === 0) {
      const ok = paint('clean', ANSI.green, color);
      out.write(`\n  ${ok} — no threats detected.\n`);
    } else {
      for (const file of withFindings) {
        out.write(`\n${formatFileHeader(file, color)}\n`);
        const markerLine = formatMarkerLine(file, color);
        if (markerLine !== null) out.write(`${markerLine}\n`);
        for (const finding of file.findings) {
          out.write(`${formatUnicodeFinding(finding, color)}\n`);
        }
        for (const pi of file.promptInjectionFindings) {
          out.write(`${formatPromptInjectionFinding(pi, color)}\n`);
        }
        for (const mcp of file.mcpFindings) {
          out.write(`${formatMcpFinding(mcp, color)}\n`);
        }
      }
    }

    if (verbose && withSuppressions.length > 0) {
      out.write(`\n${paint('suppressed by marker:', ANSI.dim, color)}\n`);
      for (const file of withSuppressions) {
        out.write(`\n${formatFileHeader(file, color)}\n`);
        const markerLine = formatMarkerLine(file, color);
        if (markerLine !== null) out.write(`${markerLine}\n`);
        for (const finding of file.suppressedFindings) {
          out.write(`${formatUnicodeFinding(finding, color)}\n`);
        }
        for (const pi of file.suppressedPromptInjectionFindings) {
          out.write(`${formatPromptInjectionFinding(pi, color)}\n`);
        }
        for (const mcp of file.suppressedMcpFindings) {
          out.write(`${formatMcpFinding(mcp, color)}\n`);
        }
      }
    }

    out.write('\n');
  }

  const high = paint(`${report.highCount} high`, report.highCount > 0 ? ANSI.red : ANSI.dim, color);
  const med = paint(
    `${report.mediumCount} medium`,
    report.mediumCount > 0 ? ANSI.yellow : ANSI.dim,
    color,
  );
  const low = paint(`${report.lowCount} low`, report.lowCount > 0 ? ANSI.cyan : ANSI.dim, color);
  out.write(`summary: ${report.findingCount} finding(s) — ${high}, ${med}, ${low}\n`);

  if (report.suppressedCount > 0) {
    const uni = report.suppressedByCategory.unicode;
    const pi = report.suppressedByCategory['prompt-injection'];
    const mcp = report.suppressedByCategory.mcp;
    const parts: string[] = [];
    if (uni > 0) parts.push(`${uni} unicode`);
    if (pi > 0) parts.push(`${pi} prompt-injection`);
    if (mcp > 0) parts.push(`${mcp} mcp`);
    const fileWord = withSuppressions.length === 1 ? 'file' : 'files';
    out.write(
      `suppressed: ${parts.join(' + ')} in ${withSuppressions.length} ${fileWord} by payload-fixture markers\n`,
    );
  }

  for (const warn of report.unsupportedGitignorePatterns) {
    out.write(paint(`warning: unsupported .gitignore pattern (M2): ${warn}\n`, ANSI.yellow, color));
  }
}
