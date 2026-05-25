// Pretty terminal reporter. File-grouped, severity-colored when stdout is
// a TTY. Layout is opinionated and stable so reviewers can diff two
// scans visually; machine consumers should use --json or --sarif instead.

import type { FileReport, ScanReport, UnicodeFinding } from '@warden-sh/core';

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
};

type Writer = { write(chunk: string): boolean | unknown };

function paint(text: string, code: string, color: boolean): string {
  if (!color) return text;
  return `${code}${text}${ANSI.reset}`;
}

function severityLabel(severity: UnicodeFinding['severity'], color: boolean): string {
  const code = severity === 'high' ? ANSI.red : severity === 'medium' ? ANSI.yellow : ANSI.cyan;
  return paint(severity.padEnd(6), code, color);
}

function formatCodepoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

function formatFinding(f: UnicodeFinding, color: boolean): string {
  const sev = severityLabel(f.severity, color);
  const rule = f.ruleId.padEnd(40);
  const cp = formatCodepoint(f.codepoint).padEnd(8);
  const offset = `byte ${f.byteOffset}`.padEnd(10);
  const kind = paint(`(${f.kind})`, ANSI.dim, color);
  return `  ${sev}  ${rule}  ${cp}  ${offset}  ${kind}`;
}

function formatFileHeader(file: FileReport, color: boolean): string {
  const kind = paint(`[${file.kind}]`, ANSI.dim, color);
  const path = paint(file.path, ANSI.bold, color);
  const count = file.findings.length;
  const tally = paint(`${count} finding${count === 1 ? '' : 's'}`, ANSI.dim, color);
  return `${path}  ${kind}  ${tally}`;
}

export function printPretty(report: ScanReport, out: Writer, opts: PrettyOptions = {}): void {
  const color = opts.color === true;
  const quiet = opts.quiet === true;

  const withFindings = report.files.filter((f) => f.findings.length > 0);

  if (!quiet) {
    out.write(
      `warden scan: ${report.matchedCount} file${report.matchedCount === 1 ? '' : 's'} scanned, ${withFindings.length} with findings.\n`,
    );

    if (withFindings.length === 0) {
      const ok = paint('clean', ANSI.green, color);
      out.write(`\n  ${ok} — no Unicode threats detected.\n`);
    } else {
      for (const file of withFindings) {
        out.write(`\n${formatFileHeader(file, color)}\n`);
        for (const finding of file.findings) {
          out.write(`${formatFinding(finding, color)}\n`);
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

  for (const warn of report.unsupportedGitignorePatterns) {
    out.write(paint(`warning: unsupported .gitignore pattern (M2): ${warn}\n`, ANSI.yellow, color));
  }
}
