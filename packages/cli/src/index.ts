#!/usr/bin/env bun
// Warden CLI entry. Surface: `warden scan [path] [--json|--sarif] [--quiet]`.
// Exit codes per docs/DECISIONS/0007-output-formats-sarif-json.md §3.

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { Command } from 'commander';
import { printJson } from './report-json.ts';
import { printPretty } from './report-pretty.ts';
import { printSarif } from './report-sarif.ts';

export const WARDEN_VERSION = '0.0.0-m3';

type ScanFlags = {
  readonly json?: true;
  readonly sarif?: true;
  readonly quiet?: true;
  readonly color?: boolean;
};

type StdStreams = {
  readonly stdout: { write(chunk: string): boolean | unknown; isTTY?: boolean };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

export function runScan(target: string, flags: ScanFlags, streams: StdStreams): number {
  const absTarget = resolve(target);
  if (!existsSync(absTarget)) {
    streams.stderr.write(`warden: path does not exist: ${target}\n`);
    return 2;
  }

  if (flags.json === true && flags.sarif === true) {
    streams.stderr.write('warden: --json and --sarif are mutually exclusive\n');
    return 2;
  }

  const report = scanPath(absTarget);

  if (flags.json === true) {
    printJson(report, WARDEN_VERSION, streams.stdout);
  } else if (flags.sarif === true) {
    printSarif(report, WARDEN_VERSION, streams.stdout);
  } else {
    // Commander's --no-color sets `color: false`; absent flag leaves it true.
    // Color requires both (a) user did not opt out and (b) stdout is a TTY.
    const userOptedOut = flags.color === false;
    const color = !userOptedOut && streams.stdout.isTTY === true;
    printPretty(report, streams.stdout, { quiet: flags.quiet === true, color });
  }

  return report.highCount > 0 ? 1 : 0;
}

export function buildProgram(streams: StdStreams): Command {
  const program = new Command();
  program
    .name('warden')
    .description(
      'Local firewall for AI coding agents — scans context files for invisible Unicode, prompt injection, suspicious MCP configs.',
    )
    .version(WARDEN_VERSION);

  program
    .command('scan')
    .description('Scan a directory or file for agent-context threats.')
    .argument('[path]', 'directory or file to scan', '.')
    .option('--json', 'emit a stable JSON report on stdout')
    .option('--sarif', 'emit a SARIF 2.1.0 report on stdout')
    .option('--quiet', 'suppress per-finding output; print summary line only')
    .option('--no-color', 'disable ANSI color in pretty output')
    .action((path: string, opts: { json?: true; sarif?: true; quiet?: true; color?: boolean }) => {
      const code = runScan(path, opts, streams);
      process.exit(code);
    });

  return program;
}

// Direct-execute guard. When imported as a library (e.g., from tests), the
// CLI does not parse argv automatically.
if (import.meta.main) {
  const program = buildProgram({ stdout: process.stdout, stderr: process.stderr });
  program.parseAsync(process.argv).catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`warden: ${msg}\n`);
    process.exit(2);
  });
}
