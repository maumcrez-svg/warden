#!/usr/bin/env bun
// Warden CLI entry. Surface: `warden scan [path] [--json|--sarif] [--quiet] [--verbose]`.
// Exit codes per docs/DECISIONS/0007-output-formats-sarif-json.md §3 and
// docs/DECISIONS/0010-payload-fixture-marker-convention.md §11.

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { Command } from 'commander';
import { printJson } from './report-json.ts';
import { printPretty } from './report-pretty.ts';
import { printSarif } from './report-sarif.ts';

export const WARDEN_VERSION = '0.0.0-m3.1';

type ScanFlags = {
  readonly json?: true;
  readonly sarif?: true;
  readonly quiet?: true;
  readonly verbose?: true;
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

  // Marker parse errors are first-class scan errors (ADR 0010 §11). Surface
  // them to stderr and exit 2 regardless of finding counts; a broken marker
  // is a configuration bug that must block the scan.
  if (report.markerErrors.length > 0) {
    for (const e of report.markerErrors) {
      streams.stderr.write(`warden: marker error: ${e.message}\n`);
    }
    return 2;
  }

  if (flags.json === true) {
    printJson(report, WARDEN_VERSION, streams.stdout);
  } else if (flags.sarif === true) {
    printSarif(report, WARDEN_VERSION, streams.stdout);
  } else {
    const userOptedOut = flags.color === false;
    const color = !userOptedOut && streams.stdout.isTTY === true;
    printPretty(report, streams.stdout, {
      quiet: flags.quiet === true,
      verbose: flags.verbose === true,
      color,
    });
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
    .option(
      '--verbose',
      'in pretty output, also list findings suppressed by payload-fixture markers',
    )
    .option('--no-color', 'disable ANSI color in pretty output')
    .action(
      (
        path: string,
        opts: {
          json?: true;
          sarif?: true;
          quiet?: true;
          verbose?: true;
          color?: boolean;
        },
      ) => {
        const code = runScan(path, opts, streams);
        process.exit(code);
      },
    );

  return program;
}

if (import.meta.main) {
  const program = buildProgram({ stdout: process.stdout, stderr: process.stderr });
  program.parseAsync(process.argv).catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`warden: ${msg}\n`);
    process.exit(2);
  });
}
