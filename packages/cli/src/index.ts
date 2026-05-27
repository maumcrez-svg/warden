#!/usr/bin/env bun
// Warden CLI entry. Surface:
//   warden scan [path] [--json|--sarif] [--quiet] [--verbose] [--strict]
//   warden trust sign <path> [--key <path>] [--reason "<text>"]
//   warden trust verify [path] [--allowed-signers <path>] [--quiet] [--json]
//   warden trust list [--json] [--verify]
//   warden trust unlock <path> --reason "<text>"
//   warden trust keys list [--json]
//   warden hooks install claude [--force]
//   warden hooks install cursor [--force]
//   warden hooks run claude [--json-output]
//   warden hooks run cursor
//   warden ioc sync [--ecosystem <name>...]
//   warden ioc status [--json]
//   warden ioc lookup <ecosystem>:<package>@<version> [--json]
//   warden ioc verify [--ecosystem <name>...]
//
// Exit codes per docs/DECISIONS/0007-output-formats-sarif-json.md §3,
// docs/DECISIONS/0010-payload-fixture-marker-convention.md §11,
// docs/DECISIONS/0012-m5-trust-signing.md §3 (the trust matrix),
// docs/DECISIONS/0013-claude-code-hook-adapter.md §4 (Claude hook matrix),
// docs/DECISIONS/0014-cursor-hook-adapter.md §4 (Cursor hook matrix),
// and docs/DECISIONS/0015-ioc-sync.md §8 (ioc subcommand matrix).

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanPath } from '@warden-sh/core';
import { Command } from 'commander';
import {
  hooksInstallClaude,
  hooksInstallCursor,
  hooksRunClaude,
  hooksRunCursor,
} from './hooks-cli.ts';
import { iocLookup, iocStatus, iocSync, iocVerify } from './ioc-cli.ts';
import { printJson } from './report-json.ts';
import { printPretty } from './report-pretty.ts';
import { printSarif } from './report-sarif.ts';
import { buildScanIocBundle } from './scan-ioc-lookup.ts';
import { trustKeysList, trustList, trustSign, trustUnlock, trustVerify } from './trust-cli.ts';

export const WARDEN_VERSION = '0.0.0-m9';

type ScanFlags = {
  readonly json?: true;
  readonly sarif?: true;
  readonly quiet?: true;
  readonly verbose?: true;
  readonly color?: boolean;
  readonly strict?: true;
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

  const strict = flags.strict === true;

  // Build the IOC lookup bundle before invoking scanPath. ADR 0016 §5:
  //   - cache absent + --strict       → exit 2 (config error) before scan
  //   - cache absent (default mode)   → skip IOC checks; scan continues
  //   - cache unreadable + --strict   → exit 2
  //   - cache unreadable (default)    → skip + stderr warn
  const bundle = buildScanIocBundle();
  if (strict && (bundle.state === 'absent' || bundle.state === 'unreadable')) {
    streams.stderr.write(
      `warden: --strict requires ioc cache; ${bundle.message ?? 'cache unavailable'}\n`,
    );
    return 2;
  }

  const report = scanPath(absTarget, {
    strict,
    iocLookup: bundle.lookup,
    ...(bundle.state === 'stale' ? { iocStateHint: 'stale' as const } : {}),
    ...(bundle.state === 'fresh' ? { iocStateHint: 'fresh' as const } : {}),
  });

  if (report.trustState === 'invocation-error') {
    streams.stderr.write(`warden: ${report.trustError ?? 'trust setup error'}\n`);
    return 2;
  }

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

  // Exit-code policy:
  //   - high findings: exit 1.
  //   - --strict: any finding (high OR medium OR info) exits 1.
  //     ADR 0016 §4 escalates `info` under strict; orphan-entry
  //     remains medium under strict per ADR 0012.
  if (report.highCount > 0) return 1;
  if (strict && report.mediumCount > 0) return 1;
  if (strict && report.infoCount > 0) return 1;
  return 0;
}

export function buildProgram(streams: StdStreams): Command {
  const program = new Command();
  program
    .name('warden')
    .description(
      'Local firewall for AI coding agents — scans context files for invisible Unicode, prompt injection, suspicious MCP configs, and unsigned trust.',
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
    .option(
      '--strict',
      'enforce trust signatures: require manifest, treat medium as blocking, ignore unlocks and ~/.warden/extra_allowed_signers',
    )
    .action(
      (
        path: string,
        opts: {
          json?: true;
          sarif?: true;
          quiet?: true;
          verbose?: true;
          color?: boolean;
          strict?: true;
        },
      ) => {
        const code = runScan(path, opts, streams);
        process.exit(code);
      },
    );

  const trust = program.command('trust').description('Trust manifest commands (ADR 0012).');

  trust
    .command('sign <path>')
    .description('Sign a file and record the entry in .warden/trust/manifest.toml.')
    .option(
      '--key <path>',
      'SSH private key path (default: git signingkey, then ~/.ssh/id_ed25519)',
    )
    .option('--reason <text>', 'free-text annotation stored with the manifest entry')
    .action((path: string, opts: { key?: string; reason?: string }) => {
      const code = trustSign(path, opts, streams);
      process.exit(code);
    });

  trust
    .command('verify [path]')
    .description('Verify signatures (offline, no network).')
    .option('--allowed-signers <path>', 'override .warden/trust/allowed_signers')
    .option('--quiet', 'suppress per-file output; rely on exit code only')
    .option('--json', 'emit warden/trust-verify/v1 JSON')
    .action(
      (path: string | undefined, opts: { allowedSigners?: string; quiet?: true; json?: true }) => {
        const code = trustVerify(path, opts, streams);
        process.exit(code);
      },
    );

  trust
    .command('list')
    .description('List manifest entries.')
    .option('--json', 'emit warden/trust-list/v1 JSON')
    .option('--verify', 'add a status column by verifying each entry')
    .action((opts: { json?: true; verify?: true }) => {
      const code = trustList(opts, streams);
      process.exit(code);
    });

  trust
    .command('unlock <path>')
    .description('Mark a path as intentionally unsigned (suppresses trust.unsigned only).')
    .option('--reason <text>', 'free-text annotation (REQUIRED)')
    .action((path: string, opts: { reason?: string }) => {
      const code = trustUnlock(path, opts, streams);
      process.exit(code);
    });

  const keys = trust.command('keys').description('Trust-root key commands.');
  keys
    .command('list')
    .description('List allowed_signers entries (read-only).')
    .option('--json', 'emit warden/trust-keys-list/v1 JSON')
    .action((opts: { json?: true }) => {
      const code = trustKeysList(opts, streams);
      process.exit(code);
    });

  const hooks = program
    .command('hooks')
    .description('Agent runtime hook adapters (ADR 0013 Claude, ADR 0014 Cursor).');

  const install = hooks
    .command('install')
    .description('Install a runtime hook adapter for a supported agent.');
  install
    .command('claude')
    .description('Install the Claude Code PreToolUse adapter (idempotent).')
    .option('--force', 'overwrite a non-Warden PreToolUse entry with the same matcher')
    .action((opts: { force?: true }) => {
      const code = hooksInstallClaude(opts, streams);
      process.exit(code);
    });
  install
    .command('cursor')
    .description('Install the Cursor 1.7+ hook adapter (idempotent).')
    .option('--force', 'overwrite a non-Warden hook entry for the same event')
    .action((opts: { force?: true }) => {
      const code = hooksInstallCursor(opts, streams);
      process.exit(code);
    });

  const run = hooks
    .command('run')
    .description('Runtime entry for an installed hook adapter (invoked by the agent).');
  run
    .command('claude')
    .description('Read a Claude Code PreToolUse JSON payload on stdin and emit a decision.')
    .option('--json-output', 'emit decision as JSON on stdout instead of exit-2 + stderr')
    .action(async (opts: { jsonOutput?: true }) => {
      const code = await hooksRunClaude(opts, {
        stdin: process.stdin,
        stdout: streams.stdout,
        stderr: streams.stderr,
      });
      process.exit(code);
    });
  run
    .command('cursor')
    .description(
      'Read a Cursor beforeReadFile / beforeShellExecution JSON payload on stdin and emit a decision on stdout (Cursor reads decisions from stdout JSON).',
    )
    .action(async () => {
      const code = await hooksRunCursor(
        {},
        {
          stdin: process.stdin,
          stdout: streams.stdout,
          stderr: streams.stderr,
        },
      );
      process.exit(code);
    });

  const ioc = program
    .command('ioc')
    .description('Supply-chain IOC cache (ADR 0015). Network only via `warden ioc sync|verify`.');

  ioc
    .command('sync')
    .description(
      'Fetch and index OSV.dev vulnerability data into ~/.warden/ioc/. Atomic (ADR 0015 §10).',
    )
    .option(
      '--ecosystem <name>',
      'sync only the named ecosystem; repeat the flag to sync several (default: all)',
      (value: string, prev: string[] = []) => [...prev, value],
      [] as string[],
    )
    .option('--force', '(reserved) force re-download even if within staleness TTL')
    .action(async (opts: { ecosystem?: string[]; force?: true }) => {
      const flags: import('./ioc-cli.ts').IocSyncFlags = {
        wardenVersion: WARDEN_VERSION,
        ...(opts.ecosystem !== undefined ? { ecosystem: opts.ecosystem } : {}),
        ...(opts.force === true ? { force: true as const } : {}),
      };
      const code = await iocSync(flags, streams);
      process.exit(code);
    });

  ioc
    .command('status')
    .description('Print last-sync timestamp, advisory count, and staleness.')
    .option('--json', 'emit warden/ioc-status/v1 JSON')
    .action((opts: { json?: true }) => {
      const code = iocStatus(opts, streams);
      process.exit(code);
    });

  ioc
    .command('lookup <target>')
    .description(
      'Look up advisories for <ecosystem>:<package>@<version>. Exit 1 on hits (for CI gating).',
    )
    .option('--json', 'emit warden/ioc-lookup/v1 JSON')
    .action((target: string, opts: { json?: true }) => {
      const code = iocLookup(target, opts, streams);
      process.exit(code);
    });

  ioc
    .command('verify')
    .description(
      'Re-download the OSV ZIPs and SHA-256 compare against the previously-cached values.',
    )
    .option(
      '--ecosystem <name>',
      'verify only the named ecosystem; repeat the flag to verify several (default: every ecosystem present in the manifest)',
      (value: string, prev: string[] = []) => [...prev, value],
      [] as string[],
    )
    .action(async (opts: { ecosystem?: string[] }) => {
      const flags: import('./ioc-cli.ts').IocVerifyFlags = {
        ...(opts.ecosystem !== undefined ? { ecosystem: opts.ecosystem } : {}),
      };
      const code = await iocVerify(flags, streams);
      process.exit(code);
    });

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
