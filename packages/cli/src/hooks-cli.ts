// CLI subcommands for the hook adapters.
// Claude (M6): ADR 0013 §§3-7.
// Cursor (M7): ADR 0014 §§3-8.

import { installClaudeHook, readAll, runOnInput } from '@warden-sh/hooks-claude';
import {
  installCursorHook,
  readAll as readAllCursor,
  runOnInput as runOnInputCursor,
} from '@warden-sh/hooks-cursor';

type Streams = {
  readonly stdout: { write(chunk: string): boolean | unknown };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

export function hooksInstallClaude(flags: { readonly force?: true }, streams: Streams): number {
  const result = installClaudeHook({ force: flags.force === true }, streams);
  if (result.exitCode === 0 && result.changed) {
    streams.stderr.write(
      `warden hooks install: wrote ${result.settingsPath} and ${result.hookScriptPath}\n`,
    );
  }
  return result.exitCode;
}

export async function hooksRunClaude(
  flags: { readonly jsonOutput?: true },
  streams: Streams & { stdin: NodeJS.ReadableStream | AsyncIterable<unknown> },
): Promise<number> {
  const input = await readAll(streams.stdin);
  const result = runOnInput(input, streams, { jsonOutput: flags.jsonOutput === true });
  return result.exitCode;
}

export function hooksInstallCursor(flags: { readonly force?: true }, streams: Streams): number {
  const result = installCursorHook({ force: flags.force === true }, streams);
  if (result.exitCode === 0 && result.changed) {
    streams.stderr.write(
      `warden hooks install: wrote ${result.hooksJsonPath} and ${result.hookScriptPath}\n`,
    );
  }
  return result.exitCode;
}

export async function hooksRunCursor(
  _flags: Record<string, never>,
  streams: Streams & { stdin: NodeJS.ReadableStream | AsyncIterable<unknown> },
): Promise<number> {
  const input = await readAllCursor(streams.stdin);
  const result = runOnInputCursor(input, streams);
  return result.exitCode;
}
