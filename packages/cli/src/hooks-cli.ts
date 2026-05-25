// CLI subcommands for `warden hooks install claude` and
// `warden hooks run claude`. Spec: ADR 0013 §§3-7.

import { installClaudeHook, readAll, runOnInput } from '@warden-sh/hooks-claude';

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
