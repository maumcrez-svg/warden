// Runtime entry point for the Claude Code PreToolUse hook.
// Spec: ADR 0013 §§3-4.
//
// I/O at the edges; the actual classification is delegated to the
// pure interceptor. CI-friendly: zero TTY requirements, structured
// stderr, exit-code conventions documented in ADR 0013 §4.

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { type Allowlist, emptyAllowlist, parseAllowlist } from './allowlist.ts';
import { type ClaudeToolUseInput, type Decision, evaluateToolCall } from './interceptor.ts';

type Streams = {
  readonly stdout: { write(chunk: string): boolean | unknown };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

export type RunOptions = {
  readonly cwd?: string;
  readonly home?: string;
  readonly allowlistPath?: string;
  // When true, emit `{"decision":"block","reason":"..."}` on stdout
  // and exit 0 instead of using the exit-2 stderr convention. Lets a
  // user opt into Anthropic's JSON-output hook contract.
  readonly jsonOutput?: boolean;
};

export type RunResult = {
  readonly exitCode: number;
  readonly decision: Decision | null;
};

function loadAllowlist(
  cwd: string,
  override: string | undefined,
  stderr: Streams['stderr'],
): Allowlist {
  const path = override ?? resolve(cwd, '.warden', 'hooks', 'allow.toml');
  if (!existsSync(path)) return emptyAllowlist();
  let content: string;
  try {
    content = readFileSync(path, 'utf8');
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    stderr.write(`warden hook: allowlist read error at ${path}: ${msg}\n`);
    return emptyAllowlist();
  }
  const parsed = parseAllowlist(content);
  if (parsed.kind === 'error') {
    stderr.write(
      `warden hook: allowlist parse error at ${path}:${parsed.line}: ${parsed.message}\n`,
    );
    return emptyAllowlist();
  }
  return parsed.allowlist;
}

export function runOnInput(inputText: string, streams: Streams, opts: RunOptions = {}): RunResult {
  const home = opts.home ?? homedir();
  const cwd = opts.cwd ?? process.cwd();

  let input: ClaudeToolUseInput;
  try {
    const parsed = JSON.parse(inputText);
    if (parsed === null || typeof parsed !== 'object') {
      streams.stderr.write('warden hook: stdin is not a JSON object\n');
      return { exitCode: 1, decision: null };
    }
    input = parsed as ClaudeToolUseInput;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    streams.stderr.write(`warden hook: stdin JSON parse error: ${msg}\n`);
    return { exitCode: 1, decision: null };
  }

  const allowlist = loadAllowlist(cwd, opts.allowlistPath, streams.stderr);
  const decision = evaluateToolCall(input, { home, cwd, allowlist });

  if (decision.kind === 'allow' || decision.kind === 'skip') {
    return { exitCode: 0, decision };
  }

  // deny
  if (opts.jsonOutput === true) {
    streams.stdout.write(
      `${JSON.stringify({ decision: 'block', reason: `${decision.ruleId}: ${decision.reason}` })}\n`,
    );
    return { exitCode: 0, decision };
  }
  streams.stderr.write(`warden: blocked by ${decision.ruleId} — ${decision.reason}\n`);
  return { exitCode: 2, decision };
}

export async function readAll(
  stream: AsyncIterable<unknown> | NodeJS.ReadableStream,
): Promise<string> {
  const chunks: string[] = [];
  // Both Node ReadableStream and Bun's stdin are async iterable over
  // Buffer chunks. We treat each chunk as utf8.
  // biome-ignore lint/suspicious/noExplicitAny: stream chunks can be Buffer or Uint8Array
  for await (const chunk of stream as AsyncIterable<any>) {
    if (typeof chunk === 'string') {
      chunks.push(chunk);
    } else if (chunk instanceof Uint8Array) {
      chunks.push(new TextDecoder('utf-8').decode(chunk));
    } else {
      chunks.push(String(chunk));
    }
  }
  return chunks.join('');
}
