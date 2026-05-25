// Runtime entry point for Cursor hook events. Spec: ADR 0014 §§3-4.
//
// I/O at the edges; classification delegated to the pure interceptor.
// Cursor reads the decision from stdout JSON, not the exit code
// (ADR 0014 §4) — that's the largest single delta from M6.

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { type Allowlist, emptyAllowlist, parseAllowlist } from '@warden-sh/hooks-claude';
import { type CursorHookInput, type Decision, evaluateCursorToolCall } from './interceptor.ts';

type Streams = {
  readonly stdout: { write(chunk: string): boolean | unknown };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

export type RunOptions = {
  readonly cwd?: string;
  readonly home?: string;
  readonly allowlistPath?: string;
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

function writeAllow(stdout: Streams['stdout']): void {
  stdout.write(`${JSON.stringify({ permission: 'allow' })}\n`);
}

function writeDeny(stdout: Streams['stdout'], ruleId: string, reason: string): void {
  stdout.write(
    `${JSON.stringify({
      permission: 'deny',
      agent_message: `${ruleId}: ${reason}`,
      user_message: `warden blocked ${ruleId} (see agent_message)`,
    })}\n`,
  );
}

export function runOnInput(inputText: string, streams: Streams, opts: RunOptions = {}): RunResult {
  const home = opts.home ?? homedir();
  const cwd = opts.cwd ?? process.cwd();

  let input: CursorHookInput;
  try {
    const parsed = JSON.parse(inputText);
    if (parsed === null || typeof parsed !== 'object') {
      // ADR 0014 §4 "config error" cell: emit allow so the developer's
      // session is not stranded on our parser bug. Stderr surfaces the
      // problem; exit 1 lets failClosed catch it if the user opted in.
      streams.stderr.write('warden hook: stdin is not a JSON object\n');
      writeAllow(streams.stdout);
      return { exitCode: 1, decision: null };
    }
    input = parsed as CursorHookInput;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    streams.stderr.write(`warden hook: stdin JSON parse error: ${msg}\n`);
    writeAllow(streams.stdout);
    return { exitCode: 1, decision: null };
  }

  const allowlist = loadAllowlist(cwd, opts.allowlistPath, streams.stderr);
  const decision = evaluateCursorToolCall(input, { home, cwd, allowlist });

  if (decision.kind === 'allow') {
    writeAllow(streams.stdout);
    return { exitCode: 0, decision };
  }
  if (decision.kind === 'skip') {
    streams.stderr.write(`warden hook: skipping — ${decision.why}\n`);
    writeAllow(streams.stdout);
    return { exitCode: 0, decision };
  }

  // deny: Cursor reads the decision from stdout JSON, exit 0
  writeDeny(streams.stdout, decision.ruleId, decision.reason);
  return { exitCode: 0, decision };
}

export async function readAll(
  stream: AsyncIterable<unknown> | NodeJS.ReadableStream,
): Promise<string> {
  const chunks: string[] = [];
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
