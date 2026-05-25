// End-to-end test of the Cursor runtime hook entry: stdin JSON →
// stdout JSON decision + exit code (ADR 0014 §§3-4). Uses runOnInput
// directly so we don't depend on shell or subprocess plumbing.

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { runOnInput } from '../src/run.ts';

const FIXTURE_ROOT = resolve(
  import.meta.dir,
  '..',
  '..',
  '..',
  'tests',
  'fixtures',
  'hooks-cursor',
);

class StringWriter {
  buf = '';
  write(s: string): boolean {
    this.buf += s;
    return true;
  }
}

function fixture(name: string): string {
  return readFileSync(resolve(FIXTURE_ROOT, name, 'input.json'), 'utf8');
}

function parseDecision(s: string): { permission: string; agent_message?: string } {
  return JSON.parse(s) as { permission: string; agent_message?: string };
}

describe('runOnInput', () => {
  test('beforeReadFile ~/.ssh/id_rsa → stdout {permission:"deny"} + exit 0', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('deny-ssh-read'), { stdout, stderr });
    // Cursor reads decisions from stdout JSON (ADR 0014 §4), not the
    // exit code. Exit 0 is the correct success-emit signal.
    expect(r.exitCode).toBe(0);
    expect(stderr.buf).toBe('');
    const obj = parseDecision(stdout.buf);
    expect(obj.permission).toBe('deny');
    expect(obj.agent_message).toContain('hooks.credential-file-read');
  });

  test('beforeShellExecution cat .env → deny via shell-read rule', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('deny-bash-cat-env'), { stdout, stderr });
    expect(r.exitCode).toBe(0);
    const obj = parseDecision(stdout.buf);
    expect(obj.permission).toBe('deny');
    expect(obj.agent_message).toContain('hooks.credential-shell-read');
  });

  test('benign beforeReadFile → stdout {permission:"allow"} + exit 0', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('allow-benign-read'), { stdout, stderr });
    expect(r.exitCode).toBe(0);
    expect(stderr.buf).toBe('');
    const obj = parseDecision(stdout.buf);
    expect(obj.permission).toBe('allow');
  });

  test('public-half .pub key → allow', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('allow-public-pub'), { stdout, stderr });
    expect(r.exitCode).toBe(0);
    expect(parseDecision(stdout.buf).permission).toBe('allow');
  });

  test('allowlist override via --allowlist-path lets the call through', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(
      fixture('allow-with-override'),
      { stdout, stderr },
      {
        allowlistPath: resolve(FIXTURE_ROOT, 'allow-with-override', 'allow.toml'),
      },
    );
    expect(r.exitCode).toBe(0);
    expect(stderr.buf).toBe('');
    expect(parseDecision(stdout.buf).permission).toBe('allow');
  });

  test('beforeMCPExecution → skip → allow with stderr note', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(
      JSON.stringify({
        hook_event_name: 'beforeMCPExecution',
        tool_name: 'whatever',
        tool_input: '{}',
      }),
      { stdout, stderr },
    );
    expect(r.exitCode).toBe(0);
    expect(parseDecision(stdout.buf).permission).toBe('allow');
    expect(stderr.buf).toContain('skipping');
    expect(stderr.buf).toContain('beforeMCPExecution');
  });

  test('malformed JSON → exit 1 with stderr, stdout still emits allow (config error policy)', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput('{ not json', { stdout, stderr });
    // ADR 0014 §4 config-error cell: stderr surfaces the problem,
    // stdout emits {"permission":"allow"} so the developer's session
    // is not stranded by our parser bug. failClosed in hooks.json
    // catches the real-crash case separately.
    expect(r.exitCode).toBe(1);
    expect(stderr.buf).toContain('parse error');
    expect(parseDecision(stdout.buf).permission).toBe('allow');
  });

  test('non-object JSON → exit 1, allow on stdout', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput('"just a string"', { stdout, stderr });
    expect(r.exitCode).toBe(1);
    expect(parseDecision(stdout.buf).permission).toBe('allow');
  });
});
