// End-to-end test of the runtime hook entry: stdin JSON → decision +
// exit code (ADR 0013 §§3-4). Uses runOnInput directly so we don't
// depend on shell or subprocess plumbing.

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
  'hooks-claude',
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

describe('runOnInput', () => {
  test('Read ~/.ssh/id_rsa → exit 2 + stderr "blocked"', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('deny-ssh-read'), { stdout, stderr });
    expect(r.exitCode).toBe(2);
    expect(stderr.buf).toContain('warden: blocked by hooks.credential-file-read');
  });

  test('benign Read → exit 0, no stdout, no stderr', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('allow-benign-read'), { stdout, stderr });
    expect(r.exitCode).toBe(0);
    expect(stdout.buf).toBe('');
    expect(stderr.buf).toBe('');
  });

  test('allowlist override via --allowlist-path lets the call through', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(
      fixture('allow-with-override'),
      {
        stdout,
        stderr,
      },
      {
        allowlistPath: resolve(FIXTURE_ROOT, 'allow-with-override', 'allow.toml'),
      },
    );
    expect(r.exitCode).toBe(0);
    expect(stderr.buf).toBe('');
  });

  test('--json-output emits decision on stdout and exits 0', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput(fixture('deny-ssh-read'), { stdout, stderr }, { jsonOutput: true });
    expect(r.exitCode).toBe(0);
    expect(stderr.buf).toBe('');
    const obj = JSON.parse(stdout.buf) as { decision: string; reason: string };
    expect(obj.decision).toBe('block');
    expect(obj.reason).toContain('hooks.credential-file-read');
  });

  test('malformed JSON → exit 1 with stderr', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput('{ not json', { stdout, stderr });
    expect(r.exitCode).toBe(1);
    expect(stderr.buf).toContain('parse error');
  });

  test('non-object JSON → exit 1', () => {
    const stdout = new StringWriter();
    const stderr = new StringWriter();
    const r = runOnInput('"just a string"', { stdout, stderr });
    expect(r.exitCode).toBe(1);
  });
});
