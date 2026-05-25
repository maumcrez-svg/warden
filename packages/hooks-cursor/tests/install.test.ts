// Unit tests for the Cursor installer (ADR 0014 §8).

import { describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installCursorHook, mergeHooksFile } from '../src/install.ts';

class StringWriter {
  buf = '';
  write(s: string): boolean {
    this.buf += s;
    return true;
  }
}

function newHome(): string {
  return mkdtempSync(join(tmpdir(), 'warden-cursor-install-'));
}

describe('installCursorHook', () => {
  test('creates hooks.json and the wrapper script when neither exists', () => {
    const home = newHome();
    const out = new StringWriter();
    const err = new StringWriter();
    const r = installCursorHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: out, stderr: err },
    );
    expect(r.exitCode).toBe(0);
    expect(r.changed).toBe(true);
    expect(existsSync(r.hooksJsonPath)).toBe(true);
    expect(existsSync(r.hookScriptPath)).toBe(true);

    const file = JSON.parse(readFileSync(r.hooksJsonPath, 'utf8')) as {
      hooks?: {
        beforeReadFile?: Array<{ command?: string; failClosed?: boolean }>;
        beforeShellExecution?: Array<{ command?: string; failClosed?: boolean }>;
      };
    };
    const readEntries = file.hooks?.beforeReadFile ?? [];
    const shellEntries = file.hooks?.beforeShellExecution ?? [];
    expect(readEntries).toHaveLength(1);
    expect(shellEntries).toHaveLength(1);
    expect(readEntries[0]?.command).toContain('cursor-pre-tool-use.sh');
    expect(shellEntries[0]?.command).toContain('cursor-pre-tool-use.sh');
    // failClosed:true is required per ADR 0014 §8 (Warden runtime
    // crash → block, not silent pass).
    expect(readEntries[0]?.failClosed).toBe(true);
    expect(shellEntries[0]?.failClosed).toBe(true);

    const script = readFileSync(r.hookScriptPath, 'utf8');
    expect(script).toContain('#!/usr/bin/env bash');
    expect(script).toContain('warden-managed');
    expect(script).toContain('/abs/bin/warden');
    expect(script).toContain('hooks run cursor');
  });

  test('is idempotent — running twice produces a byte-identical hooks.json', () => {
    const home = newHome();
    const streams = { stdout: new StringWriter(), stderr: new StringWriter() };
    const r1 = installCursorHook({ home, wardenBinPath: '/abs/bin/warden' }, streams);
    expect(r1.exitCode).toBe(0);
    const after1 = readFileSync(r1.hooksJsonPath, 'utf8');
    const wrapperAfter1 = readFileSync(r1.hookScriptPath, 'utf8');

    const r2 = installCursorHook({ home, wardenBinPath: '/abs/bin/warden' }, streams);
    expect(r2.exitCode).toBe(0);
    expect(r2.changed).toBe(false);
    const after2 = readFileSync(r2.hooksJsonPath, 'utf8');
    const wrapperAfter2 = readFileSync(r2.hookScriptPath, 'utf8');
    expect(after1).toBe(after2);
    expect(wrapperAfter1).toBe(wrapperAfter2);
  });

  test('preserves unrelated hooks.json keys', () => {
    const home = newHome();
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(
      join(home, '.cursor', 'hooks.json'),
      JSON.stringify(
        {
          notes: 'user-managed comments',
          hooks: {
            stop: [{ command: '/abs/audit.sh' }],
          },
        },
        null,
        2,
      ),
    );
    const r = installCursorHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
    const file = JSON.parse(readFileSync(r.hooksJsonPath, 'utf8')) as {
      notes?: string;
      hooks?: { stop?: Array<{ command?: string }>; beforeReadFile?: unknown };
    };
    expect(file.notes).toBe('user-managed comments');
    expect(file.hooks?.stop?.[0]?.command).toBe('/abs/audit.sh');
    expect(file.hooks?.beforeReadFile).toBeDefined();
  });

  test('replaces an existing Warden entry without duplicating it', () => {
    const home = newHome();
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(
      join(home, '.cursor', 'hooks.json'),
      JSON.stringify(
        {
          hooks: {
            beforeReadFile: [{ command: '/old/path/cursor-pre-tool-use.sh', failClosed: true }],
          },
        },
        null,
        2,
      ),
    );
    const r = installCursorHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
    const file = JSON.parse(readFileSync(r.hooksJsonPath, 'utf8')) as {
      hooks: { beforeReadFile: Array<{ command: string }> };
    };
    const cmds = file.hooks.beforeReadFile.map((e) => e.command);
    expect(cmds).toHaveLength(1);
    expect(cmds[0]).toContain('cursor-pre-tool-use.sh');
    expect(cmds[0]).not.toContain('/old/path');
  });

  test('refuses to overwrite a non-Warden hook for the same event (without --force)', () => {
    const home = newHome();
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(
      join(home, '.cursor', 'hooks.json'),
      JSON.stringify(
        {
          hooks: {
            beforeReadFile: [{ command: '/usr/local/bin/other-tool' }],
          },
        },
        null,
        2,
      ),
    );
    const err = new StringWriter();
    const r = installCursorHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: err },
    );
    expect(r.exitCode).toBe(1);
    expect(err.buf).toContain('non-Warden hook entries');
    expect(err.buf).toContain('beforeReadFile');
  });

  test('--force overwrites a non-Warden hook', () => {
    const home = newHome();
    mkdirSync(join(home, '.cursor'), { recursive: true });
    writeFileSync(
      join(home, '.cursor', 'hooks.json'),
      JSON.stringify(
        {
          hooks: {
            beforeReadFile: [{ command: '/usr/local/bin/other-tool' }],
          },
        },
        null,
        2,
      ),
    );
    const r = installCursorHook(
      { home, force: true, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
  });
});

describe('mergeHooksFile (pure)', () => {
  test('starts from an empty hooks key when the file is empty', () => {
    const out = mergeHooksFile({}, '/abs/script.sh', { force: false });
    expect(out.conflicts).toHaveLength(0);
    expect(out.file.hooks).toBeDefined();
  });

  test('registers both beforeReadFile and beforeShellExecution', () => {
    const out = mergeHooksFile({}, '/abs/script.sh', { force: false });
    const h = out.file.hooks as Record<string, unknown>;
    expect(h.beforeReadFile).toBeDefined();
    expect(h.beforeShellExecution).toBeDefined();
  });

  test('does NOT register a Warden entry for beforeMCPExecution (deferred)', () => {
    const out = mergeHooksFile({}, '/abs/script.sh', { force: false });
    const h = out.file.hooks as Record<string, unknown>;
    expect(h.beforeMCPExecution).toBeUndefined();
  });
});
