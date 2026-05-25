// Unit tests for the installer (ADR 0013 §§7-8).

import { describe, expect, test } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { installClaudeHook, mergeSettings } from '../src/install.ts';

class StringWriter {
  buf = '';
  write(s: string): boolean {
    this.buf += s;
    return true;
  }
}

function newHome(): string {
  return mkdtempSync(join(tmpdir(), 'warden-hook-install-'));
}

describe('installClaudeHook', () => {
  test('creates settings.json and the wrapper script when neither exists', () => {
    const home = newHome();
    const out = new StringWriter();
    const err = new StringWriter();
    const r = installClaudeHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: out, stderr: err },
    );
    expect(r.exitCode).toBe(0);
    expect(r.changed).toBe(true);
    expect(existsSync(r.settingsPath)).toBe(true);
    expect(existsSync(r.hookScriptPath)).toBe(true);

    const settings = JSON.parse(readFileSync(r.settingsPath, 'utf8')) as {
      hooks?: { PreToolUse?: Array<{ matcher?: string; hooks?: Array<{ command?: string }> }> };
    };
    const entries = settings.hooks?.PreToolUse ?? [];
    expect(entries).toHaveLength(1);
    expect(entries[0]?.matcher).toContain('Bash');
    expect(entries[0]?.hooks?.[0]?.command).toContain('claude-pre-tool-use.sh');

    const script = readFileSync(r.hookScriptPath, 'utf8');
    expect(script).toContain('#!/usr/bin/env bash');
    expect(script).toContain('warden-managed');
    expect(script).toContain('/abs/bin/warden');
  });

  test('is idempotent — running twice produces a byte-identical settings.json', () => {
    const home = newHome();
    const streams = { stdout: new StringWriter(), stderr: new StringWriter() };
    const r1 = installClaudeHook({ home, wardenBinPath: '/abs/bin/warden' }, streams);
    expect(r1.exitCode).toBe(0);
    const after1 = readFileSync(r1.settingsPath, 'utf8');
    const wrapperAfter1 = readFileSync(r1.hookScriptPath, 'utf8');

    const r2 = installClaudeHook({ home, wardenBinPath: '/abs/bin/warden' }, streams);
    expect(r2.exitCode).toBe(0);
    expect(r2.changed).toBe(false);
    const after2 = readFileSync(r2.settingsPath, 'utf8');
    const wrapperAfter2 = readFileSync(r2.hookScriptPath, 'utf8');
    expect(after1).toBe(after2);
    expect(wrapperAfter1).toBe(wrapperAfter2);
  });

  test('preserves unrelated settings keys', () => {
    const home = newHome();
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeFileSync(
      join(home, '.claude', 'settings.json'),
      JSON.stringify({ theme: 'dark', model: 'opus' }, null, 2),
    );
    const r = installClaudeHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
    const settings = JSON.parse(readFileSync(r.settingsPath, 'utf8')) as {
      theme?: string;
      model?: string;
      hooks?: unknown;
    };
    expect(settings.theme).toBe('dark');
    expect(settings.model).toBe('opus');
    expect(settings.hooks).toBeDefined();
  });

  test('replaces an existing Warden entry without duplicating it', () => {
    const home = newHome();
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeFileSync(
      join(home, '.claude', 'settings.json'),
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              {
                matcher: 'Read|Edit|Write|Bash|MultiEdit',
                hooks: [{ type: 'command', command: '/old/path/warden hooks run claude' }],
              },
            ],
          },
        },
        null,
        2,
      ),
    );
    const r = installClaudeHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
    const settings = JSON.parse(readFileSync(r.settingsPath, 'utf8')) as {
      hooks: { PreToolUse: Array<{ hooks: Array<{ command: string }> }> };
    };
    const entries = settings.hooks.PreToolUse;
    expect(entries).toHaveLength(1);
    const cmds = entries[0]?.hooks.map((h) => h.command) ?? [];
    expect(cmds).toHaveLength(1);
    expect(cmds[0]).toContain('claude-pre-tool-use.sh');
    expect(cmds[0]).not.toContain('/old/path/warden');
  });

  test('refuses to overwrite a non-Warden hook with the same matcher (without --force)', () => {
    const home = newHome();
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeFileSync(
      join(home, '.claude', 'settings.json'),
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              {
                matcher: 'Read|Edit|Write|Bash|MultiEdit',
                hooks: [{ type: 'command', command: '/usr/local/bin/other-tool' }],
              },
            ],
          },
        },
        null,
        2,
      ),
    );
    const err = new StringWriter();
    const r = installClaudeHook(
      { home, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: err },
    );
    expect(r.exitCode).toBe(1);
    expect(err.buf).toContain('non-Warden PreToolUse hook');
  });

  test('--force overwrites a non-Warden hook', () => {
    const home = newHome();
    mkdirSync(join(home, '.claude'), { recursive: true });
    writeFileSync(
      join(home, '.claude', 'settings.json'),
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [
              {
                matcher: 'Read|Edit|Write|Bash|MultiEdit',
                hooks: [{ type: 'command', command: '/usr/local/bin/other-tool' }],
              },
            ],
          },
        },
        null,
        2,
      ),
    );
    const r = installClaudeHook(
      { home, force: true, wardenBinPath: '/abs/bin/warden' },
      { stdout: new StringWriter(), stderr: new StringWriter() },
    );
    expect(r.exitCode).toBe(0);
  });
});

describe('mergeSettings (pure)', () => {
  test('returns the same object shape when the matcher is absent', () => {
    const out = mergeSettings({}, '/abs/script.sh', { force: false });
    expect(out.conflict).toBeNull();
    expect(out.settings.hooks).toBeDefined();
  });
});
