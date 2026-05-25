// Unit tests for the pure interceptor (ADR 0013 §2).
// Fixtures live under tests/fixtures/hooks-claude/.

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { emptyAllowlist, evaluateToolCall, parseAllowlist } from '../src/index.ts';

const FIXTURE_ROOT = resolve(
  import.meta.dir,
  '..',
  '..',
  '..',
  'tests',
  'fixtures',
  'hooks-claude',
);

function loadInput(name: string): unknown {
  const text = readFileSync(resolve(FIXTURE_ROOT, name, 'input.json'), 'utf8');
  return JSON.parse(text);
}

function loadAllowlist(name: string) {
  const text = readFileSync(resolve(FIXTURE_ROOT, name, 'allow.toml'), 'utf8');
  const r = parseAllowlist(text);
  if (r.kind !== 'ok') throw new Error(`allowlist load failed: ${r.message}`);
  return r.allowlist;
}

const HOME = '/home/test';
const CWD = '/repo';

describe('evaluateToolCall — deny cases', () => {
  test('Read ~/.ssh/id_rsa is blocked', () => {
    const input = loadInput('deny-ssh-read');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(d.ruleId).toBe('hooks.credential-file-read');
  });

  test('Bash cat .env is blocked by shell-read rule', () => {
    const input = loadInput('deny-bash-cat-env');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(d.ruleId).toBe('hooks.credential-shell-read');
  });

  test('Bash curl ... ~/.aws/credentials is blocked by pipe-network rule', () => {
    const input = loadInput('deny-pipe-network');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    // Either credential-shell-read OR credential-pipe-network would be
    // accurate; the rule pack iterates in order and the first match
    // wins. We assert on T5 coverage either way.
    expect(['hooks.credential-shell-read', 'hooks.credential-pipe-network']).toContain(d.ruleId);
  });

  test('Bash openssl rsa -in ~/.ssh/id_rsa is blocked', () => {
    const d = evaluateToolCall(
      {
        tool_name: 'Bash',
        tool_input: { command: 'openssl rsa -in ~/.ssh/id_rsa -out /tmp/leak' },
      },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
  });

  test('Write to ~/.aws/credentials is blocked (write rule, not just read)', () => {
    const d = evaluateToolCall(
      { tool_name: 'Write', tool_input: { file_path: '~/.aws/credentials' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
  });

  test('relative .env path inside cwd is canonicalized and blocked', () => {
    const d = evaluateToolCall(
      { tool_name: 'Read', tool_input: { file_path: '.env' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
  });
});

describe('evaluateToolCall — allow cases', () => {
  test('Read of a public-half SSH key (.pub) is allowed', () => {
    const input = loadInput('allow-public-pub');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('allow');
  });

  test('Read of ~/.ssh/config is allowed (housekeeping carve-out)', () => {
    const d = evaluateToolCall(
      { tool_name: 'Read', tool_input: { file_path: '~/.ssh/config' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('Read of ~/.ssh/known_hosts is allowed', () => {
    const d = evaluateToolCall(
      { tool_name: 'Read', tool_input: { file_path: '~/.ssh/known_hosts' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('Read of .env.example is allowed', () => {
    const d = evaluateToolCall(
      { tool_name: 'Read', tool_input: { file_path: '.env.example' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('benign Read passes', () => {
    const input = loadInput('allow-benign-read');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('allow');
  });

  test('an unknown tool name short-circuits to allow', () => {
    const d = evaluateToolCall(
      { tool_name: 'WebFetch', tool_input: { url: 'https://example.com' } },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('missing tool_input → skip (cooperative)', () => {
    const d = evaluateToolCall(
      { tool_name: 'Read' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('skip');
  });
});

describe('evaluateToolCall — allowlist override', () => {
  test('allow.toml entry permits the otherwise-blocked path', () => {
    const input = loadInput('allow-with-override');
    const allowlist = loadAllowlist('allow-with-override');
    const d = evaluateToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist,
    });
    expect(d.kind).toBe('allow');
  });

  test('mismatched rule in allowlist does NOT permit the call', () => {
    const allowlist = {
      schema: 'v1' as const,
      entries: [
        {
          rule: 'hooks.credential-shell-read', // wrong rule for a Read tool
          path: '~/.aws/credentials',
          commandPattern: null,
          reason: 'test',
        },
      ],
    };
    const d = evaluateToolCall(
      { tool_name: 'Read', tool_input: { file_path: '~/.aws/credentials' } },
      { home: HOME, cwd: CWD, allowlist },
    );
    expect(d.kind).toBe('deny');
  });

  test('command-pattern allowlist permits a matching Bash invocation', () => {
    const allowlist = {
      schema: 'v1' as const,
      entries: [
        {
          rule: 'hooks.credential-shell-read',
          path: null,
          commandPattern: '^openssl dec ',
          reason: 'release decrypt step',
        },
      ],
    };
    const d = evaluateToolCall(
      { tool_name: 'Bash', tool_input: { command: 'openssl dec -in ~/.gnupg/secring.gpg' } },
      { home: HOME, cwd: CWD, allowlist },
    );
    expect(d.kind).toBe('allow');
  });
});
