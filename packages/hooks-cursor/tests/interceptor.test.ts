// Unit tests for the pure Cursor interceptor (ADR 0014 §2).
// Fixtures live under tests/fixtures/hooks-cursor/.

import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { emptyAllowlist, parseAllowlist } from '@warden-sh/hooks-claude';
import { evaluateCursorToolCall } from '../src/index.ts';

const FIXTURE_ROOT = resolve(
  import.meta.dir,
  '..',
  '..',
  '..',
  'tests',
  'fixtures',
  'hooks-cursor',
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

describe('evaluateCursorToolCall — deny cases', () => {
  test('beforeReadFile ~/.ssh/id_rsa is blocked', () => {
    const input = loadInput('deny-ssh-read');
    const d = evaluateCursorToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(d.ruleId).toBe('hooks.credential-file-read');
  });

  test('beforeShellExecution cat .env is blocked by shell-read rule', () => {
    const input = loadInput('deny-bash-cat-env');
    const d = evaluateCursorToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(d.ruleId).toBe('hooks.credential-shell-read');
  });

  test('beforeShellExecution curl ... ~/.aws/credentials is blocked', () => {
    const input = loadInput('deny-pipe-network');
    const d = evaluateCursorToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(['hooks.credential-shell-read', 'hooks.credential-pipe-network']).toContain(d.ruleId);
  });

  test('beforeShellExecution openssl rsa -in ~/.ssh/id_rsa is blocked', () => {
    const d = evaluateCursorToolCall(
      {
        hook_event_name: 'beforeShellExecution',
        command: 'openssl rsa -in ~/.ssh/id_rsa -out /tmp/leak',
        cwd: '/repo',
      },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
  });

  test('relative .env path inside cwd is canonicalized and blocked', () => {
    const d = evaluateCursorToolCall(
      { hook_event_name: 'beforeReadFile', file_path: '.env' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
  });

  test('beforeShellExecution uses the event-supplied cwd over the context cwd', () => {
    // Cursor sends cwd=/var/sandbox; the explicit ./.env triggers
    // canonicalization in the tokenizer (paths starting with ./, ../,
    // /, or ~/ get absolutized). The resulting token must be resolved
    // against the event-supplied cwd, not the context cwd=/repo.
    const d = evaluateCursorToolCall(
      {
        hook_event_name: 'beforeShellExecution',
        command: 'cat ./.env',
        cwd: '/var/sandbox',
      },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('deny');
    if (d.kind !== 'deny') return;
    expect(d.reason).toContain('/var/sandbox/');
    expect(d.reason).not.toContain('/repo/');
  });
});

describe('evaluateCursorToolCall — allow cases', () => {
  test('beforeReadFile of a .pub key is allowed (public-half carve-out)', () => {
    const input = loadInput('allow-public-pub');
    const d = evaluateCursorToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('allow');
  });

  test('beforeReadFile of ~/.ssh/config is allowed (housekeeping carve-out)', () => {
    const d = evaluateCursorToolCall(
      { hook_event_name: 'beforeReadFile', file_path: '~/.ssh/config' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('beforeReadFile of .env.example is allowed', () => {
    const d = evaluateCursorToolCall(
      { hook_event_name: 'beforeReadFile', file_path: '.env.example' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('allow');
  });

  test('benign beforeReadFile passes', () => {
    const input = loadInput('allow-benign-read');
    const d = evaluateCursorToolCall(input as never, {
      home: HOME,
      cwd: CWD,
      allowlist: emptyAllowlist(),
    });
    expect(d.kind).toBe('allow');
  });

  test('beforeMCPExecution is deferred → skip (ADR 0014 §10)', () => {
    const d = evaluateCursorToolCall(
      {
        hook_event_name: 'beforeMCPExecution',
        tool_name: 'whatever',
        tool_input: '{"path":"~/.ssh/id_rsa"}',
      },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('skip');
    if (d.kind !== 'skip') return;
    expect(d.why).toContain('beforeMCPExecution');
  });

  test('afterFileEdit is unrecognized → skip → allow at the runner', () => {
    const d = evaluateCursorToolCall(
      { hook_event_name: 'afterFileEdit', file_path: '/tmp/x' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('skip');
  });

  test('missing required field → skip (cooperative)', () => {
    const d = evaluateCursorToolCall(
      { hook_event_name: 'beforeReadFile' },
      { home: HOME, cwd: CWD, allowlist: emptyAllowlist() },
    );
    expect(d.kind).toBe('skip');
  });
});

describe('evaluateCursorToolCall — allowlist override', () => {
  test('allow.toml entry permits the otherwise-blocked path', () => {
    const input = loadInput('allow-with-override');
    const allowlist = loadAllowlist('allow-with-override');
    const d = evaluateCursorToolCall(input as never, {
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
          rule: 'hooks.credential-shell-read',
          path: '~/.aws/credentials',
          commandPattern: null,
          reason: 'test',
        },
      ],
    };
    const d = evaluateCursorToolCall(
      { hook_event_name: 'beforeReadFile', file_path: '~/.aws/credentials' },
      { home: HOME, cwd: CWD, allowlist },
    );
    expect(d.kind).toBe('deny');
  });

  test('command-pattern allowlist permits a matching beforeShellExecution', () => {
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
    const d = evaluateCursorToolCall(
      {
        hook_event_name: 'beforeShellExecution',
        command: 'openssl dec -in ~/.gnupg/secring.gpg',
      },
      { home: HOME, cwd: CWD, allowlist },
    );
    expect(d.kind).toBe('allow');
  });
});

describe('cross-vendor parity with M6 (ADR 0014 §11)', () => {
  // For each malicious M6 fixture under tests/fixtures/hooks-claude/,
  // its Cursor-shaped equivalent under tests/fixtures/hooks-cursor/
  // must fire the same rule ID. This is the load-bearing check that
  // the rule pack in @warden-sh/rules stays vendor-independent: if a
  // rule starts behaving differently on Claude vs Cursor inputs, this
  // test fails.
  type Case = {
    readonly name: string;
    readonly cursorFixture: string;
    readonly expectedRuleId: ReadonlyArray<string>;
  };
  const cases: ReadonlyArray<Case> = [
    {
      name: 'SSH private key read',
      cursorFixture: 'deny-ssh-read',
      expectedRuleId: ['hooks.credential-file-read'],
    },
    {
      name: 'Bash cat .env',
      cursorFixture: 'deny-bash-cat-env',
      expectedRuleId: ['hooks.credential-shell-read'],
    },
    {
      name: 'Bash curl + credential',
      cursorFixture: 'deny-pipe-network',
      expectedRuleId: ['hooks.credential-shell-read', 'hooks.credential-pipe-network'],
    },
  ];

  for (const c of cases) {
    test(`${c.name} — same rule fires on Cursor input as on Claude`, () => {
      const input = loadInput(c.cursorFixture);
      const d = evaluateCursorToolCall(input as never, {
        home: HOME,
        cwd: CWD,
        allowlist: emptyAllowlist(),
      });
      expect(d.kind).toBe('deny');
      if (d.kind !== 'deny') return;
      expect(c.expectedRuleId).toContain(d.ruleId);
    });
  }
});
