// Unit tests for the allow.toml parser (ADR 0013 §6).

import { describe, expect, test } from 'bun:test';
import { parseAllowlist } from '../src/allowlist.ts';

describe('parseAllowlist', () => {
  test('well-formed allowlist with one path entry', () => {
    const text = [
      'schema = "v1"',
      '',
      '[[allow]]',
      'rule = "hooks.credential-file-read"',
      'path = "~/.aws/credentials"',
      'reason = "ci deploy"',
      '',
    ].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    expect(r.allowlist.entries).toHaveLength(1);
    const e = r.allowlist.entries[0];
    if (e === undefined) throw new Error('no entry');
    expect(e.rule).toBe('hooks.credential-file-read');
    expect(e.path).toBe('~/.aws/credentials');
    expect(e.commandPattern).toBeNull();
  });

  test('command-pattern entry', () => {
    const text = [
      'schema = "v1"',
      '[[allow]]',
      'rule = "hooks.credential-shell-read"',
      'command-pattern = "^openssl dec.*"',
      'reason = "release decrypt"',
    ].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('ok');
    if (r.kind !== 'ok') return;
    const e = r.allowlist.entries[0];
    if (e === undefined) throw new Error('no entry');
    expect(e.commandPattern).toBe('^openssl dec.*');
    expect(e.path).toBeNull();
  });

  test('missing schema → error', () => {
    const text = '[[allow]]\nrule = "x"\npath = "y"\nreason = "z"\n';
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
  });

  test('unknown schema → error with line number', () => {
    const text = 'schema = "v99"\n';
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
    if (r.kind !== 'error') return;
    expect(r.line).toBe(1);
    expect(r.message).toContain('unsupported schema');
  });

  test('block missing rule → error', () => {
    const text = ['schema = "v1"', '[[allow]]', 'path = "x"', 'reason = "y"'].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
    if (r.kind !== 'error') return;
    expect(r.message).toContain('requires `rule');
  });

  test('block missing reason → error', () => {
    const text = ['schema = "v1"', '[[allow]]', 'rule = "x"', 'path = "y"'].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
    if (r.kind !== 'error') return;
    expect(r.message).toContain('reason');
  });

  test('block with neither path nor command-pattern → error', () => {
    const text = ['schema = "v1"', '[[allow]]', 'rule = "x"', 'reason = "y"'].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
  });

  test('block with both path and command-pattern → error', () => {
    const text = [
      'schema = "v1"',
      '[[allow]]',
      'rule = "x"',
      'path = "p"',
      'command-pattern = "c"',
      'reason = "z"',
    ].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
    if (r.kind !== 'error') return;
    expect(r.message).toContain('at most one');
  });

  test('invalid regex in command-pattern → error', () => {
    const text = [
      'schema = "v1"',
      '[[allow]]',
      'rule = "x"',
      'command-pattern = "[unclosed"',
      'reason = "z"',
    ].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
    if (r.kind !== 'error') return;
    expect(r.message).toContain('invalid command-pattern regex');
  });

  test('empty reason → error', () => {
    const text = ['schema = "v1"', '[[allow]]', 'rule = "x"', 'path = "y"', 'reason = "   "'].join(
      '\n',
    );
    const r = parseAllowlist(text);
    expect(r.kind).toBe('error');
  });

  test('comments and blank lines are tolerated', () => {
    const text = [
      '# header',
      '',
      'schema = "v1"',
      '# describing the next entry',
      '[[allow]]',
      'rule = "a"',
      'path = "b"',
      'reason = "c"',
    ].join('\n');
    const r = parseAllowlist(text);
    expect(r.kind).toBe('ok');
  });
});
