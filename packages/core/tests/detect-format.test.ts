import { describe, expect, test } from 'bun:test';
import { type FileKind, detectFormat } from '../src/detect-format.ts';

describe('detectFormat — named agent-context files', () => {
  const cases: ReadonlyArray<readonly [string, FileKind]> = [
    ['CLAUDE.md', 'claude-md'],
    ['repo/CLAUDE.md', 'claude-md'],
    ['AGENTS.md', 'agents-md'],
    ['.cursorrules', 'cursorrules'],
    ['nested/.cursorrules', 'cursorrules'],
    ['.cursor/rules/foo.mdc', 'cursor-rule'],
    ['project/.cursor/rules/bar.mdc', 'cursor-rule'],
    ['.windsurfrules', 'windsurfrules'],
    ['.clinerules', 'clinerules'],
    ['.aider.conf.yml', 'aider-conf'],
    ['.github/copilot-instructions.md', 'copilot-instructions'],
    ['some/project/.github/copilot-instructions.md', 'copilot-instructions'],
    ['mcp.json', 'mcp-json'],
    ['config/mcp.json', 'mcp-json'],
  ];
  for (const [path, kind] of cases) {
    test(`${path} -> ${kind}`, () => {
      expect(detectFormat(path)).toBe(kind);
    });
  }
});

describe('detectFormat — skill files', () => {
  const cases: ReadonlyArray<string> = [
    '.claude/commands/verify.md',
    'project/.claude/commands/milestone.md',
    '.claude/skills/foo/SKILL.md',
    'skills/bar/SKILL.md',
    'SKILL.md',
    'nested/dir/SKILL.md',
  ];
  for (const path of cases) {
    test(`${path} -> skill-md`, () => {
      expect(detectFormat(path)).toBe('skill-md');
    });
  }
});

describe('detectFormat — generic markdown fallback', () => {
  test('plain README.md', () => {
    expect(detectFormat('README.md')).toBe('markdown');
  });
  test('CHANGELOG.md', () => {
    expect(detectFormat('CHANGELOG.md')).toBe('markdown');
  });
  test('docs/anything.md', () => {
    expect(detectFormat('docs/anything.md')).toBe('markdown');
  });
  test('.markdown extension', () => {
    expect(detectFormat('notes.markdown')).toBe('markdown');
  });
  test('case-insensitive .md extension', () => {
    expect(detectFormat('NOTES.MD')).toBe('markdown');
  });
});

describe('detectFormat — .mdc is cursor-rule even outside .cursor/rules/', () => {
  test('rules/something.mdc -> cursor-rule', () => {
    expect(detectFormat('rules/something.mdc')).toBe('cursor-rule');
  });
  test('top-level something.mdc -> cursor-rule', () => {
    expect(detectFormat('something.mdc')).toBe('cursor-rule');
  });
});

describe('detectFormat — non-candidates return null', () => {
  const cases: ReadonlyArray<string> = [
    'package.json', // covered by M4 (MCP), not blanket json
    'src/index.ts',
    'image.png',
    'a/b/c.css',
    '.env',
    '.env.local',
    'random.yaml',
  ];
  for (const path of cases) {
    test(`${path} -> null`, () => {
      expect(detectFormat(path)).toBeNull();
    });
  }
});

describe('detectFormat — lockfiles (ADR 0016)', () => {
  const cases: ReadonlyArray<readonly [string, FileKind]> = [
    ['package-lock.json', 'npm-lockfile'],
    ['repo/package-lock.json', 'npm-lockfile'],
    ['poetry.lock', 'poetry-lockfile'],
    ['svc/poetry.lock', 'poetry-lockfile'],
    ['uv.lock', 'uv-lockfile'],
    ['py-app/uv.lock', 'uv-lockfile'],
    ['Cargo.lock', 'cargo-lockfile'],
    ['rust-app/Cargo.lock', 'cargo-lockfile'],
  ];
  for (const [path, kind] of cases) {
    test(`${path} -> ${kind}`, () => {
      expect(detectFormat(path)).toBe(kind);
    });
  }
});

describe('detectFormat — markdown casing', () => {
  test('lowercase claude.md falls into generic markdown (CLAUDE.md is the named kind)', () => {
    expect(detectFormat('claude.md')).toBe('markdown');
  });
});

describe('detectFormat — backslash normalization (Windows-style)', () => {
  test('backslashed CLAUDE.md', () => {
    expect(detectFormat('project\\CLAUDE.md')).toBe('claude-md');
  });
  test('backslashed cursor rule', () => {
    expect(detectFormat('.cursor\\rules\\foo.mdc')).toBe('cursor-rule');
  });
});
