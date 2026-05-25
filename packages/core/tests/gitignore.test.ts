import { describe, expect, test } from 'bun:test';
import { parseGitignore } from '../src/gitignore.ts';

describe('parseGitignore', () => {
  test('skips comments and blank lines', () => {
    const out = parseGitignore('# header\n\n# another\n');
    expect(out.patterns).toEqual([]);
    expect(out.unsupported).toEqual([]);
  });

  test('unanchored name becomes both file and directory globs', () => {
    const out = parseGitignore('node_modules\n');
    expect(out.patterns).toEqual(['**/node_modules', '**/node_modules/**']);
  });

  test('trailing slash yields directory-only glob', () => {
    const out = parseGitignore('build/\n');
    expect(out.patterns).toEqual(['**/build/**']);
  });

  test('anchored leading slash is not prefixed with **/', () => {
    const out = parseGitignore('/dist\n');
    expect(out.patterns).toEqual(['dist', 'dist/**']);
  });

  test('extension wildcard passes through', () => {
    const out = parseGitignore('*.log\n');
    expect(out.patterns).toEqual(['**/*.log', '**/*.log/**']);
  });

  test('negation patterns recorded as unsupported', () => {
    const out = parseGitignore('!important.md\n');
    expect(out.patterns).toEqual([]);
    expect(out.unsupported).toEqual(['!important.md']);
  });

  test('mixed file with comments and patterns', () => {
    const out = parseGitignore('# logs\n*.log\n\n# build\ndist/\n!keep.txt\n');
    expect(out.patterns).toEqual(['**/*.log', '**/*.log/**', '**/dist/**']);
    expect(out.unsupported).toEqual(['!keep.txt']);
  });
});
