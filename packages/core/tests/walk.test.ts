import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { walk } from '../src/walk.ts';

function makeTree(): string {
  const root = mkdtempSync(join(tmpdir(), 'warden-walk-'));
  // Files
  writeFileSync(join(root, 'CLAUDE.md'), '# top\n');
  writeFileSync(join(root, 'README.md'), '# readme\n');
  writeFileSync(join(root, 'package.json'), '{}\n');
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src', 'index.ts'), 'export {};\n');
  mkdirSync(join(root, 'docs'));
  writeFileSync(join(root, 'docs', 'guide.md'), '# guide\n');
  mkdirSync(join(root, 'node_modules', 'foo'), { recursive: true });
  writeFileSync(join(root, 'node_modules', 'foo', 'index.js'), '// vendor\n');
  mkdirSync(join(root, 'dist'));
  writeFileSync(join(root, 'dist', 'bundle.js'), '// build\n');
  mkdirSync(join(root, '.git'));
  writeFileSync(join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
  writeFileSync(join(root, '.gitignore'), 'dist/\n');
  return root;
}

describe('walk', () => {
  let root = '';

  beforeEach(() => {
    root = makeTree();
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  test('always skips .git and node_modules', () => {
    const out = walk(root);
    for (const f of out.files) {
      expect(f.startsWith('.git/')).toBe(false);
      expect(f.startsWith('node_modules/')).toBe(false);
    }
  });

  test('honors .gitignore (dist/)', () => {
    const out = walk(root);
    for (const f of out.files) {
      expect(f.startsWith('dist/')).toBe(false);
    }
  });

  test('returns deterministic lexicographic order', () => {
    const out = walk(root);
    const sorted = [...out.files].sort();
    expect(out.files).toEqual(sorted);
  });

  test('respectGitignore: false includes dist contents', () => {
    const out = walk(root, { respectGitignore: false });
    expect(out.files.some((f) => f.startsWith('dist/'))).toBe(true);
  });

  test('includes nested markdown files', () => {
    const out = walk(root);
    expect(out.files).toContain('CLAUDE.md');
    expect(out.files).toContain('README.md');
    expect(out.files).toContain('docs/guide.md');
  });

  test('honors .wardenignore on top of .gitignore', () => {
    writeFileSync(join(root, '.wardenignore'), 'README.md\n');
    const out = walk(root);
    expect(out.files).not.toContain('README.md');
    expect(out.files).toContain('CLAUDE.md');
  });

  test('reports unsupported negation patterns', () => {
    writeFileSync(join(root, '.wardenignore'), '!keep.md\n');
    const out = walk(root);
    expect(out.unsupportedGitignorePatterns).toEqual(['!keep.md']);
  });

  test('non-existent root returns empty', () => {
    const out = walk(resolve(root, 'does-not-exist'));
    expect(out.files).toEqual([]);
  });

  test('single-file root is returned as-is', () => {
    const out = walk(join(root, 'CLAUDE.md'));
    expect(out.files).toEqual(['CLAUDE.md']);
  });
});
