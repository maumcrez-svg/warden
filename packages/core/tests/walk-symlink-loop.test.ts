import { describe, expect, test } from 'bun:test';
import { lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { walk } from '../src/walk.ts';

// Regression: a directory containing a symlink loop
// (dir-a/link-to-b -> ../dir-b and dir-b/link-to-a -> ../dir-a)
// must not cause the walker to recurse forever. The walker passes
// `followSymlinks: false` to Bun.Glob.scanSync, so symlinks — including
// symlinks-to-directories — are not traversed and the loop is
// structurally impossible to enter. Origin: M2 review (post-6d0117b).
//
// The fixture under tests/fixtures/symlink-loop/ commits real symlinks
// (git mode 120000). On Windows without symlink privileges the entries
// may materialize as regular files; the lstat guard below skips the
// test in that case rather than producing a misleading failure.

const REPO_ROOT = resolve(import.meta.dir, '../../..');
const FIXTURE = resolve(REPO_ROOT, 'tests/fixtures/symlink-loop');
const LINK_A = resolve(FIXTURE, 'dir-a/link-to-b');
const LINK_B = resolve(FIXTURE, 'dir-b/link-to-a');

function symlinksPresent(): boolean {
  try {
    return lstatSync(LINK_A).isSymbolicLink() && lstatSync(LINK_B).isSymbolicLink();
  } catch {
    return false;
  }
}

describe('walk — symlink loop resilience', () => {
  test.skipIf(!symlinksPresent())('terminates under 2s and returns only the two real files', () => {
    const t0 = Date.now();
    const out = walk(FIXTURE);
    const elapsed = Date.now() - t0;

    expect(elapsed).toBeLessThan(2000);
    expect(out.files).toEqual(['dir-a/real-file.md', 'dir-b/real-file.md']);
    expect(out.unsupportedGitignorePatterns).toEqual([]);
  });
});
