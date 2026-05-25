// File walker for `warden scan`. Walks a directory using Bun's Glob,
// applies always-ignored paths (.git, node_modules), the project's
// .gitignore and .wardenignore (when respectGitignore is true, the
// default), and returns a deterministic sorted list of repo-relative
// paths.
//
// .wardenignore uses the same syntax as .gitignore. It exists so a
// project can exclude paths from Warden scans that legitimately belong
// in version control — e.g., test fixtures containing intentional
// malicious payloads. See docs/DECISIONS/0006-file-walker-and-format-detection.md
// §"`.wardenignore`".
//
// Symlinks are not followed: the scanner's threat model treats them as
// outside the trust boundary of the scanned root.

import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { Glob } from 'bun';
import { parseGitignore } from './gitignore.ts';

const ALWAYS_IGNORE: ReadonlyArray<string> = [
  '**/.git/**',
  '.git/**',
  '**/node_modules/**',
  'node_modules/**',
  // ADR 0012 §7.3 — trust manifest contains hash + signature blobs
  // (base64 → false-positive for credential detection) and free-text
  // reason fields (potential prompt-injection match). The verify path
  // reads the manifest as data, never feeds it to detectors.
  '**/.warden/trust/**',
  '.warden/trust/**',
];

export type WalkOptions = {
  readonly respectGitignore?: boolean;
};

export type WalkResult = {
  readonly root: string;
  readonly files: ReadonlyArray<string>;
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
};

function fileExists(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function walk(rootPath: string, opts: WalkOptions = {}): WalkResult {
  const root = resolve(rootPath);
  const respectGitignore = opts.respectGitignore !== false;

  // Single-file targets bypass the walker — scan exactly the path given.
  if (isDirectory(root) === false && fileExists(root)) {
    return { root, files: [root.split('/').pop() ?? root], unsupportedGitignorePatterns: [] };
  }

  // Non-existent or non-directory root: return empty rather than throwing.
  // The CLI is responsible for surfacing the user-facing "path not found"
  // message via existsSync() before invoking walk.
  if (!isDirectory(root)) {
    return { root, files: [], unsupportedGitignorePatterns: [] };
  }

  let ignorePatterns: string[] = [...ALWAYS_IGNORE];
  const unsupported: string[] = [];

  if (respectGitignore) {
    for (const ignoreFile of ['.gitignore', '.wardenignore']) {
      try {
        const text = readFileSync(resolve(root, ignoreFile), 'utf8');
        const parsed = parseGitignore(text);
        ignorePatterns = [...ignorePatterns, ...parsed.patterns];
        unsupported.push(...parsed.unsupported);
      } catch {
        // File absent — proceed without it.
      }
    }
  }

  const ignoreGlobs = ignorePatterns.map((p) => new Glob(p));
  const all = new Glob('**/*');
  const out: string[] = [];

  for (const rel of all.scanSync({
    cwd: root,
    onlyFiles: true,
    dot: true,
    followSymlinks: false,
  })) {
    let skip = false;
    for (const ig of ignoreGlobs) {
      if (ig.match(rel)) {
        skip = true;
        break;
      }
    }
    if (skip) continue;
    out.push(rel);
  }

  out.sort();
  return { root, files: out, unsupportedGitignorePatterns: unsupported };
}
