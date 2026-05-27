// npm package-lock.json (v2/v3) parser. ADR 0016 §1, §3.
//
// Format reference:
//   https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
//   (verified 2026-05-25).
//
// Shape:
//   {
//     "lockfileVersion": 2 | 3,
//     "packages": {
//       "": { "name": "...", "version": "...", "dependencies": {...}, "devDependencies": {...} },
//       "node_modules/<name>": { "version": "1.0.0", ... },
//       "node_modules/<name>/node_modules/<inner>": { "version": "...", ... }
//     }
//   }
//
// The root entry `packages[""]` enumerates direct production +
// development dependencies. Every other entry is transitive (unless
// the same name shows up in the root direct/dev sets — workspace edges
// can produce that intersection but it doesn't change classification).
//
// v1 lockfiles (only `dependencies` tree, no `packages` map) are
// deferred per ADR 0016 §1 — they return `kind: 'error'` with a
// recognizable message so the orchestrator can skip without aborting
// the scan.

import type { LockfileEntry, LockfileParseResult } from './types.ts';

type NpmRootPackageEntry = {
  readonly version?: unknown;
  readonly dependencies?: unknown;
  readonly devDependencies?: unknown;
};

export function parseNpmLockfile(content: string): LockfileParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { kind: 'error', message: `package-lock.json JSON parse error: ${msg}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { kind: 'error', message: 'package-lock.json root is not a JSON object' };
  }
  const root = parsed as Record<string, unknown>;
  const version = root.lockfileVersion;
  if (version !== 2 && version !== 3) {
    return {
      kind: 'error',
      message: `unsupported lockfileVersion ${String(version)} (M9 supports v2/v3 only)`,
    };
  }
  const packages = root.packages;
  if (packages === undefined || typeof packages !== 'object' || packages === null) {
    return { kind: 'error', message: 'package-lock.json missing "packages" map' };
  }

  const pkgMap = packages as Record<string, NpmRootPackageEntry | undefined>;
  const rootEntry = pkgMap[''] ?? {};
  const directNames = new Set<string>();
  const collect = (record: unknown): void => {
    if (record === null || typeof record !== 'object' || Array.isArray(record)) return;
    for (const k of Object.keys(record as Record<string, unknown>)) directNames.add(k);
  };
  collect(rootEntry.dependencies);
  collect(rootEntry.devDependencies);

  const entries: LockfileEntry[] = [];
  for (const [key, raw] of Object.entries(pkgMap)) {
    if (key === '') continue; // root entry is the workspace, not a dep
    if (raw === undefined || raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      continue;
    }
    const obj = raw as Record<string, unknown>;
    const version = typeof obj.version === 'string' ? obj.version : undefined;
    if (version === undefined) continue;
    // The package name is the segment after the LAST occurrence of
    // "node_modules/". This handles nested-dep duplication (multiple
    // versions of the same dep in a single tree).
    const name = nameFromPackagesKey(key);
    if (name === null) continue;
    const position = directNames.has(name) ? 'direct' : 'transitive';
    entries.push({ ecosystem: 'npm', name, version, position });
  }

  // Deterministic ordering for stable findings output.
  entries.sort((a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
  );
  return { kind: 'ok', entries };
}

function nameFromPackagesKey(key: string): string | null {
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  if (idx === -1) return null;
  const remainder = key.slice(idx + marker.length);
  if (remainder === '') return null;
  return remainder;
}
