// poetry.lock parser. ADR 0016 §1, §3.
//
// Format reference:
//   https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock
//   (verified 2026-05-25).
//
// poetry.lock does NOT flag direct packages in the lockfile itself.
// Direct names come from pyproject.toml: `[tool.poetry.dependencies]`
// and `[tool.poetry.group.*.dependencies]`. When the manifest is
// absent or unreadable, every entry is classified as direct (ADR 0016
// §3 fallback — louder than silent).
//
// poetry.lock package entries look like:
//   [[package]]
//   name = "requests"
//   version = "2.31.0"
//   ...
//   [package.dependencies]      (sub-table for the most-recent [[package]])
//   certifi = ">=2017.4.17"
//
// Our minimal TOML parser materializes `[package.dependencies]` as a
// nested `dependencies` key on the most-recent `[[package]]` entry,
// because the parser tracks ensureTable navigation through the last
// array-of-tables element when applicable. We don't need that sub-
// table here — only `name` and `version` per entry.

import { parseTomlMini, tomlArray, tomlString, tomlTable } from './toml-mini.ts';
import type { LockfileEntry, LockfileParseResult } from './types.ts';

export function parsePoetryLockfile(
  content: string,
  manifestContent: string | null,
): LockfileParseResult {
  const parsed = parseTomlMini(content);
  if (parsed.kind === 'error') {
    return {
      kind: 'error',
      message: `poetry.lock TOML parse error at line ${parsed.line}: ${parsed.message}`,
    };
  }
  const packagesRaw = tomlArray(parsed.root.package);
  if (packagesRaw === undefined) {
    return { kind: 'ok', entries: [] };
  }

  const directNames = manifestContent !== null ? poetryDirectNames(manifestContent) : null;

  const entries: LockfileEntry[] = [];
  for (const raw of packagesRaw) {
    const tbl = tomlTable(raw);
    if (tbl === undefined) continue;
    const name = tomlString(tbl.name);
    const version = tomlString(tbl.version);
    if (name === undefined || version === undefined) continue;
    // Poetry normalizes package names case-insensitively in
    // [tool.poetry.dependencies]; the lockfile may carry the canonical
    // form. We compare lowercased to match.
    const normName = name.toLowerCase();
    const position =
      directNames === null ? 'direct' : directNames.has(normName) ? 'direct' : 'transitive';
    entries.push({ ecosystem: 'PyPI', name, version, position });
  }

  entries.sort((a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
  );
  return { kind: 'ok', entries };
}

function poetryDirectNames(manifestContent: string): ReadonlySet<string> {
  const out = new Set<string>();
  const parsed = parseTomlMini(manifestContent);
  if (parsed.kind === 'error') return out;

  // [tool.poetry.dependencies]
  const tool = tomlTable(parsed.root.tool);
  const poetry = tool === undefined ? undefined : tomlTable(tool.poetry);
  if (poetry === undefined) return out;

  const direct = tomlTable(poetry.dependencies);
  if (direct !== undefined) {
    for (const k of Object.keys(direct)) {
      // Conventional: "python" is the interpreter constraint, not a
      // package to scan against PyPI advisories.
      if (k.toLowerCase() !== 'python') out.add(k.toLowerCase());
    }
  }

  // [tool.poetry.group.<name>.dependencies] — dev and other groups.
  const groups = tomlTable(poetry.group);
  if (groups !== undefined) {
    for (const groupName of Object.keys(groups)) {
      const groupTbl = tomlTable(groups[groupName]);
      if (groupTbl === undefined) continue;
      const groupDeps = tomlTable(groupTbl.dependencies);
      if (groupDeps === undefined) continue;
      for (const k of Object.keys(groupDeps)) {
        if (k.toLowerCase() !== 'python') out.add(k.toLowerCase());
      }
    }
  }

  return out;
}
