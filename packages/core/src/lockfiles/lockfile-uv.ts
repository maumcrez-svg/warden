// uv.lock parser. ADR 0016 §1, §3.
//
// Format reference:
//   https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile
//   (verified 2026-05-25).
//
// uv.lock entries:
//   [[package]]
//   name = "requests"
//   version = "2.32.3"
//   source = { registry = "https://pypi.org/simple" }
//   dependencies = [
//     { name = "certifi" },
//     { name = "charset-normalizer" },
//     ...
//   ]
//
// Direct vs transitive:
//   The project itself appears as a [[package]] entry with
//   `source = { virtual = "." }` (or sometimes editable = "..."). Its
//   `dependencies = [{ name = "..." }]` array enumerates the direct
//   names. ADR 0016 §3: when no virtual entry is found, treat all
//   entries as direct (older uv.lock files without virtual sources).

import { parseTomlMini, tomlArray, tomlString, tomlTable } from './toml-mini.ts';
import type { LockfileEntry, LockfileParseResult } from './types.ts';

export function parseUvLockfile(content: string): LockfileParseResult {
  const parsed = parseTomlMini(content);
  if (parsed.kind === 'error') {
    return {
      kind: 'error',
      message: `uv.lock TOML parse error at line ${parsed.line}: ${parsed.message}`,
    };
  }
  const packagesRaw = tomlArray(parsed.root.package);
  if (packagesRaw === undefined) {
    return { kind: 'ok', entries: [] };
  }

  const directNames = directNamesFromUvVirtual(packagesRaw);

  const entries: LockfileEntry[] = [];
  for (const raw of packagesRaw) {
    const tbl = tomlTable(raw);
    if (tbl === undefined) continue;
    if (isVirtualPackage(tbl)) continue; // project itself; not a dep
    const name = tomlString(tbl.name);
    const version = tomlString(tbl.version);
    if (name === undefined || version === undefined) continue;
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

function isVirtualPackage(tbl: Record<string, unknown>): boolean {
  const source = tomlTable(tbl.source as never);
  if (source === undefined) return false;
  if (typeof source.virtual === 'string') return true;
  if (typeof source.editable === 'string') return true;
  return false;
}

function directNamesFromUvVirtual(packages: ReadonlyArray<unknown>): ReadonlySet<string> | null {
  let virtualEntry: Record<string, unknown> | null = null;
  for (const raw of packages) {
    const tbl = tomlTable(raw as never);
    if (tbl === undefined) continue;
    if (isVirtualPackage(tbl)) {
      virtualEntry = tbl;
      break;
    }
  }
  if (virtualEntry === null) return null;

  const out = new Set<string>();
  const deps = tomlArray(virtualEntry.dependencies as never);
  if (deps === undefined) return out;
  for (const d of deps) {
    const dt = tomlTable(d);
    if (dt === undefined) {
      // Sometimes dependencies are bare strings; uv permits that
      // in older revisions. Best-effort parse: take the first token.
      const s = tomlString(d);
      if (s !== undefined) {
        const head = s.split(/\s+/)[0];
        if (head !== undefined && head.length > 0) out.add(head.toLowerCase());
      }
      continue;
    }
    const name = tomlString(dt.name);
    if (name !== undefined) out.add(name.toLowerCase());
  }
  return out;
}
