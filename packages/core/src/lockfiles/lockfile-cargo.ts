// Cargo.lock parser. ADR 0016 §1, §3.
//
// Format reference:
//   https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html
//   (verified 2026-05-25).
//
// Each `[[package]]` block has at minimum `name` and `version`. A
// `dependencies = ["name", "name version source"]` array enumerates
// transitive edges. The lockfile alone does NOT distinguish root
// workspace members from third-party dependencies — the matching
// `[package].name` in `Cargo.toml` (or `[workspace].members` plus
// their inner manifests) is the source of truth for direct names.
//
// ADR 0016 §3: when `Cargo.toml` is absent/unreadable, classify all
// entries as direct (louder fallback, not silent).

import { parseTomlMini, tomlArray, tomlString, tomlTable } from './toml-mini.ts';
import type { LockfileEntry, LockfileParseResult } from './types.ts';

export function parseCargoLockfile(
  content: string,
  manifestContent: string | null,
): LockfileParseResult {
  const parsed = parseTomlMini(content);
  if (parsed.kind === 'error') {
    return {
      kind: 'error',
      message: `Cargo.lock TOML parse error at line ${parsed.line}: ${parsed.message}`,
    };
  }
  const packagesRaw = tomlArray(parsed.root.package);
  if (packagesRaw === undefined) {
    return { kind: 'ok', entries: [] };
  }

  const directNames = manifestContent !== null ? cargoDirectNames(manifestContent) : null;
  // null = manifest unreadable → treat everything as direct (ADR 0016 §3).

  const entries: LockfileEntry[] = [];
  for (const raw of packagesRaw) {
    const tbl = tomlTable(raw);
    if (tbl === undefined) continue;
    const name = tomlString(tbl.name);
    const version = tomlString(tbl.version);
    if (name === undefined || version === undefined) continue;
    const position =
      directNames === null ? 'direct' : directNames.has(name) ? 'direct' : 'transitive';
    entries.push({ ecosystem: 'crates.io', name, version, position });
  }

  entries.sort((a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
  );
  return { kind: 'ok', entries };
}

// Read direct dep names from Cargo.toml. Looks at:
//   [package].name            (this crate's own name — excluded from direct)
//   [dependencies], [dev-dependencies], [build-dependencies]
//   [target.<cfg>.dependencies]  (target-specific deps)
//
// Returns the set of names that should classify as direct. The crate's
// own name is intentionally NOT in the set — when present in the
// lockfile (e.g. a workspace root) we still don't report a finding for
// it. But callers don't need to worry about that distinction; even if
// it WAS marked direct, having no advisory means no finding.
function cargoDirectNames(manifestContent: string): ReadonlySet<string> {
  const out = new Set<string>();
  const parsed = parseTomlMini(manifestContent);
  if (parsed.kind === 'error') return out;
  const root = parsed.root;

  const collectKeys = (v: unknown): void => {
    const tbl = tomlTable(v as never);
    if (tbl === undefined) return;
    for (const k of Object.keys(tbl)) out.add(k);
  };
  collectKeys(root.dependencies);
  collectKeys(root['dev-dependencies']);
  collectKeys(root['build-dependencies']);

  // [target.<cfg>.dependencies] — walk one level deep through `target`.
  const target = tomlTable(root.target);
  if (target !== undefined) {
    for (const subKey of Object.keys(target)) {
      const sub = tomlTable(target[subKey]);
      if (sub === undefined) continue;
      collectKeys(sub.dependencies);
      collectKeys(sub['dev-dependencies']);
      collectKeys(sub['build-dependencies']);
    }
  }

  return out;
}
