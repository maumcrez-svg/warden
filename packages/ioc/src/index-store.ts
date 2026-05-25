// Per-ecosystem index read/write + lookup. Spec: ADR 0015 §2.
//
// On-disk layout: <cache>/osv/<ecosystem>.json. Loaded lazily — only
// the ecosystems a lookup asks about are read into memory.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { OsvRange } from './version.ts';

export const INDEX_SCHEMA = 'warden-ioc/v1' as const;

// Pruned-to-MVP advisory record. ADR 0015 §2 enumerates the kept
// fields (id, severity, summary[:200], ranges, references[:1]); we
// keep nothing else. The OSV record's full shape lives in the
// upstream source and can be fetched on demand via the references[0]
// URL by a curious user.
export type PrunedAdvisory = {
  readonly id: string;
  readonly severity: 'high' | 'medium' | 'low';
  readonly summary: string;
  readonly ranges: ReadonlyArray<OsvRange>;
  readonly references: ReadonlyArray<string>;
};

export type Index = {
  readonly schema: typeof INDEX_SCHEMA;
  readonly ecosystem: string;
  readonly source: string;
  readonly synced_at: string;
  readonly advisory_count: number;
  // Keyed by package name. A package may have multiple advisories
  // (e.g. distinct CVE ranges). Order within the array is the
  // upstream OSV order, sorted by id for determinism.
  readonly packages: Readonly<Record<string, ReadonlyArray<PrunedAdvisory>>>;
};

export type IndexReadResult =
  | { readonly kind: 'ok'; readonly index: Index }
  | { readonly kind: 'missing' }
  | { readonly kind: 'error'; readonly message: string };

export function indexPath(cacheRoot: string, ecosystem: string): string {
  return resolve(cacheRoot, 'osv', `${ecosystem}.json`);
}

export function readIndex(path: string): IndexReadResult {
  if (!existsSync(path)) return { kind: 'missing' };
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    return { kind: 'error', message: `cannot read index: ${String(e)}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { kind: 'error', message: `index JSON parse error: ${msg}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { kind: 'error', message: 'index is not a JSON object' };
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema !== INDEX_SCHEMA) {
    return {
      kind: 'error',
      message: `unsupported index schema "${String(obj.schema)}"; this Warden expects "${INDEX_SCHEMA}"`,
    };
  }
  return { kind: 'ok', index: parsed as Index };
}

// Atomic write: temp + rename. The caller passes the final path
// directly (vs. cacheRoot + ecosystem) so this function is usable in
// both the live cache root and a sync stage directory.
export function writeIndexAtomic(path: string, index: Index): void {
  mkdirSync(dirname(path), { recursive: true });
  // Stable key order for byte-identical re-syncs (ADR §10 atomicity
  // depends on the swap being a no-op when upstream hasn't changed).
  const sortedPackages: Record<string, ReadonlyArray<PrunedAdvisory>> = {};
  for (const key of Object.keys(index.packages).sort()) {
    sortedPackages[key] = index.packages[key] as ReadonlyArray<PrunedAdvisory>;
  }
  const stable: Index = { ...index, packages: sortedPackages };
  const tmp = resolve(dirname(path), `${path.split('/').pop()}.tmp-${Date.now()}`);
  const serialized = `${JSON.stringify(stable, null, 2)}\n`;
  writeFileSync(tmp, serialized, { encoding: 'utf8' });
  renameSync(tmp, path);
}

// Synchronous lookup: return all advisories for a package, regardless
// of version. The version-range filtering happens in lookup.ts so
// this module stays I/O-pure.
export function getAdvisoriesForPackage(
  index: Index,
  packageName: string,
): ReadonlyArray<PrunedAdvisory> {
  return index.packages[packageName] ?? [];
}
