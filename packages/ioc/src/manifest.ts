// Manifest read/write. Spec: ADR 0015 §2 (schema) + §10 (atomicity).
//
// The manifest is the single source of truth for "what version of the
// cache is current." Written last during sync, read first by every
// other ioc subcommand. Pure functions over strings + a minimal
// atomic-write helper at the bottom.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export const MANIFEST_SCHEMA = 'warden-ioc/v1' as const;

export type ManifestSourceEntry = {
  readonly name: string;
  readonly url: string;
  readonly synced_at: string;
  readonly ecosystems: ReadonlyArray<string>;
  readonly advisory_count: number;
  readonly zip_sha256: string;
  readonly zip_size_bytes: number;
};

export type Manifest = {
  readonly schema: typeof MANIFEST_SCHEMA;
  readonly synced_at: string;
  readonly warden_version: string;
  readonly sources: ReadonlyArray<ManifestSourceEntry>;
};

export type ManifestReadResult =
  | { readonly kind: 'ok'; readonly manifest: Manifest }
  | { readonly kind: 'missing' }
  | { readonly kind: 'error'; readonly message: string };

export function readManifest(path: string): ManifestReadResult {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { kind: 'missing' };
    return { kind: 'error', message: `cannot read manifest: ${String(e)}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { kind: 'error', message: `manifest JSON parse error: ${msg}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { kind: 'error', message: 'manifest is not a JSON object' };
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.schema !== MANIFEST_SCHEMA) {
    return {
      kind: 'error',
      message: `unsupported manifest schema "${String(obj.schema)}"; this Warden expects "${MANIFEST_SCHEMA}"`,
    };
  }
  // Light-touch validation: trust the shape if schema matches.
  // Anything more would be busywork — the manifest is machine-written
  // by sync.ts, which controls the shape end-to-end.
  return { kind: 'ok', manifest: parsed as Manifest };
}

// Atomic write: temp file in the same directory + POSIX rename.
// Same filesystem guarantee documented in ADR 0015 §10. The caller
// is responsible for ensuring the parent directory exists.
export function writeManifestAtomic(path: string, manifest: Manifest): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = resolve(dirname(path), `${path.split('/').pop()}.tmp-${Date.now()}`);
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  writeFileSync(tmp, serialized, { encoding: 'utf8' });
  renameSync(tmp, path);
}

// Ages the manifest in human-readable form. Used by warden ioc status
// to report staleness without doing date math in the CLI layer.
export function ageHoursSinceSync(manifest: Manifest, now: Date = new Date()): number {
  const then = new Date(manifest.synced_at).getTime();
  if (!Number.isFinite(then)) return Number.POSITIVE_INFINITY;
  return (now.getTime() - then) / (1000 * 60 * 60);
}
