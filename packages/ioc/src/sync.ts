// IOC sync — the ONLY network-bound file in the Warden codebase, by
// design. Spec: ADR 0015 §§3, 7, 10.
//
// The runtime contract:
//   - Network access is HTTPS-only, host-pinned to
//     storage.googleapis.com (the OSV bulk bucket).
//   - Redirects to any other host are refused.
//   - All cache writes are staged in a sibling tempdir and rename-
//     swapped on success. Failure leaves the previous cache intact.
//   - The fetcher is injectable so tests use local fixture ZIPs
//     without ever touching the network.

import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
} from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { resolve } from 'node:path';
import { type Unzipped, unzipSync } from 'fflate';
import {
  INDEX_SCHEMA,
  type Index,
  type PrunedAdvisory,
  indexPath,
  writeIndexAtomic,
} from './index-store.ts';
import { MANIFEST_SCHEMA, type Manifest, readManifest, writeManifestAtomic } from './manifest.ts';
import type { OsvRange } from './version.ts';

const OSV_BUCKET_BASE = 'https://storage.googleapis.com/osv-vulnerabilities';
const ALLOWED_HOST = 'storage.googleapis.com';

// Ecosystems shipped by default-all (ADR 0015 §12 resolved decision
// #2). The OSV bucket also publishes archives for more obscure
// ecosystems (Chainguard, Wolfi, etc.); we sync this list out of the
// box and accept anything via `--ecosystem` for the rest.
export const DEFAULT_ECOSYSTEMS: ReadonlyArray<string> = [
  'npm',
  'PyPI',
  'Go',
  'Maven',
  'RubyGems',
  'crates.io',
  'NuGet',
  'Packagist',
  'Hex',
  'Pub',
];

export type FetchFn = (url: string) => Promise<Uint8Array>;

export type SyncOptions = {
  readonly cacheRoot: string;
  readonly ecosystems?: ReadonlyArray<string>;
  readonly wardenVersion: string;
  readonly fetcher?: FetchFn;
  readonly now?: () => Date;
};

export type SyncEcosystemResult = {
  readonly ecosystem: string;
  readonly advisory_count: number;
  readonly zip_sha256: string;
  readonly zip_size_bytes: number;
  readonly diff: { readonly added: number; readonly dropped: number };
};

export type SyncResult = {
  readonly ecosystems: ReadonlyArray<SyncEcosystemResult>;
  readonly manifestPath: string;
  readonly totalAdvisories: number;
};

// Public entry point. Orchestrates download + parse + prune + atomic
// commit. Network code is isolated to the injected fetcher (or the
// default https fetcher in §"Network code" below).
export async function syncOsv(opts: SyncOptions): Promise<SyncResult> {
  const fetcher = opts.fetcher ?? defaultHttpsFetcher;
  const now = opts.now ?? (() => new Date());
  const ecosystems = opts.ecosystems ?? DEFAULT_ECOSYSTEMS;
  const cacheRoot = opts.cacheRoot;

  mkdirSync(cacheRoot, { recursive: true });
  gcOrphanStageDirs(cacheRoot, now());

  const stageDir = resolve(cacheRoot, `.tmp-${now().getTime()}`);
  mkdirSync(resolve(stageDir, 'osv'), { recursive: true });

  const results: SyncEcosystemResult[] = [];
  try {
    for (const ecosystem of ecosystems) {
      const url = `${OSV_BUCKET_BASE}/${ecosystem}/all.zip`;
      const bytes = await fetcher(url);
      const zipSha = sha256(bytes);
      const records = parseOsvZip(bytes);
      const previousIndex = readPreviousIndexSafely(cacheRoot, ecosystem);
      const index = buildIndex({
        ecosystem,
        synced_at: now().toISOString(),
        records,
      });
      const stagedPath = indexPath(stageDir, ecosystem);
      writeIndexAtomic(stagedPath, index);
      const diff = computeDiff(previousIndex, index);
      results.push({
        ecosystem,
        advisory_count: index.advisory_count,
        zip_sha256: zipSha,
        zip_size_bytes: bytes.byteLength,
        diff,
      });
    }
  } catch (e) {
    // Clean up the partial stage and re-raise. The previous cache is
    // untouched (atomicity §10 guarantee #2).
    try {
      rmSync(stageDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup; not fatal.
    }
    throw e;
  }

  // Commit phase. ADR 0015 §10 step 3: rename-swap. The previous
  // osv/ directory is moved to osv.prev-<ts>, the staged osv/ becomes
  // the live one, the previous is then deleted.
  const liveOsvDir = resolve(cacheRoot, 'osv');
  const prevOsvDir = resolve(cacheRoot, `osv.prev-${now().getTime()}`);
  const stagedOsvDir = resolve(stageDir, 'osv');

  const hadPreviousOsv = existsSync(liveOsvDir);
  if (hadPreviousOsv) {
    renameSync(liveOsvDir, prevOsvDir);
  }
  try {
    renameSync(stagedOsvDir, liveOsvDir);
  } catch (e) {
    // Swap-mid failure: roll back the rename of the previous osv/.
    if (hadPreviousOsv) {
      try {
        renameSync(prevOsvDir, liveOsvDir);
      } catch {
        // If the rollback also fails, both directories may be in
        // unusual states. Surface the original error; the user can
        // re-sync to recover.
      }
    }
    throw e;
  }
  if (hadPreviousOsv) {
    try {
      rmSync(prevOsvDir, { recursive: true, force: true });
    } catch {
      // Old dir cleanup is best-effort.
    }
  }

  // Manifest is the last write, ADR §10 step 4. Read the previous
  // manifest first to preserve history append (best-effort).
  const manifestPath = resolve(cacheRoot, 'manifest.json');
  const previousManifest = readManifest(manifestPath);
  const totalAdvisories = results.reduce((sum, r) => sum + r.advisory_count, 0);

  const newManifest: Manifest = {
    schema: MANIFEST_SCHEMA,
    synced_at: now().toISOString(),
    warden_version: opts.wardenVersion,
    sources: [
      {
        name: 'osv',
        url: OSV_BUCKET_BASE,
        synced_at: now().toISOString(),
        ecosystems: results.map((r) => r.ecosystem),
        advisory_count: totalAdvisories,
        zip_sha256: results.map((r) => `${r.ecosystem}:${r.zip_sha256}`).join(','),
        zip_size_bytes: results.reduce((sum, r) => sum + r.zip_size_bytes, 0),
      },
    ],
  };
  writeManifestAtomic(manifestPath, newManifest);

  // History append (best-effort, per ADR §10 step 6).
  if (previousManifest.kind === 'ok') {
    try {
      const historyDir = resolve(cacheRoot, 'history');
      mkdirSync(historyDir, { recursive: true });
      const safeTimestamp = previousManifest.manifest.synced_at.replace(/[:.]/g, '-');
      const historyFile = resolve(historyDir, `${safeTimestamp}.json`);
      // Use the atomic-write pattern to avoid leaving a half-written
      // history file if the process is killed.
      writeManifestAtomic(historyFile, previousManifest.manifest);
      pruneHistory(historyDir, 10);
    } catch {
      // Non-fatal — current cache is already committed.
    }
  }

  // Clean up the now-empty stage directory.
  try {
    rmSync(stageDir, { recursive: true, force: true });
  } catch {
    // Best-effort.
  }

  return { ecosystems: results, manifestPath, totalAdvisories };
}

function readPreviousIndexSafely(cacheRoot: string, ecosystem: string): Index | null {
  // Skip the full schema check from readIndex — a malformed previous
  // file shouldn't block a fresh sync; the diff just falls back to
  // "everything is new."
  const path = indexPath(cacheRoot, ecosystem);
  if (!existsSync(path)) return null;
  try {
    const text = readFileSync(path, 'utf8');
    const parsed = JSON.parse(text);
    if (parsed === null || typeof parsed !== 'object') return null;
    return parsed as Index;
  } catch {
    return null;
  }
}

function computeDiff(previous: Index | null, current: Index): { added: number; dropped: number } {
  if (previous === null) {
    return { added: current.advisory_count, dropped: 0 };
  }
  const prevIds = new Set<string>();
  for (const pkg of Object.values(previous.packages ?? {})) {
    for (const a of pkg ?? []) prevIds.add(a.id);
  }
  const curIds = new Set<string>();
  for (const pkg of Object.values(current.packages)) {
    for (const a of pkg) curIds.add(a.id);
  }
  let added = 0;
  for (const id of curIds) if (!prevIds.has(id)) added++;
  let dropped = 0;
  for (const id of prevIds) if (!curIds.has(id)) dropped++;
  return { added, dropped };
}

function pruneHistory(historyDir: string, keep: number): void {
  try {
    const entries = readdirSync(historyDir)
      .filter((n) => n.endsWith('.json'))
      .map((n) => ({ n, mtime: statSync(resolve(historyDir, n)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
    for (const e of entries.slice(keep)) {
      try {
        rmSync(resolve(historyDir, e.n), { force: true });
      } catch {
        // Skip individual failures.
      }
    }
  } catch {
    // History dir doesn't exist or is unreadable; nothing to prune.
  }
}

// GC of orphan stage dirs from killed previous syncs. ADR 0015 §10
// step 5: any `.tmp-*` older than 1 hour is from a process that
// died long enough ago that we can safely reclaim its space.
function gcOrphanStageDirs(cacheRoot: string, now: Date): void {
  if (!existsSync(cacheRoot)) return;
  const oneHourAgo = now.getTime() - 60 * 60 * 1000;
  try {
    const entries = readdirSync(cacheRoot);
    for (const name of entries) {
      if (!name.startsWith('.tmp-') && !name.startsWith('osv.prev-')) continue;
      const full = resolve(cacheRoot, name);
      try {
        const st = statSync(full);
        if (st.mtimeMs < oneHourAgo) {
          rmSync(full, { recursive: true, force: true });
        }
      } catch {
        // Skip; nothing else to do.
      }
    }
  } catch {
    // Cache root unreadable; let the sync fail loudly later.
  }
}

// --- ZIP parsing + advisory pruning ----------------------------------

type OsvRawRecord = {
  id?: string;
  summary?: string;
  details?: string;
  severity?: ReadonlyArray<{ type?: string; score?: string }>;
  affected?: ReadonlyArray<{
    package?: { ecosystem?: string; name?: string };
    ranges?: ReadonlyArray<OsvRange>;
  }>;
  references?: ReadonlyArray<{ type?: string; url?: string }>;
  database_specific?: { severity?: string };
};

function parseOsvZip(bytes: Uint8Array): ReadonlyArray<OsvRawRecord> {
  let unzipped: Unzipped;
  try {
    unzipped = unzipSync(bytes);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`osv zip parse failed: ${msg}`);
  }
  const decoder = new TextDecoder('utf-8');
  const out: OsvRawRecord[] = [];
  for (const [filename, data] of Object.entries(unzipped)) {
    if (!filename.endsWith('.json')) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(decoder.decode(data));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`osv entry ${filename} parse failed: ${msg}`);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
    out.push(parsed as OsvRawRecord);
  }
  return out;
}

function pickSeverity(rec: OsvRawRecord): 'high' | 'medium' | 'low' {
  const ds = rec.database_specific?.severity;
  if (typeof ds === 'string') {
    const norm = ds.toUpperCase();
    if (norm === 'CRITICAL' || norm === 'HIGH') return 'high';
    if (norm === 'MODERATE' || norm === 'MEDIUM') return 'medium';
    if (norm === 'LOW') return 'low';
  }
  // No severity → 'medium' per ADR 0015 §5 mapping.
  return 'medium';
}

function buildIndex(args: {
  ecosystem: string;
  synced_at: string;
  records: ReadonlyArray<OsvRawRecord>;
}): Index {
  const packages: Record<string, PrunedAdvisory[]> = {};
  let advisory_count = 0;

  for (const rec of args.records) {
    if (typeof rec.id !== 'string' || rec.id.length === 0) continue;
    const affected = rec.affected ?? [];
    for (const aff of affected) {
      const pkgEco = aff.package?.ecosystem;
      const pkgName = aff.package?.name;
      if (typeof pkgName !== 'string' || pkgName.length === 0) continue;
      if (typeof pkgEco !== 'string' || pkgEco !== args.ecosystem) continue;

      const pruned: PrunedAdvisory = {
        id: rec.id,
        severity: pickSeverity(rec),
        summary: pickSummary(rec),
        ranges: (aff.ranges ?? []).filter((r) => r.type === 'SEMVER' || r.type === 'ECOSYSTEM'),
        references: (rec.references ?? [])
          .map((r) => r.url)
          .filter((u): u is string => typeof u === 'string')
          .slice(0, 1),
      };

      if (packages[pkgName] === undefined) packages[pkgName] = [];
      // Dedup: an OSV advisory can list the same package multiple
      // times across `affected` entries (e.g. distinct version ranges
      // for different OS distros). Keep only the first per (id, pkg).
      const pkgArr = packages[pkgName] as PrunedAdvisory[];
      if (!pkgArr.some((a) => a.id === pruned.id)) {
        pkgArr.push(pruned);
        advisory_count++;
      }
    }
  }

  // Sort advisories within each package by id for deterministic
  // re-syncs (atomicity §10 requires byte-identical writes when
  // upstream hasn't changed).
  for (const arr of Object.values(packages)) {
    (arr as PrunedAdvisory[]).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  return {
    schema: INDEX_SCHEMA,
    ecosystem: args.ecosystem,
    source: 'osv',
    synced_at: args.synced_at,
    advisory_count,
    packages,
  };
}

function pickSummary(rec: OsvRawRecord): string {
  const raw = rec.summary ?? rec.details ?? '';
  const trimmed = raw.replaceAll(/\s+/g, ' ').trim();
  return trimmed.slice(0, 200);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

// --- Network code (the only place this is allowed) ------------------

// Exported for unit testing. Returns null when the URL is acceptable,
// or an error message string when it should be rejected. Centralizes
// the network-policy check so the rejection conditions in ADR 0015 §7
// are auditable in one place.
export function validateOsvUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `not a valid URL: ${url}`;
  }
  if (parsed.protocol !== 'https:') {
    return `refusing non-HTTPS URL: ${url}`;
  }
  if (parsed.hostname !== ALLOWED_HOST) {
    return `refusing host "${parsed.hostname}"; only ${ALLOWED_HOST} is allowed`;
  }
  return null;
}

function defaultHttpsFetcher(url: string): Promise<Uint8Array> {
  const rejection = validateOsvUrl(url);
  if (rejection !== null) {
    return Promise.reject(new Error(rejection));
  }
  const parsed = new URL(url);

  return new Promise<Uint8Array>((resolveP, rejectP) => {
    const req = httpsRequest(
      {
        method: 'GET',
        hostname: parsed.hostname,
        path: `${parsed.pathname}${parsed.search}`,
        headers: {
          'user-agent': 'warden-ioc/0.0.0-m8 (+https://github.com/warden-sh/warden)',
          accept: 'application/zip,application/octet-stream;q=0.9,*/*;q=0.1',
        },
      },
      (res) => {
        // We deliberately do NOT follow redirects. If OSV moves the
        // bucket, the user upgrades Warden; we do not silently follow
        // 3xx to an unverified host.
        if (res.statusCode === undefined || res.statusCode >= 300) {
          res.resume();
          rejectP(
            new Error(`HTTP ${String(res.statusCode)} from ${parsed.hostname}${parsed.pathname}`),
          );
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolveP(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
        });
        res.on('error', rejectP);
      },
    );
    req.on('error', rejectP);
    req.end();
  });
}

// --- Verify support --------------------------------------------------

export type VerifyOptions = {
  readonly cacheRoot: string;
  readonly ecosystems?: ReadonlyArray<string>;
  readonly fetcher?: FetchFn;
};

export type VerifyEcosystemResult = {
  readonly ecosystem: string;
  readonly previousSha256: string;
  readonly currentSha256: string;
  readonly matches: boolean;
};

export type VerifyResult = {
  readonly ecosystems: ReadonlyArray<VerifyEcosystemResult>;
  readonly allMatch: boolean;
};

// Re-fetches the cached ZIP hashes and compares them to the previously
// stored values in manifest.json. Surfaces feed-content drift between
// syncs (ADR 0015 §9 mitigation #4).
export async function verifyOsv(opts: VerifyOptions): Promise<VerifyResult> {
  const manifestPath = resolve(opts.cacheRoot, 'manifest.json');
  const manifestRead = readManifest(manifestPath);
  if (manifestRead.kind !== 'ok') {
    throw new Error(
      `cannot read manifest at ${manifestPath}: ${manifestRead.kind === 'error' ? manifestRead.message : 'missing — run `warden ioc sync` first'}`,
    );
  }
  const fetcher = opts.fetcher ?? defaultHttpsFetcher;
  const ecosystems = opts.ecosystems ?? extractEcosystemsFromManifest(manifestRead.manifest);

  // Build a lookup of previous hashes from the manifest's
  // zip_sha256 field (encoded as "ecosystem:hash,ecosystem:hash,…").
  const prevHashes = new Map<string, string>();
  for (const src of manifestRead.manifest.sources) {
    for (const pair of src.zip_sha256.split(',')) {
      const [eco, hash] = pair.split(':');
      if (eco !== undefined && hash !== undefined) prevHashes.set(eco, hash);
    }
  }

  const results: VerifyEcosystemResult[] = [];
  for (const ecosystem of ecosystems) {
    const url = `${OSV_BUCKET_BASE}/${ecosystem}/all.zip`;
    const bytes = await fetcher(url);
    const current = sha256(bytes);
    const previous = prevHashes.get(ecosystem) ?? '';
    results.push({
      ecosystem,
      previousSha256: previous,
      currentSha256: current,
      matches: previous === current,
    });
  }
  return { ecosystems: results, allMatch: results.every((r) => r.matches) };
}

function extractEcosystemsFromManifest(m: Manifest): ReadonlyArray<string> {
  const out = new Set<string>();
  for (const src of m.sources) {
    for (const e of src.ecosystems) out.add(e);
  }
  return [...out];
}
