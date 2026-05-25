// CLI subcommands for `warden ioc sync|status|lookup|verify`.
// Spec: ADR 0015 §8.

import { homedir } from 'node:os';
import { resolve } from 'node:path';
import {
  DEFAULT_ECOSYSTEMS,
  type Index,
  type LookupResult,
  type Manifest,
  type SyncResult,
  type VerifyResult,
  ageHoursSinceSync,
  indexPath,
  lookupInIndex,
  parseLookupTarget,
  readIndex,
  readManifest,
  syncOsv,
  verifyOsv,
} from '@warden-sh/ioc';

type Streams = {
  readonly stdout: { write(chunk: string): boolean | unknown };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

function defaultCacheRoot(): string {
  const xdg = process.env.XDG_CACHE_HOME;
  if (typeof xdg === 'string' && xdg.length > 0) {
    return resolve(xdg, 'warden', 'ioc');
  }
  return resolve(homedir(), '.warden', 'ioc');
}

export type IocSyncFlags = {
  readonly ecosystem?: ReadonlyArray<string>;
  readonly force?: true;
  readonly cacheRoot?: string;
  readonly wardenVersion: string;
};

export async function iocSync(flags: IocSyncFlags, streams: Streams): Promise<number> {
  const cacheRoot = flags.cacheRoot ?? defaultCacheRoot();
  const ecosystems =
    flags.ecosystem !== undefined && flags.ecosystem.length > 0
      ? flags.ecosystem
      : DEFAULT_ECOSYSTEMS;

  let result: SyncResult;
  try {
    result = await syncOsv({
      cacheRoot,
      ecosystems,
      wardenVersion: flags.wardenVersion,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    streams.stderr.write(`warden ioc sync: ${msg}\n`);
    return 1;
  }

  // Stderr summary line (ADR 0015 §8 "logs `synced N advisories from osv` on stderr; silent on stdout").
  let added = 0;
  let dropped = 0;
  for (const eco of result.ecosystems) {
    added += eco.diff.added;
    dropped += eco.diff.dropped;
  }
  streams.stderr.write(
    `synced osv: +${added} new / -${dropped} dropped / ${result.totalAdvisories} total across ${result.ecosystems.length} ecosystem(s)\n`,
  );
  return 0;
}

export type IocStatusFlags = {
  readonly json?: true;
  readonly cacheRoot?: string;
};

export function iocStatus(flags: IocStatusFlags, streams: Streams): number {
  const cacheRoot = flags.cacheRoot ?? defaultCacheRoot();
  const manifestRead = readManifest(resolve(cacheRoot, 'manifest.json'));
  if (manifestRead.kind === 'missing') {
    if (flags.json === true) {
      streams.stdout.write(
        `${JSON.stringify({ schema: 'warden/ioc-status/v1', cache: 'missing' })}\n`,
      );
      return 0;
    }
    streams.stderr.write(
      `warden ioc status: no cache at ${cacheRoot} — run \`warden ioc sync\` first\n`,
    );
    return 0;
  }
  if (manifestRead.kind === 'error') {
    streams.stderr.write(`warden ioc status: ${manifestRead.message}\n`);
    return 2;
  }
  const manifest: Manifest = manifestRead.manifest;
  const ageHours = ageHoursSinceSync(manifest);
  const ageDays = ageHours / 24;

  if (flags.json === true) {
    streams.stdout.write(
      `${JSON.stringify({
        schema: 'warden/ioc-status/v1',
        cache: 'present',
        cacheRoot,
        synced_at: manifest.synced_at,
        age_hours: ageHours,
        sources: manifest.sources,
      })}\n`,
    );
    return 0;
  }

  streams.stdout.write(`cache:     ${cacheRoot}\n`);
  streams.stdout.write(`synced:    ${manifest.synced_at} (${ageDays.toFixed(1)} days ago)\n`);
  for (const src of manifest.sources) {
    streams.stdout.write(
      `  source ${src.name}: ${src.advisory_count} advisories across ${src.ecosystems.length} ecosystem(s)\n`,
    );
    streams.stdout.write(`    ecosystems: ${src.ecosystems.join(', ')}\n`);
  }
  return 0;
}

export type IocLookupFlags = {
  readonly json?: true;
  readonly cacheRoot?: string;
};

export function iocLookup(target: string, flags: IocLookupFlags, streams: Streams): number {
  const cacheRoot = flags.cacheRoot ?? defaultCacheRoot();
  const parsedTarget = parseLookupTarget(target);
  if (parsedTarget === null) {
    streams.stderr.write(
      `warden ioc lookup: malformed target "${target}"; expected <ecosystem>:<package>@<version>\n`,
    );
    return 2;
  }
  const indexRead = readIndex(indexPath(cacheRoot, parsedTarget.ecosystem));
  if (indexRead.kind === 'missing') {
    streams.stderr.write(
      `warden ioc lookup: no index for ecosystem "${parsedTarget.ecosystem}" at ${cacheRoot} — run \`warden ioc sync\` first\n`,
    );
    return 2;
  }
  if (indexRead.kind === 'error') {
    streams.stderr.write(`warden ioc lookup: ${indexRead.message}\n`);
    return 2;
  }
  const index: Index = indexRead.index;
  const result: LookupResult = lookupInIndex(index, parsedTarget);

  if (flags.json === true) {
    streams.stdout.write(
      `${JSON.stringify({
        schema: 'warden/ioc-lookup/v1',
        target: parsedTarget,
        matches: result.matches.map((m) => ({
          id: m.advisory.id,
          severity: m.advisory.severity,
          summary: m.advisory.summary,
          ranges: m.advisory.ranges,
          references: m.advisory.references,
          confidence: m.confidence,
          note: m.note,
        })),
      })}\n`,
    );
  } else {
    for (const m of result.matches) {
      const conf = m.confidence === 'in-range' ? '' : '  [version-unknown]';
      streams.stdout.write(
        `${m.advisory.id}  ${m.advisory.severity}  ${m.advisory.summary}${conf}\n`,
      );
      for (const range of m.advisory.ranges) {
        const events = range.events
          .map((e) =>
            e.introduced !== undefined
              ? `introduced=${e.introduced}`
              : e.fixed !== undefined
                ? `fixed=${e.fixed}`
                : e.last_affected !== undefined
                  ? `last_affected=${e.last_affected}`
                  : '',
          )
          .filter((s) => s.length > 0)
          .join(' ');
        streams.stdout.write(`  range: ${range.type} ${events}\n`);
      }
      if (m.advisory.references.length > 0) {
        streams.stdout.write(`  ref:   ${m.advisory.references[0]}\n`);
      }
      if (m.confidence === 'version-unknown') {
        streams.stdout.write(`  note:  ${m.note}\n`);
      }
    }
  }
  // Exit 1 on hits (ADR 0015 §12 resolved decision #4 — CI gating).
  return result.matches.length > 0 ? 1 : 0;
}

export type IocVerifyFlags = {
  readonly ecosystem?: ReadonlyArray<string>;
  readonly cacheRoot?: string;
};

export async function iocVerify(flags: IocVerifyFlags, streams: Streams): Promise<number> {
  const cacheRoot = flags.cacheRoot ?? defaultCacheRoot();
  let result: VerifyResult;
  try {
    result = await verifyOsv({
      cacheRoot,
      ...(flags.ecosystem !== undefined ? { ecosystems: flags.ecosystem } : {}),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    streams.stderr.write(`warden ioc verify: ${msg}\n`);
    return 2;
  }

  for (const r of result.ecosystems) {
    if (r.matches) {
      streams.stdout.write(`${r.ecosystem}: ok (sha256 ${r.currentSha256.slice(0, 12)}…)\n`);
    } else {
      streams.stdout.write(
        `${r.ecosystem}: MISMATCH (previous ${r.previousSha256.slice(0, 12)}… vs current ${r.currentSha256.slice(0, 12)}…)\n`,
      );
    }
  }

  return result.allMatch ? 0 : 1;
}
