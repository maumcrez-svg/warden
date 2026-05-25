// Test-only helpers that build OSV-shaped fixture ZIPs at runtime via
// fflate. Keeping fixture construction in a helper (vs. committing a
// binary ZIP under tests/fixtures/ioc/) means the malicious-package
// IDs and ranges live in readable TypeScript and the assertions can
// reference them directly.

import { zipSync } from 'fflate';

export type FixtureAdvisory = {
  readonly id: string;
  readonly summary: string;
  readonly severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  readonly ecosystem: string;
  readonly packageName: string;
  readonly introduced: string;
  readonly fixed?: string;
  readonly lastAffected?: string;
  readonly rangeType?: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  readonly references?: ReadonlyArray<string>;
};

// The real event-stream@3.3.6 advisory shape. ID and URL are the
// public GHSA record. Range is the documented backdoor window —
// 3.3.6 was the only affected version; flatmap-stream@0.1.1 was the
// dependency that contained the actual backdoor.
export const EVENT_STREAM_ADVISORY: FixtureAdvisory = {
  id: 'GHSA-mh6f-8j2x-4483',
  summary:
    'Malicious code in event-stream 3.3.6 — flatmap-stream dep contained a Bitcoin wallet stealer targeting copay/bitpay.',
  severity: 'CRITICAL',
  ecosystem: 'npm',
  packageName: 'event-stream',
  introduced: '3.3.6',
  fixed: '4.0.0',
  rangeType: 'SEMVER',
  references: ['https://github.com/advisories/GHSA-mh6f-8j2x-4483'],
};

// A benign-looking second advisory in the same ecosystem so tests
// exercise multi-record indexes.
export const LEFT_PAD_ADVISORY: FixtureAdvisory = {
  id: 'TEST-LEFT-PAD-0001',
  summary: 'Synthetic fixture advisory for left-pad (test only).',
  severity: 'MEDIUM',
  ecosystem: 'npm',
  packageName: 'left-pad',
  introduced: '0.0.0',
  fixed: '1.1.1',
  rangeType: 'SEMVER',
  references: ['https://example.test/advisories/TEST-LEFT-PAD-0001'],
};

function advisoryToOsv(adv: FixtureAdvisory): Record<string, unknown> {
  const events: Array<Record<string, string>> = [{ introduced: adv.introduced }];
  if (adv.fixed !== undefined) events.push({ fixed: adv.fixed });
  if (adv.lastAffected !== undefined) events.push({ last_affected: adv.lastAffected });
  return {
    id: adv.id,
    summary: adv.summary,
    database_specific: { severity: adv.severity },
    affected: [
      {
        package: { ecosystem: adv.ecosystem, name: adv.packageName },
        ranges: [{ type: adv.rangeType ?? 'SEMVER', events }],
      },
    ],
    references: (adv.references ?? []).map((url) => ({ type: 'ADVISORY', url })),
  };
}

// Builds a ZIP whose entries match OSV's per-record layout
// (<ID>.json files inside the ZIP). Used as the fixture for sync
// tests that inject a fetcher returning these bytes.
export function buildFixtureZip(advisories: ReadonlyArray<FixtureAdvisory>): Uint8Array {
  const entries: Record<string, Uint8Array> = {};
  const encoder = new TextEncoder();
  for (const adv of advisories) {
    const json = JSON.stringify(advisoryToOsv(adv), null, 2);
    entries[`${adv.id}.json`] = encoder.encode(json);
  }
  return zipSync(entries);
}

// Build a ZIP intentionally malformed at the third entry — used to
// verify the atomicity guarantee (sync abort leaves previous cache
// intact). We give a valid filename but corrupt JSON inside.
export function buildBrokenZip(advisories: ReadonlyArray<FixtureAdvisory>): Uint8Array {
  const entries: Record<string, Uint8Array> = {};
  const encoder = new TextEncoder();
  let i = 0;
  for (const adv of advisories) {
    if (i === 2) {
      entries[`${adv.id}.json`] = encoder.encode('{ not valid json at all');
    } else {
      entries[`${adv.id}.json`] = encoder.encode(JSON.stringify(advisoryToOsv(adv), null, 2));
    }
    i++;
  }
  return zipSync(entries);
}
