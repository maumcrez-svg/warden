// Public surface of @warden-sh/ioc. Imported by the CLI
// (`warden ioc sync|status|lookup|verify`) and by unit tests in this
// package.
//
// This is the only Warden package whose sync.ts is allowed to import
// network modules (node:https, node:net, etc.). ADR 0015 §7 codifies
// the boundary; the Biome `noRestrictedImports` rule enforces it at
// lint time.

export type {
  Manifest,
  ManifestReadResult,
  ManifestSourceEntry,
} from './manifest.ts';
export {
  ageHoursSinceSync,
  MANIFEST_SCHEMA,
  readManifest,
  writeManifestAtomic,
} from './manifest.ts';

export type { Index, IndexReadResult, PrunedAdvisory } from './index-store.ts';
export {
  getAdvisoriesForPackage,
  INDEX_SCHEMA,
  indexPath,
  readIndex,
  writeIndexAtomic,
} from './index-store.ts';

export type { LookupMatch, LookupResult, LookupTarget } from './lookup.ts';
export { lookupInIndex, parseLookupTarget } from './lookup.ts';

export type {
  MatchResult,
  OsvRange,
  OsvRangeEvent,
  Version,
} from './version.ts';
export { compareVersions, matchOsvRange, parseVersion } from './version.ts';

export type { Pep440Version } from './version-pep440.ts';
export {
  comparePep440Versions,
  matchPep440Range,
  parsePep440Version,
} from './version-pep440.ts';

export type {
  FetchFn,
  SyncEcosystemResult,
  SyncOptions,
  SyncResult,
  VerifyEcosystemResult,
  VerifyOptions,
  VerifyResult,
} from './sync.ts';
export { DEFAULT_ECOSYSTEMS, syncOsv, validateOsvUrl, verifyOsv } from './sync.ts';
