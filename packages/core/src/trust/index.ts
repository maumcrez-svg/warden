// Public surface for the trust subsystem. Imported by the CLI and by
// scan-path.ts; downstream consumers go through `@warden-sh/core`.

export type {
  AllowedSignerEntry,
  AllowedSignersParseResult,
  ParseError as AllowedSignersParseError,
} from './allowed-signers.ts';
export {
  findEntryByFingerprint,
  fingerprintFromKeyData,
  parseAllowedSigners,
} from './allowed-signers.ts';
export { HASH_PREFIX, hashFileContent, parseHash } from './hash.ts';
export type {
  Manifest,
  ManifestParseResult,
  TrustEntry,
  UnlockEntry,
} from './manifest.ts';
export {
  MANIFEST_SCHEMA,
  emptyManifest,
  findTrust,
  findUnlock,
  parseManifest,
  serializeManifest,
  upsertTrust,
  upsertUnlock,
} from './manifest.ts';
export { SSH_SIGN_NAMESPACE, buildSignMessage } from './sign-message.ts';
export type {
  Signature,
  SignParams,
  SignResult,
  Signer,
  VerifyParams,
  VerifyResult,
  Verifier,
} from './signer.ts';
export { MockSigner, MockVerifier, SshSigner, SshVerifier } from './signer.ts';
export type {
  FileTrustResult,
  TrustFinding,
  TrustFindingCategory,
  TrustFileInput,
  TrustMode,
  TrustScanResult,
  TrustSeverity,
} from './scan.ts';
export { scanTrustForFiles } from './scan.ts';
