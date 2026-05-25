export type {
  McpFinding,
  PromptInjectionFinding,
  UnicodeFinding,
  UnicodeFindingKind,
} from './findings.ts';
export { scanUnicode } from './scan-unicode.ts';
export { scanPromptInjection } from './scan-prompt-injection.ts';
export { scanMcp } from './scan-mcp.ts';
export type { FileKind } from './detect-format.ts';
export { detectFormat } from './detect-format.ts';
export type { WalkOptions, WalkResult } from './walk.ts';
export { walk } from './walk.ts';
export type { GitignoreParse } from './gitignore.ts';
export { parseGitignore } from './gitignore.ts';
export type {
  FileReport,
  MarkerError,
  ScanOptions,
  ScanReport,
  TrustState,
} from './scan-path.ts';
export { scanPath } from './scan-path.ts';
export type {
  ApplyMarkerResult,
  FindingCategory,
  Marker,
  MarkerFamily,
  MarkerParseResult,
  MarkerScope,
} from './marker.ts';
export { applyMarker, markerCoversCategory, parseMarker } from './marker.ts';

// Trust subsystem (ADR 0012). Manifest parsing/serialization, allowed_signers
// parsing, Signer/Verifier interfaces (SSH-backed concrete impls + Mock
// variants for unit tests), trust finding shape, and the scan layer.
export type {
  AllowedSignerEntry,
  AllowedSignersParseResult,
  AllowedSignersParseError,
  FileTrustResult,
  Manifest,
  ManifestParseResult,
  SignParams,
  SignResult,
  Signature,
  Signer,
  TrustEntry,
  TrustFileInput,
  TrustFinding,
  TrustFindingCategory,
  TrustMode,
  TrustScanResult,
  TrustSeverity,
  UnlockEntry,
  VerifyParams,
  VerifyResult,
  Verifier,
} from './trust/index.ts';
export {
  HASH_PREFIX,
  MANIFEST_SCHEMA,
  MockSigner,
  MockVerifier,
  SSH_SIGN_NAMESPACE,
  SshSigner,
  SshVerifier,
  buildSignMessage,
  emptyManifest,
  findEntryByFingerprint,
  findTrust,
  findUnlock,
  fingerprintFromKeyData,
  hashFileContent,
  parseAllowedSigners,
  parseHash,
  parseManifest,
  scanTrustForFiles,
  serializeManifest,
  upsertTrust,
  upsertUnlock,
} from './trust/index.ts';
