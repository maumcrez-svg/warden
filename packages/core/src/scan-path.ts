// scanPath composes walk -> detectFormat -> scanUnicode + scanPromptInjection
// -> trust verification into a single deterministic pipeline. After
// detection, payload-fixture markers (ADR 0010) split findings into kept
// vs suppressed. ADR 0012 layers trust verification on top: findings of
// category `trust.*` may fire when `.warden/trust/manifest.toml` is
// present (or the `.warden/trust-required` sentinel triggers enforcement
// without `--strict`).
//
// I/O surface: readFileSync (for files) + spawnSync (only when trust
// verify is active, via the injected Verifier). The hot-path
// architectural boundary (`docs/ARCHITECTURE.md` §4) treats the trust
// verifier as cold-path coupling explicitly allowed by ADR 0012 §8.

import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';
import { type FileKind, detectFormat } from './detect-format.ts';
import type {
  McpFinding,
  PromptInjectionFinding,
  SupplyChainFinding,
  SupplyChainSeverity,
  UnicodeFinding,
} from './findings.ts';
import { type FindingCategory, type Marker, applyMarker, parseMarker } from './marker.ts';
import { scanMcp } from './scan-mcp.ts';
import { scanPromptInjection } from './scan-prompt-injection.ts';
import {
  type ScanIocLookup,
  type SupplyChainParseError,
  scanSupplyChain,
} from './scan-supply-chain.ts';
import { scanUnicode } from './scan-unicode.ts';
import { type Manifest, parseManifest } from './trust/manifest.ts';
import {
  type TrustFileInput,
  type TrustFinding,
  type TrustMode,
  scanTrustForFiles,
} from './trust/scan.ts';
import { SshVerifier, type Verifier } from './trust/signer.ts';
import { walk } from './walk.ts';

export type FileReport = {
  readonly path: string;
  readonly kind: FileKind;
  readonly findings: ReadonlyArray<UnicodeFinding>;
  readonly promptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
  readonly mcpFindings: ReadonlyArray<McpFinding>;
  readonly trustFindings: ReadonlyArray<TrustFinding>;
  readonly supplyChainFindings: ReadonlyArray<SupplyChainFinding>;
  readonly marker: Marker | null;
  readonly suppressedFindings: ReadonlyArray<UnicodeFinding>;
  readonly suppressedPromptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
  readonly suppressedMcpFindings: ReadonlyArray<McpFinding>;
  readonly suppressedTrustFindings: ReadonlyArray<TrustFinding>;
  readonly suppressedSupplyChainFindings: ReadonlyArray<SupplyChainFinding>;
};

export type MarkerError = {
  readonly path: string;
  readonly message: string;
};

export type TrustState =
  | 'not-enforced'
  | 'enforced'
  | 'strict'
  | 'sentinel-no-manifest'
  | 'invocation-error';

// IOC cache state for `supply-chain.*` findings (ADR 0016 §5):
//   - 'absent'      no cache initialized (warden ioc sync never run)
//   - 'fresh'       cache present and within staleness TTL
//   - 'stale'       cache present but past TTL (≥7d default)
//   - 'unreadable'  cache present but couldn't be read (corrupt JSON, perms)
//   - 'not-required'  no lockfiles in the scan, so cache state is irrelevant
export type IocState = 'absent' | 'fresh' | 'stale' | 'unreadable' | 'not-required';

export type ScanReport = {
  readonly root: string;
  readonly scannedAt: string;
  readonly fileCount: number;
  readonly matchedCount: number;
  readonly findingCount: number;
  readonly highCount: number;
  readonly mediumCount: number;
  readonly lowCount: number;
  // `info` is the new severity tier introduced by ADR 0016 §4 (M9).
  // Default exit policy does NOT gate on info; --strict does.
  readonly infoCount: number;
  readonly suppressedCount: number;
  readonly suppressedByCategory: Readonly<Record<FindingCategory | 'trust', number>>;
  readonly files: ReadonlyArray<FileReport>;
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
  readonly markerErrors: ReadonlyArray<MarkerError>;
  readonly trustState: TrustState;
  readonly trustError: string | null;
  readonly orphanTrustFindings: ReadonlyArray<TrustFinding>;
  readonly iocState: IocState;
  readonly iocMessage: string | null;
  readonly supplyChainParseErrors: ReadonlyArray<SupplyChainParseError>;
};

export type ScanOptions = {
  readonly respectGitignore?: boolean;
  readonly now?: () => Date;
  readonly strict?: boolean;
  readonly verifier?: Verifier;
  // For tests/single-file scans: pretend the scan root sits under this
  // directory when looking for `.warden/trust/`. Defaults to the scan
  // root (or its parent if root is a file).
  readonly trustRoot?: string;
  // Optional IOC lookup bundle. When provided, scanPath calls
  // scanSupplyChain on each detected lockfile (ADR 0016 §8). When
  // omitted (or null), lockfile scanning is skipped — the resulting
  // `iocState` reports 'absent' if any lockfile was encountered, else
  // 'not-required'. The CLI wires this bundle from @warden-sh/ioc.
  readonly iocLookup?: ScanIocLookup | null;
  // Reported `iocState` value when iocLookup is provided. The CLI
  // computes it from manifest age and passes it through; scanPath
  // itself doesn't read the manifest.
  readonly iocStateHint?: 'fresh' | 'stale';
};

function safeReadUtf8(absPath: string): string | null {
  try {
    return readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}

function safeReadBytes(absPath: string): Uint8Array | null {
  try {
    return new Uint8Array(readFileSync(absPath));
  } catch {
    return null;
  }
}

type FileScanResult =
  | {
      readonly kind: 'report';
      readonly report: FileReport;
      readonly rawBytes: Uint8Array;
      readonly content: string;
    }
  | { readonly kind: 'error'; readonly error: MarkerError };

function scanSingleFile(
  absPath: string,
  displayPath: string,
  fileKind: FileKind,
): FileScanResult | null {
  const bytes = safeReadBytes(absPath);
  if (bytes === null) return null;
  const content = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

  const markerResult = parseMarker(displayPath, content);
  if (markerResult.kind === 'error') {
    return { kind: 'error', error: { path: displayPath, message: markerResult.message } };
  }
  const marker = markerResult.kind === 'ok' ? markerResult.marker : null;

  const unicodeFindings = scanUnicode(content);
  const piFindings = scanPromptInjection(content);
  // MCP findings only apply to mcp-json files; running the JSON parser
  // against markdown/CLAUDE.md would just produce invalid-json noise.
  const mcpFindings: ReadonlyArray<McpFinding> = fileKind === 'mcp-json' ? scanMcp(content) : [];

  const unicodeSplit = applyMarker(marker, 'unicode', unicodeFindings, content);
  const piSplit = applyMarker(marker, 'prompt-injection', piFindings, content);
  const mcpSplit = applyMarker(marker, 'mcp', mcpFindings, content);

  return {
    kind: 'report',
    rawBytes: bytes,
    content,
    report: {
      path: displayPath,
      kind: fileKind,
      findings: unicodeSplit.kept,
      promptInjectionFindings: piSplit.kept,
      mcpFindings: mcpSplit.kept,
      trustFindings: [],
      supplyChainFindings: [],
      marker,
      suppressedFindings: unicodeSplit.suppressed,
      suppressedPromptInjectionFindings: piSplit.suppressed,
      suppressedMcpFindings: mcpSplit.suppressed,
      suppressedTrustFindings: [],
      suppressedSupplyChainFindings: [],
    },
  };
}

function isLockfileKind(k: FileKind): boolean {
  return (
    k === 'npm-lockfile' || k === 'poetry-lockfile' || k === 'uv-lockfile' || k === 'cargo-lockfile'
  );
}

function ecosystemForLockfile(k: FileKind): 'npm' | 'PyPI' | 'crates.io' | null {
  if (k === 'npm-lockfile') return 'npm';
  if (k === 'poetry-lockfile' || k === 'uv-lockfile') return 'PyPI';
  if (k === 'cargo-lockfile') return 'crates.io';
  return null;
}

// Locate the adjacent manifest read by the Poetry / Cargo parsers
// (ADR 0016 §3). Pure path resolution + read; called once per
// lockfile. The walker may have already excluded these manifests if
// they were .gitignored, but the file-system read is independent.
function readAdjacentManifest(
  scanRoot: string,
  lockfileRelOrAbsPath: string,
  isFileRoot: boolean,
  manifestBase: string,
): string | null {
  const lockfileAbs = isFileRoot ? lockfileRelOrAbsPath : resolve(scanRoot, lockfileRelOrAbsPath);
  const manifestAbs = resolve(dirname(lockfileAbs), manifestBase);
  return safeReadUtf8(manifestAbs);
}

function readManifest(trustRoot: string): { manifest: Manifest | null; error: string | null } {
  const manifestPath = resolve(trustRoot, '.warden', 'trust', 'manifest.toml');
  if (!existsSync(manifestPath)) return { manifest: null, error: null };
  const content = safeReadUtf8(manifestPath);
  if (content === null) {
    return { manifest: null, error: `cannot read ${manifestPath}` };
  }
  const result = parseManifest(content);
  if (result.kind === 'error') {
    return { manifest: null, error: `manifest parse error: ${result.message}` };
  }
  return { manifest: result.manifest, error: null };
}

function readAllowedSigners(trustRoot: string, strict: boolean): string | null {
  const repoPath = resolve(trustRoot, '.warden', 'trust', 'allowed_signers');
  let combined = '';
  let any = false;
  if (existsSync(repoPath)) {
    const text = safeReadUtf8(repoPath);
    if (text !== null) {
      combined += text;
      any = true;
    }
  }
  // ADR 0012 §5: ~/.warden/extra_allowed_signers is additive but ignored
  // under --strict (production posture trusts only the repo-committed root).
  if (!strict) {
    const extraPath = resolve(homedir(), '.warden', 'extra_allowed_signers');
    if (existsSync(extraPath)) {
      const text = safeReadUtf8(extraPath);
      if (text !== null) {
        combined += `\n${text}`;
        any = true;
      }
    }
  }
  return any ? combined : null;
}

function sentinelPresent(trustRoot: string): boolean {
  return existsSync(resolve(trustRoot, '.warden', 'trust-required'));
}

const BROAD_MARKER_FAMILIES: ReadonlyArray<string> = ['rules-data', 'detector-test'];

function fileIsBroadMarker(report: FileReport): boolean {
  if (report.marker === null) return false;
  for (const fam of report.marker.families) {
    if (BROAD_MARKER_FAMILIES.includes(fam)) return true;
  }
  return false;
}

export function scanPath(rootPath: string, opts: ScanOptions = {}): ScanReport {
  const root = resolve(rootPath);
  const now = opts.now ?? (() => new Date());
  const strict = opts.strict === true;

  let isFileRoot = false;
  try {
    isFileRoot = statSync(root).isFile();
  } catch {
    // Non-existent or unreadable — return an empty report; the CLI surface
    // is responsible for reporting the user-facing error.
  }

  const trustRoot = opts.trustRoot ?? (isFileRoot ? dirname(root) : root);

  const files: FileReport[] = [];
  const rawBytesByPath = new Map<string, Uint8Array>();
  const contentByPath = new Map<string, string>();
  const markerErrors: MarkerError[] = [];
  let unsupported: ReadonlyArray<string> = [];

  if (isFileRoot) {
    const kind = detectFormat(basename(root));
    if (kind !== null) {
      const r = scanSingleFile(root, basename(root), kind);
      if (r !== null) {
        if (r.kind === 'report') {
          files.push(r.report);
          rawBytesByPath.set(r.report.path, r.rawBytes);
          contentByPath.set(r.report.path, r.content);
        } else markerErrors.push(r.error);
      }
    }
  } else {
    const w = walk(root, { respectGitignore: opts.respectGitignore !== false });
    unsupported = w.unsupportedGitignorePatterns;
    for (const rel of w.files) {
      const kind = detectFormat(rel);
      if (kind === null) continue;
      const r = scanSingleFile(resolve(root, rel), rel, kind);
      if (r === null) continue;
      if (r.kind === 'report') {
        files.push(r.report);
        rawBytesByPath.set(r.report.path, r.rawBytes);
        contentByPath.set(r.report.path, r.content);
      } else markerErrors.push(r.error);
    }
  }

  // Trust verification layer.
  const sentinel = sentinelPresent(trustRoot);
  const { manifest, error: manifestError } = readManifest(trustRoot);
  const allowedSignersContent = readAllowedSigners(trustRoot, strict);

  let trustState: TrustState;
  let trustError: string | null = manifestError;
  let orphanTrustFindings: ReadonlyArray<TrustFinding> = [];

  if (manifestError !== null) {
    trustState = 'invocation-error';
  } else if (strict && manifest === null) {
    trustState = 'invocation-error';
    trustError = '--strict requires .warden/trust/manifest.toml to be present';
  } else if (manifest === null && sentinel) {
    trustState = 'sentinel-no-manifest';
  } else if (manifest === null) {
    trustState = 'not-enforced';
  } else if (strict) {
    trustState = 'strict';
  } else {
    trustState = 'enforced';
  }

  if (trustState !== 'not-enforced' && trustState !== 'invocation-error') {
    const verifier = opts.verifier ?? new SshVerifier();
    const inputs: TrustFileInput[] = files.map((f) => {
      const bytes = rawBytesByPath.get(f.path);
      return {
        path: f.path,
        content: bytes ?? new Uint8Array(),
        hasBroadMarker: fileIsBroadMarker(f),
      };
    });
    const mode: TrustMode = {
      strict,
      manifestPresent: manifest !== null,
      sentinelPresent: sentinel,
      allowedSignersContent,
    };
    const result = scanTrustForFiles(inputs, manifest, mode, verifier);
    orphanTrustFindings = result.orphanFindings;
    for (let i = 0; i < files.length; i++) {
      const f = files[i] as FileReport;
      const r = result.perFile.get(f.path);
      if (r === undefined) continue;
      files[i] = {
        ...f,
        trustFindings: r.kept,
        suppressedTrustFindings: r.suppressed,
      };
    }
  }

  // Supply-chain layer (ADR 0016 §8). Per-lockfile scan with marker
  // suppression. Index loading is lazy via the injected ScanIocLookup —
  // packages/core does not depend on @warden-sh/ioc directly.
  const supplyChainParseErrors: SupplyChainParseError[] = [];
  const hasLockfiles = files.some((f) => isLockfileKind(f.kind));
  let iocState: IocState;
  let iocMessage: string | null = null;

  if (!hasLockfiles) {
    iocState = 'not-required';
  } else if (opts.iocLookup === undefined || opts.iocLookup === null) {
    iocState = 'absent';
    iocMessage = "ioc cache not initialized; run 'warden ioc sync' to enable supply-chain checks";
  } else {
    iocState = opts.iocStateHint === 'stale' ? 'stale' : 'fresh';
    for (let i = 0; i < files.length; i++) {
      const f = files[i] as FileReport;
      if (!isLockfileKind(f.kind)) continue;
      const eco = ecosystemForLockfile(f.kind);
      if (eco === null) continue;
      const lookup = opts.iocLookup.forEcosystem(eco);
      if (lookup === null) continue; // index for this ecosystem not synced
      const content = contentByPath.get(f.path) ?? '';
      const manifestContent =
        f.kind === 'cargo-lockfile'
          ? readAdjacentManifest(root, isFileRoot ? root : f.path, isFileRoot, 'Cargo.toml')
          : f.kind === 'poetry-lockfile'
            ? readAdjacentManifest(root, isFileRoot ? root : f.path, isFileRoot, 'pyproject.toml')
            : null;
      const result = scanSupplyChain(
        { lockfileKind: f.kind, lockfileContent: content, manifestContent },
        lookup,
      );
      if (result.parseError !== null) {
        supplyChainParseErrors.push({ path: f.path, message: result.parseError });
      }
      const split = applyMarker(f.marker, 'supply-chain', result.findings, content);
      files[i] = {
        ...f,
        supplyChainFindings: split.kept,
        suppressedSupplyChainFindings: split.suppressed,
      };
    }
  }

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;
  let findingCount = 0;
  let suppressedUnicode = 0;
  let suppressedPi = 0;
  let suppressedMcp = 0;
  let suppressedTrust = 0;
  let suppressedSupply = 0;
  const tally = (severity: 'high' | 'medium' | 'low' | SupplyChainSeverity): void => {
    findingCount += 1;
    if (severity === 'high') highCount += 1;
    else if (severity === 'medium') mediumCount += 1;
    else if (severity === 'low') lowCount += 1;
    else if (severity === 'info') infoCount += 1;
  };
  for (const f of files) {
    for (const finding of f.findings) tally(finding.severity);
    for (const pi of f.promptInjectionFindings) tally(pi.severity);
    for (const mcp of f.mcpFindings) tally(mcp.severity);
    for (const t of f.trustFindings) tally(t.severity);
    for (const sc of f.supplyChainFindings) tally(sc.severity);
    suppressedUnicode += f.suppressedFindings.length;
    suppressedPi += f.suppressedPromptInjectionFindings.length;
    suppressedMcp += f.suppressedMcpFindings.length;
    suppressedTrust += f.suppressedTrustFindings.length;
    suppressedSupply += f.suppressedSupplyChainFindings.length;
  }
  for (const t of orphanTrustFindings) tally(t.severity);

  return {
    root,
    scannedAt: now().toISOString(),
    fileCount: files.length,
    matchedCount: files.length,
    findingCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount,
    suppressedCount:
      suppressedUnicode + suppressedPi + suppressedMcp + suppressedTrust + suppressedSupply,
    suppressedByCategory: {
      unicode: suppressedUnicode,
      'prompt-injection': suppressedPi,
      mcp: suppressedMcp,
      'supply-chain': suppressedSupply,
      trust: suppressedTrust,
    },
    files,
    unsupportedGitignorePatterns: unsupported,
    markerErrors,
    trustState,
    trustError,
    orphanTrustFindings,
    iocState,
    iocMessage,
    supplyChainParseErrors,
  };
}
