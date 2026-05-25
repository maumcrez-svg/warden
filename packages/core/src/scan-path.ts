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
import type { McpFinding, PromptInjectionFinding, UnicodeFinding } from './findings.ts';
import { type FindingCategory, type Marker, applyMarker, parseMarker } from './marker.ts';
import { scanMcp } from './scan-mcp.ts';
import { scanPromptInjection } from './scan-prompt-injection.ts';
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
  readonly marker: Marker | null;
  readonly suppressedFindings: ReadonlyArray<UnicodeFinding>;
  readonly suppressedPromptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
  readonly suppressedMcpFindings: ReadonlyArray<McpFinding>;
  readonly suppressedTrustFindings: ReadonlyArray<TrustFinding>;
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

export type ScanReport = {
  readonly root: string;
  readonly scannedAt: string;
  readonly fileCount: number;
  readonly matchedCount: number;
  readonly findingCount: number;
  readonly highCount: number;
  readonly mediumCount: number;
  readonly lowCount: number;
  readonly suppressedCount: number;
  readonly suppressedByCategory: Readonly<Record<FindingCategory | 'trust', number>>;
  readonly files: ReadonlyArray<FileReport>;
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
  readonly markerErrors: ReadonlyArray<MarkerError>;
  readonly trustState: TrustState;
  readonly trustError: string | null;
  readonly orphanTrustFindings: ReadonlyArray<TrustFinding>;
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
  | { readonly kind: 'report'; readonly report: FileReport; readonly rawBytes: Uint8Array }
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
    report: {
      path: displayPath,
      kind: fileKind,
      findings: unicodeSplit.kept,
      promptInjectionFindings: piSplit.kept,
      mcpFindings: mcpSplit.kept,
      trustFindings: [],
      marker,
      suppressedFindings: unicodeSplit.suppressed,
      suppressedPromptInjectionFindings: piSplit.suppressed,
      suppressedMcpFindings: mcpSplit.suppressed,
      suppressedTrustFindings: [],
    },
  };
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

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let findingCount = 0;
  let suppressedUnicode = 0;
  let suppressedPi = 0;
  let suppressedMcp = 0;
  let suppressedTrust = 0;
  const tally = (severity: 'high' | 'medium' | 'low'): void => {
    findingCount += 1;
    if (severity === 'high') highCount += 1;
    else if (severity === 'medium') mediumCount += 1;
    else lowCount += 1;
  };
  for (const f of files) {
    for (const finding of f.findings) tally(finding.severity);
    for (const pi of f.promptInjectionFindings) tally(pi.severity);
    for (const mcp of f.mcpFindings) tally(mcp.severity);
    for (const t of f.trustFindings) tally(t.severity);
    suppressedUnicode += f.suppressedFindings.length;
    suppressedPi += f.suppressedPromptInjectionFindings.length;
    suppressedMcp += f.suppressedMcpFindings.length;
    suppressedTrust += f.suppressedTrustFindings.length;
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
    suppressedCount: suppressedUnicode + suppressedPi + suppressedMcp + suppressedTrust,
    suppressedByCategory: {
      unicode: suppressedUnicode,
      'prompt-injection': suppressedPi,
      mcp: suppressedMcp,
      trust: suppressedTrust,
    },
    files,
    unsupportedGitignorePatterns: unsupported,
    markerErrors,
    trustState,
    trustError,
    orphanTrustFindings,
  };
}
