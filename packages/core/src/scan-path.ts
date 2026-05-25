// scanPath composes walk -> detectFormat -> scanUnicode + scanPromptInjection
// into a single deterministic, offline pipeline. After detection, payload-
// fixture markers (ADR 0010) split findings into kept vs suppressed. The
// returned ScanReport surfaces both so reporters can show "the scanner did
// see this, the marker explained it".
//
// I/O surface: readFileSync only. No network, no spawn, no async. The
// architecture boundary in docs/ARCHITECTURE.md §4 ("hot path") forbids
// network calls; readFileSync is the only I/O the scanner is permitted.

import { readFileSync, statSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { type FileKind, detectFormat } from './detect-format.ts';
import type { PromptInjectionFinding, UnicodeFinding } from './findings.ts';
import { type FindingCategory, type Marker, applyMarker, parseMarker } from './marker.ts';
import { scanPromptInjection } from './scan-prompt-injection.ts';
import { scanUnicode } from './scan-unicode.ts';
import { walk } from './walk.ts';

export type FileReport = {
  readonly path: string;
  readonly kind: FileKind;
  readonly findings: ReadonlyArray<UnicodeFinding>;
  readonly promptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
  readonly marker: Marker | null;
  readonly suppressedFindings: ReadonlyArray<UnicodeFinding>;
  readonly suppressedPromptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
};

export type MarkerError = {
  readonly path: string;
  readonly message: string;
};

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
  readonly suppressedByCategory: Readonly<Record<FindingCategory, number>>;
  readonly files: ReadonlyArray<FileReport>;
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
  readonly markerErrors: ReadonlyArray<MarkerError>;
};

export type ScanOptions = {
  readonly respectGitignore?: boolean;
  readonly now?: () => Date;
};

function safeReadUtf8(absPath: string): string | null {
  try {
    return readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}

type FileScanResult =
  | { readonly kind: 'report'; readonly report: FileReport }
  | { readonly kind: 'error'; readonly error: MarkerError };

function scanSingleFile(
  absPath: string,
  displayPath: string,
  fileKind: FileKind,
): FileScanResult | null {
  const content = safeReadUtf8(absPath);
  if (content === null) return null;

  const markerResult = parseMarker(displayPath, content);
  if (markerResult.kind === 'error') {
    return { kind: 'error', error: { path: displayPath, message: markerResult.message } };
  }
  const marker = markerResult.kind === 'ok' ? markerResult.marker : null;

  const unicodeFindings = scanUnicode(content);
  const piFindings = scanPromptInjection(content);

  const unicodeSplit = applyMarker(marker, 'unicode', unicodeFindings, content);
  const piSplit = applyMarker(marker, 'prompt-injection', piFindings, content);

  return {
    kind: 'report',
    report: {
      path: displayPath,
      kind: fileKind,
      findings: unicodeSplit.kept,
      promptInjectionFindings: piSplit.kept,
      marker,
      suppressedFindings: unicodeSplit.suppressed,
      suppressedPromptInjectionFindings: piSplit.suppressed,
    },
  };
}

export function scanPath(rootPath: string, opts: ScanOptions = {}): ScanReport {
  const root = resolve(rootPath);
  const now = opts.now ?? (() => new Date());

  let isFileRoot = false;
  try {
    isFileRoot = statSync(root).isFile();
  } catch {
    // Non-existent or unreadable — return an empty report; the CLI surface
    // is responsible for reporting the user-facing error.
  }

  const files: FileReport[] = [];
  const markerErrors: MarkerError[] = [];
  let unsupported: ReadonlyArray<string> = [];

  if (isFileRoot) {
    const kind = detectFormat(basename(root));
    if (kind !== null) {
      const r = scanSingleFile(root, basename(root), kind);
      if (r !== null) {
        if (r.kind === 'report') files.push(r.report);
        else markerErrors.push(r.error);
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
      if (r.kind === 'report') files.push(r.report);
      else markerErrors.push(r.error);
    }
  }

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let findingCount = 0;
  let suppressedUnicode = 0;
  let suppressedPi = 0;
  for (const f of files) {
    for (const finding of f.findings) {
      findingCount += 1;
      if (finding.severity === 'high') highCount += 1;
      else if (finding.severity === 'medium') mediumCount += 1;
      else lowCount += 1;
    }
    for (const pi of f.promptInjectionFindings) {
      findingCount += 1;
      if (pi.severity === 'high') highCount += 1;
      else if (pi.severity === 'medium') mediumCount += 1;
      else lowCount += 1;
    }
    suppressedUnicode += f.suppressedFindings.length;
    suppressedPi += f.suppressedPromptInjectionFindings.length;
  }

  return {
    root,
    scannedAt: now().toISOString(),
    fileCount: files.length,
    matchedCount: files.length,
    findingCount,
    highCount,
    mediumCount,
    lowCount,
    suppressedCount: suppressedUnicode + suppressedPi,
    suppressedByCategory: {
      unicode: suppressedUnicode,
      'prompt-injection': suppressedPi,
    },
    files,
    unsupportedGitignorePatterns: unsupported,
    markerErrors,
  };
}
