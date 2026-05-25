// scanPath composes walk -> detectFormat -> scanUnicode + scanPromptInjection
// into a single deterministic, offline pipeline. Returns a typed report
// consumable by any reporter in packages/cli.
//
// I/O surface: readFileSync only. No network, no spawn, no async. The
// architecture boundary in docs/ARCHITECTURE.md §4 ("hot path") forbids
// network calls; readFileSync is the only I/O the scanner is permitted.

import { readFileSync, statSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { type FileKind, detectFormat } from './detect-format.ts';
import type { PromptInjectionFinding, UnicodeFinding } from './findings.ts';
import { scanPromptInjection } from './scan-prompt-injection.ts';
import { scanUnicode } from './scan-unicode.ts';
import { walk } from './walk.ts';

export type FileReport = {
  readonly path: string;
  readonly kind: FileKind;
  readonly findings: ReadonlyArray<UnicodeFinding>;
  readonly promptInjectionFindings: ReadonlyArray<PromptInjectionFinding>;
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
  readonly files: ReadonlyArray<FileReport>;
  readonly unsupportedGitignorePatterns: ReadonlyArray<string>;
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

function singleFileReport(absPath: string, displayPath: string): FileReport | null {
  const kind = detectFormat(displayPath);
  if (kind === null) return null;
  const content = safeReadUtf8(absPath);
  if (content === null) return null;
  return {
    path: displayPath,
    kind,
    findings: scanUnicode(content),
    promptInjectionFindings: scanPromptInjection(content),
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
  let unsupported: ReadonlyArray<string> = [];

  if (isFileRoot) {
    const report = singleFileReport(root, basename(root));
    if (report !== null) files.push(report);
  } else {
    const w = walk(root, { respectGitignore: opts.respectGitignore !== false });
    unsupported = w.unsupportedGitignorePatterns;
    for (const rel of w.files) {
      const kind = detectFormat(rel);
      if (kind === null) continue;
      const content = safeReadUtf8(resolve(root, rel));
      if (content === null) continue;
      files.push({
        path: rel,
        kind,
        findings: scanUnicode(content),
        promptInjectionFindings: scanPromptInjection(content),
      });
    }
  }

  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let findingCount = 0;
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
    files,
    unsupportedGitignorePatterns: unsupported,
  };
}
