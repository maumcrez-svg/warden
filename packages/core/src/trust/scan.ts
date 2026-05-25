// Trust verification pipeline. ADR 0012 §3 (default-behavior matrix).
//
// Inputs:
//   - manifest (parsed from .warden/trust/manifest.toml; may be absent)
//   - allowedSignersContent (committed .warden/trust/allowed_signers;
//     in --strict mode, ~/.warden/extra_allowed_signers is ignored)
//   - sentinelPresent (.warden/trust-required)
//   - perFile content + manifest entry lookups
//
// Outputs:
//   - per-file `TrustFinding[]` (kept) and `suppressedTrustFindings[]`
//     for findings silenced by an [[unlock]] block
//   - orphan entries (manifest entries whose path is absent on disk)
//   - a top-level `trustState` discriminator
//
// The pipeline itself does not read files — it operates on already-
// loaded content. The caller (`scanPath`) is responsible for I/O.

import { hashFileContent } from './hash.ts';
import { type Manifest, type TrustEntry, findTrust, findUnlock } from './manifest.ts';
import { buildSignMessage } from './sign-message.ts';
import type { Verifier, VerifyResult } from './signer.ts';

export type TrustSeverity = 'high' | 'medium' | 'low';

export type TrustFindingCategory =
  | 'trust.unsigned'
  | 'trust.signature-mismatch'
  | 'trust.untrusted-signer'
  | 'trust.orphan-entry';

export type TrustFinding = {
  readonly ruleId: TrustFindingCategory;
  readonly severity: TrustSeverity;
  readonly message: string;
  readonly hint: string;
  readonly path: string;
};

export type TrustMode = {
  readonly strict: boolean;
  readonly manifestPresent: boolean;
  readonly sentinelPresent: boolean;
  readonly allowedSignersContent: string | null;
};

export type TrustFileInput = {
  readonly path: string;
  readonly content: Uint8Array;
  readonly hasBroadMarker: boolean;
};

export type FileTrustResult = {
  readonly kept: ReadonlyArray<TrustFinding>;
  readonly suppressed: ReadonlyArray<TrustFinding>;
};

export type TrustScanResult = {
  readonly perFile: ReadonlyMap<string, FileTrustResult>;
  readonly orphanFindings: ReadonlyArray<TrustFinding>;
};

function unsignedSeverity(strict: boolean, broadMarker: boolean): TrustSeverity {
  if (strict) return 'high';
  if (broadMarker) return 'high';
  return 'medium';
}

function elevatedHighForBroad(strict: boolean, broadMarker: boolean): TrustSeverity {
  // signature-mismatch / untrusted-signer baseline is HIGH; broad-marker
  // does not change that, but neither does --strict downgrade it.
  if (strict || broadMarker) return 'high';
  return 'high';
}

function orphanSeverity(strict: boolean): TrustSeverity {
  return strict ? 'medium' : 'low';
}

function makeFinding(
  category: TrustFindingCategory,
  severity: TrustSeverity,
  path: string,
  message: string,
  hint: string,
): TrustFinding {
  return { ruleId: category, severity, message, hint, path };
}

function verifyEntry(
  verifier: Verifier,
  entry: TrustEntry,
  fileContent: Uint8Array,
  allowedSignersContent: string,
): { ok: true } | { ok: false; reason: 'hash-mismatch' | VerifyResult['kind']; message: string } {
  const onDisk = hashFileContent(fileContent);
  if (onDisk !== entry.hash) {
    return {
      ok: false,
      reason: 'hash-mismatch',
      message: `on-disk hash ${onDisk} differs from manifest hash ${entry.hash}`,
    };
  }
  const message = buildSignMessage(entry.path, entry.hash);
  const verify = verifier.verify({
    message,
    signatureBlob: entry.signature,
    allowedSignersContent,
    signerFingerprint: entry.signer,
  });
  if (verify.kind === 'ok') return { ok: true };
  return { ok: false, reason: verify.kind, message: verify.message };
}

export function scanTrustForFiles(
  files: ReadonlyArray<TrustFileInput>,
  manifest: Manifest | null,
  mode: TrustMode,
  verifier: Verifier,
): TrustScanResult {
  const perFile = new Map<string, FileTrustResult>();
  const orphanFindings: TrustFinding[] = [];

  // No manifest, no sentinel, no strict → trust simply not enforced.
  if (manifest === null && !mode.sentinelPresent && !mode.strict) {
    return { perFile, orphanFindings };
  }

  // Sentinel without manifest → every walked agent-context file is unsigned.
  // ADR 0012 §3 matrix row 4 ("scan, sentinel present, manifest absent").
  if (manifest === null && mode.sentinelPresent) {
    for (const f of files) {
      const finding = makeFinding(
        'trust.unsigned',
        'high',
        f.path,
        `manifest absent but ${'.warden/trust-required'} sentinel is committed`,
        `to start trust adoption: warden trust sign ${f.path}`,
      );
      perFile.set(f.path, { kept: [finding], suppressed: [] });
    }
    return { perFile, orphanFindings };
  }

  if (manifest === null) {
    // --strict with manifest absent is an invocation error — caller handles.
    return { perFile, orphanFindings };
  }

  const allowed = mode.allowedSignersContent ?? '';

  for (const f of files) {
    const trustEntry = findTrust(manifest, f.path);
    const unlockEntry = findUnlock(manifest, f.path);
    if (trustEntry === null) {
      const sev = unsignedSeverity(mode.strict, f.hasBroadMarker);
      const finding = makeFinding(
        'trust.unsigned',
        sev,
        f.path,
        'file is not signed in .warden/trust/manifest.toml',
        `to sign: warden trust sign ${f.path}`,
      );
      // Unlock suppresses only `trust.unsigned`, and only outside --strict.
      if (unlockEntry !== null && !mode.strict) {
        perFile.set(f.path, { kept: [], suppressed: [finding] });
      } else {
        perFile.set(f.path, { kept: [finding], suppressed: [] });
      }
      continue;
    }

    // Verify hash and signature.
    const result = verifyEntry(verifier, trustEntry, f.content, allowed);
    if (result.ok) {
      perFile.set(f.path, { kept: [], suppressed: [] });
      continue;
    }
    let category: TrustFindingCategory;
    if (result.reason === 'hash-mismatch') category = 'trust.signature-mismatch';
    else if (result.reason === 'signature-invalid') category = 'trust.signature-mismatch';
    else if (result.reason === 'untrusted-signer') category = 'trust.untrusted-signer';
    else {
      // setup-error: surface as untrusted-signer message rather than swallowing.
      category = 'trust.untrusted-signer';
    }
    const sev = elevatedHighForBroad(mode.strict, f.hasBroadMarker);
    const hint =
      category === 'trust.signature-mismatch'
        ? `to re-sign: warden trust sign ${f.path}`
        : 'add the signing key to .warden/trust/allowed_signers, or re-sign with an allowed key';
    const finding = makeFinding(category, sev, f.path, result.message, hint);
    // Unlock NEVER suppresses mismatch or untrusted-signer (ADR 0012 §3).
    perFile.set(f.path, { kept: [finding], suppressed: [] });
  }

  // Orphan entries: manifest declares a path that wasn't walked / doesn't
  // exist on disk. Default severity is low (warning, exit-0-friendly);
  // strict promotes to medium and contributes to exit 1.
  const filePaths = new Set(files.map((f) => f.path));
  for (const t of manifest.trust) {
    if (!filePaths.has(t.path)) {
      orphanFindings.push(
        makeFinding(
          'trust.orphan-entry',
          orphanSeverity(mode.strict),
          t.path,
          'manifest entry has no matching file on disk',
          `remove the orphan entry by re-signing without ${t.path}, or restore the file`,
        ),
      );
    }
  }

  return { perFile, orphanFindings };
}
