import { describe, expect, test } from 'bun:test';
import { hashFileContent } from '../src/trust/hash.ts';
import { emptyManifest, upsertTrust, upsertUnlock } from '../src/trust/manifest.ts';
import { type TrustFileInput, type TrustMode, scanTrustForFiles } from '../src/trust/scan.ts';
import { buildSignMessage } from '../src/trust/sign-message.ts';
import { MockVerifier } from '../src/trust/signer.ts';

// Deterministic stamp function — paired with MockVerifier the same way
// MockSigner would be: signature blob is "stamp:<hex>" of the message.
function stamp(message: Uint8Array): string {
  let s = 'stamp:';
  for (const b of message) s += b.toString(16).padStart(2, '0');
  return s;
}

const TRUSTED_FP = 'SHA256:trusted';
const UNTRUSTED_FP = 'SHA256:untrusted';

function makeManifestWithEntry(path: string, content: Uint8Array, signerFp = TRUSTED_FP) {
  const hash = hashFileContent(content);
  const sig = stamp(buildSignMessage(path, hash));
  return upsertTrust(emptyManifest(), {
    path,
    hash,
    signer: signerFp,
    signedAt: '2026-05-25T03:14:00Z',
    signature: sig,
    reason: null,
  }).manifest;
}

const defaultMode: TrustMode = {
  strict: false,
  manifestPresent: true,
  sentinelPresent: false,
  allowedSignersContent: 'unused-by-mock',
};

const verifier = new MockVerifier({ trustedFingerprints: [TRUSTED_FP], stamp });

describe('scanTrustForFiles', () => {
  test('no manifest, no sentinel, no strict → trust not enforced', () => {
    const content = new TextEncoder().encode('hi');
    const files: TrustFileInput[] = [{ path: 'a.md', content, hasBroadMarker: false }];
    const r = scanTrustForFiles(
      files,
      null,
      { ...defaultMode, manifestPresent: false, allowedSignersContent: null },
      verifier,
    );
    expect(r.perFile.size).toBe(0);
    expect(r.orphanFindings).toHaveLength(0);
  });

  test('sentinel present, no manifest → trust.unsigned HIGH for every file', () => {
    const files: TrustFileInput[] = [
      { path: 'a.md', content: new TextEncoder().encode('hi'), hasBroadMarker: false },
    ];
    const r = scanTrustForFiles(
      files,
      null,
      {
        ...defaultMode,
        manifestPresent: false,
        sentinelPresent: true,
        allowedSignersContent: null,
      },
      verifier,
    );
    const a = r.perFile.get('a.md');
    expect(a?.kept).toHaveLength(1);
    expect(a?.kept[0]?.severity).toBe('high');
    expect(a?.kept[0]?.ruleId).toBe('trust.unsigned');
  });

  test('valid signature passes cleanly', () => {
    const content = new TextEncoder().encode('hi');
    const manifest = makeManifestWithEntry('a.md', content);
    const files: TrustFileInput[] = [{ path: 'a.md', content, hasBroadMarker: false }];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    expect(r.perFile.get('a.md')?.kept).toHaveLength(0);
    expect(r.orphanFindings).toHaveLength(0);
  });

  test('byte-level tamper → trust.signature-mismatch HIGH', () => {
    const original = new TextEncoder().encode('hi');
    const manifest = makeManifestWithEntry('a.md', original);
    const tampered = new TextEncoder().encode('hI');
    const files: TrustFileInput[] = [{ path: 'a.md', content: tampered, hasBroadMarker: false }];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    const finding = r.perFile.get('a.md')?.kept[0];
    expect(finding?.ruleId).toBe('trust.signature-mismatch');
    expect(finding?.severity).toBe('high');
  });

  test('signer not in allowed_signers → trust.untrusted-signer HIGH', () => {
    const content = new TextEncoder().encode('hi');
    const manifest = makeManifestWithEntry('a.md', content, UNTRUSTED_FP);
    const files: TrustFileInput[] = [{ path: 'a.md', content, hasBroadMarker: false }];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    const finding = r.perFile.get('a.md')?.kept[0];
    expect(finding?.ruleId).toBe('trust.untrusted-signer');
    expect(finding?.severity).toBe('high');
  });

  test('unsigned file with manifest → trust.unsigned MEDIUM in default mode', () => {
    const manifest = emptyManifest();
    const files: TrustFileInput[] = [
      { path: 'a.md', content: new TextEncoder().encode('hi'), hasBroadMarker: false },
    ];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    const finding = r.perFile.get('a.md')?.kept[0];
    expect(finding?.ruleId).toBe('trust.unsigned');
    expect(finding?.severity).toBe('medium');
  });

  test('unlock entry suppresses trust.unsigned (default mode)', () => {
    const manifest = upsertUnlock(emptyManifest(), {
      path: 'a.md',
      reason: 'wip',
      unlockedAt: 't',
      unlockedBy: 'u',
    }).manifest;
    const files: TrustFileInput[] = [
      { path: 'a.md', content: new TextEncoder().encode('hi'), hasBroadMarker: false },
    ];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    const a = r.perFile.get('a.md');
    expect(a?.kept).toHaveLength(0);
    expect(a?.suppressed).toHaveLength(1);
    expect(a?.suppressed[0]?.ruleId).toBe('trust.unsigned');
  });

  test('unlock NEVER suppresses signature-mismatch', () => {
    const original = new TextEncoder().encode('hi');
    let manifest = makeManifestWithEntry('a.md', original);
    manifest = upsertUnlock(manifest, {
      path: 'a.md',
      reason: 'wip',
      unlockedAt: 't',
      unlockedBy: 'u',
    }).manifest;
    const tampered = new TextEncoder().encode('hI');
    const files: TrustFileInput[] = [{ path: 'a.md', content: tampered, hasBroadMarker: false }];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    const a = r.perFile.get('a.md');
    expect(a?.kept).toHaveLength(1);
    expect(a?.kept[0]?.ruleId).toBe('trust.signature-mismatch');
  });

  test('strict mode ignores unlock entry', () => {
    const manifest = upsertUnlock(emptyManifest(), {
      path: 'a.md',
      reason: 'wip',
      unlockedAt: 't',
      unlockedBy: 'u',
    }).manifest;
    const files: TrustFileInput[] = [
      { path: 'a.md', content: new TextEncoder().encode('hi'), hasBroadMarker: false },
    ];
    const r = scanTrustForFiles(files, manifest, { ...defaultMode, strict: true }, verifier);
    const a = r.perFile.get('a.md');
    expect(a?.kept).toHaveLength(1);
    expect(a?.suppressed).toHaveLength(0);
    expect(a?.kept[0]?.severity).toBe('high');
  });

  test('broad-marker + unsigned → trust.unsigned elevated to HIGH', () => {
    const manifest = emptyManifest();
    const files: TrustFileInput[] = [
      { path: 'a.md', content: new TextEncoder().encode('hi'), hasBroadMarker: true },
    ];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    expect(r.perFile.get('a.md')?.kept[0]?.severity).toBe('high');
  });

  test('orphan entry: manifest declares path absent from walk', () => {
    const manifest = makeManifestWithEntry('absent.md', new TextEncoder().encode('hi'));
    const files: TrustFileInput[] = [];
    const r = scanTrustForFiles(files, manifest, defaultMode, verifier);
    expect(r.orphanFindings).toHaveLength(1);
    expect(r.orphanFindings[0]?.ruleId).toBe('trust.orphan-entry');
    expect(r.orphanFindings[0]?.severity).toBe('low');
  });

  test('orphan entry: severity is MEDIUM under strict', () => {
    const manifest = makeManifestWithEntry('absent.md', new TextEncoder().encode('hi'));
    const r = scanTrustForFiles([], manifest, { ...defaultMode, strict: true }, verifier);
    expect(r.orphanFindings[0]?.severity).toBe('medium');
  });
});
