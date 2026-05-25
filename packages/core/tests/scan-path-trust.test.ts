// Integration tests for scanPath × trust subsystem. Each test copies a
// scenario fixture from tests/fixtures/trust/<scenario>/ into a temp
// directory, synthesizes the appropriate `.warden/trust/manifest.toml`
// + `allowed_signers` for the scenario, then runs `scanPath` with the
// MockVerifier as the injected dependency. The real ssh-keygen path is
// exercised separately by trust-ssh-roundtrip.test.ts.

import { describe, expect, test } from 'bun:test';
import { cpSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { scanPath } from '../src/index.ts';
import { hashFileContent } from '../src/trust/hash.ts';
import {
  emptyManifest,
  serializeManifest,
  upsertTrust,
  upsertUnlock,
} from '../src/trust/manifest.ts';
import { buildSignMessage } from '../src/trust/sign-message.ts';
import { MockVerifier } from '../src/trust/signer.ts';

const FIXTURES = resolve(import.meta.dir, '../../../tests/fixtures/trust');

function stamp(message: Uint8Array): string {
  let s = 'stamp:';
  for (const b of message) s += b.toString(16).padStart(2, '0');
  return s;
}

const TRUSTED_FP = 'SHA256:mock-trusted';
const UNTRUSTED_FP = 'SHA256:mock-untrusted';
const verifier = new MockVerifier({ trustedFingerprints: [TRUSTED_FP], stamp });

function setupScenario(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `warden-trust-${name}-`));
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  return dir;
}

function writeManifestAndAllowed(dir: string, manifestText: string, allowedSigners: string): void {
  mkdirSync(join(dir, '.warden', 'trust'), { recursive: true });
  writeFileSync(join(dir, '.warden', 'trust', 'manifest.toml'), manifestText);
  writeFileSync(join(dir, '.warden', 'trust', 'allowed_signers'), allowedSigners);
}

describe('scanPath × trust', () => {
  test('signed-clean: valid signature → 0 findings, exit 0 equivalent', () => {
    const dir = setupScenario('signed-clean');
    const content = readFileSync(join(dir, 'CLAUDE.md'));
    const hash = hashFileContent(new Uint8Array(content));
    const signature = stamp(buildSignMessage('CLAUDE.md', hash));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'CLAUDE.md',
      hash,
      signer: TRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature,
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    expect(report.trustState).toBe('enforced');
    expect(report.highCount).toBe(0);
    expect(report.findingCount).toBe(0);
    expect(report.orphanTrustFindings).toHaveLength(0);
  });

  test('signature-mismatch: hash diverges → trust.signature-mismatch HIGH', () => {
    const dir = setupScenario('signature-mismatch');
    const wrongHash = hashFileContent(new TextEncoder().encode('bogus pre-tamper content\n'));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'CLAUDE.md',
      hash: wrongHash,
      signer: TRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature: stamp(buildSignMessage('CLAUDE.md', wrongHash)),
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings).toHaveLength(1);
    expect(file?.trustFindings[0]?.ruleId).toBe('trust.signature-mismatch');
    expect(file?.trustFindings[0]?.severity).toBe('high');
    expect(report.highCount).toBeGreaterThan(0);
  });

  test('untrusted-signer: fingerprint not in allowed_signers → trust.untrusted-signer HIGH', () => {
    const dir = setupScenario('untrusted-signer');
    const content = readFileSync(join(dir, 'CLAUDE.md'));
    const hash = hashFileContent(new Uint8Array(content));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'CLAUDE.md',
      hash,
      signer: UNTRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature: stamp(buildSignMessage('CLAUDE.md', hash)),
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings[0]?.ruleId).toBe('trust.untrusted-signer');
    expect(file?.trustFindings[0]?.severity).toBe('high');
  });

  test('unsigned-with-manifest: file unsigned, manifest covers something else → MEDIUM (default)', () => {
    const dir = setupScenario('unsigned-with-manifest');
    // Manifest declares a [[trust]] entry for an unrelated path that
    // doesn't exist on disk; orphan-entry will fire but the unsigned
    // CLAUDE.md still emits trust.unsigned.
    const otherHash = hashFileContent(new TextEncoder().encode('other'));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'OTHER.md',
      hash: otherHash,
      signer: TRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature: stamp(buildSignMessage('OTHER.md', otherHash)),
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings[0]?.ruleId).toBe('trust.unsigned');
    expect(file?.trustFindings[0]?.severity).toBe('medium');
    // Default mode → highCount stays 0; mediumCount > 0.
    expect(report.highCount).toBe(0);
    expect(report.mediumCount).toBeGreaterThan(0);
  });

  test('unsigned-with-manifest under --strict: unsigned → HIGH, orphan → MEDIUM', () => {
    const dir = setupScenario('unsigned-with-manifest');
    const otherHash = hashFileContent(new TextEncoder().encode('other'));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'OTHER.md',
      hash: otherHash,
      signer: TRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature: stamp(buildSignMessage('OTHER.md', otherHash)),
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier, strict: true });
    expect(report.trustState).toBe('strict');
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings[0]?.severity).toBe('high');
    // Orphan present and at medium under strict.
    expect(
      report.orphanTrustFindings.some(
        (o) => o.ruleId === 'trust.orphan-entry' && o.severity === 'medium',
      ),
    ).toBe(true);
  });

  test('unsigned-with-unlock: unlock suppresses trust.unsigned (default mode)', () => {
    const dir = setupScenario('unsigned-with-unlock');
    const manifest = upsertUnlock(emptyManifest(), {
      path: 'CLAUDE.md',
      reason: 'wip',
      unlockedAt: '2026-05-25T03:00:00Z',
      unlockedBy: 'tester@example',
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings).toHaveLength(0);
    expect(file?.suppressedTrustFindings).toHaveLength(1);
    expect(report.suppressedByCategory.trust).toBe(1);
  });

  test('unsigned-with-unlock under --strict: unlock is IGNORED → HIGH', () => {
    const dir = setupScenario('unsigned-with-unlock');
    const manifest = upsertUnlock(emptyManifest(), {
      path: 'CLAUDE.md',
      reason: 'wip',
      unlockedAt: '2026-05-25T03:00:00Z',
      unlockedBy: 'tester@example',
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier, strict: true });
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings[0]?.severity).toBe('high');
    expect(file?.suppressedTrustFindings).toHaveLength(0);
  });

  test('orphan-entry: manifest path absent on disk → trust.orphan-entry LOW', () => {
    const dir = setupScenario('orphan-entry');
    const absentHash = hashFileContent(new TextEncoder().encode('phantom'));
    const manifest = upsertTrust(emptyManifest(), {
      path: 'phantom.md',
      hash: absentHash,
      signer: TRUSTED_FP,
      signedAt: '2026-05-25T03:14:00Z',
      signature: stamp(buildSignMessage('phantom.md', absentHash)),
      reason: null,
    }).manifest;
    writeManifestAndAllowed(dir, serializeManifest(manifest), '');

    const report = scanPath(dir, { verifier });
    expect(report.orphanTrustFindings).toHaveLength(1);
    expect(report.orphanTrustFindings[0]?.severity).toBe('low');
    expect(report.highCount).toBe(0);
  });

  test('sentinel-no-manifest: sentinel present, manifest absent → trust.unsigned HIGH per file', () => {
    const dir = setupScenario('sentinel-no-manifest');
    const report = scanPath(dir, { verifier });
    expect(report.trustState).toBe('sentinel-no-manifest');
    const file = report.files.find((f) => f.path === 'CLAUDE.md');
    expect(file?.trustFindings[0]?.ruleId).toBe('trust.unsigned');
    expect(file?.trustFindings[0]?.severity).toBe('high');
    expect(report.highCount).toBeGreaterThan(0);
  });

  test('pre-M5 repo (no manifest, no sentinel) is unaffected by trust layer', () => {
    const dir = setupScenario('signed-clean');
    // No manifest written.
    const report = scanPath(dir, { verifier });
    expect(report.trustState).toBe('not-enforced');
    expect(report.findingCount).toBe(0);
  });

  test('--strict with manifest absent → invocation-error', () => {
    const dir = setupScenario('signed-clean');
    // No manifest written.
    const report = scanPath(dir, { verifier, strict: true });
    expect(report.trustState).toBe('invocation-error');
    expect(report.trustError).toMatch(/--strict requires/);
  });
});
