// Integration test exercising the real ssh-keygen subprocess path.
// Skipped when ssh-keygen is unavailable on PATH — keeps the suite
// runnable in stripped-down CI environments without OpenSSH.
//
// ADR 0012 §"Acceptance criteria": "MockSigner unit tests cover the
// Signer/Verifier interface; CI fixture tests exercise the real
// ssh-keygen subprocess path."

import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  SshSigner,
  SshVerifier,
  buildSignMessage,
  fingerprintFromKeyData,
  hashFileContent,
} from '../src/trust/index.ts';

function hasSshKeygen(): boolean {
  const r = spawnSync('ssh-keygen', ['-h'], { encoding: 'utf8' });
  // `-h` is unknown to ssh-keygen but returns status 1 with usage on stderr;
  // ENOENT comes back via the `error` field.
  return r.error === undefined;
}

const skip = !hasSshKeygen();

describe.skipIf(skip)('SshSigner + SshVerifier round-trip', () => {
  test('signs and verifies an ed25519 keypair', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-ssh-rt-'));
    try {
      const keyPath = join(dir, 'id_ed25519');
      const gen = spawnSync(
        'ssh-keygen',
        ['-t', 'ed25519', '-N', '', '-f', keyPath, '-C', 'warden-test'],
        { encoding: 'utf8' },
      );
      expect(gen.status).toBe(0);

      const pub = readFileSync(`${keyPath}.pub`, 'utf8').trim().split(/\s+/);
      const keyData = pub[1] as string;
      const fingerprint = fingerprintFromKeyData(keyData);
      expect(fingerprint).not.toBeNull();
      if (fingerprint === null) return;

      const allowedSigners = `tester@example namespaces="warden" ssh-ed25519 ${keyData} warden-test\n`;
      writeFileSync(join(dir, 'allowed_signers'), allowedSigners);

      const fileContent = new TextEncoder().encode('hello, warden\n');
      const hash = hashFileContent(fileContent);
      const message = buildSignMessage('CLAUDE.md', hash);
      const signer = new SshSigner();
      const sign = signer.sign({ message, keyPath });
      expect(sign.kind).toBe('ok');
      if (sign.kind !== 'ok') return;
      expect(sign.signature.signer).toBe(fingerprint);

      const verifier = new SshVerifier();
      const verify = verifier.verify({
        message,
        signatureBlob: sign.signature.blob,
        allowedSignersContent: allowedSigners,
        signerFingerprint: sign.signature.signer,
      });
      expect(verify.kind).toBe('ok');
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    }
  });

  test('tampering with the message fails verification', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-ssh-rt-'));
    try {
      const keyPath = join(dir, 'id_ed25519');
      const gen = spawnSync(
        'ssh-keygen',
        ['-t', 'ed25519', '-N', '', '-f', keyPath, '-C', 'warden-test'],
        { encoding: 'utf8' },
      );
      expect(gen.status).toBe(0);
      const pub = readFileSync(`${keyPath}.pub`, 'utf8').trim().split(/\s+/);
      const keyData = pub[1] as string;
      const allowedSigners = `tester@example namespaces="warden" ssh-ed25519 ${keyData}\n`;

      const original = new TextEncoder().encode('hello\n');
      const tampered = new TextEncoder().encode('hellp\n');
      const signMsg = buildSignMessage('a.md', hashFileContent(original));
      const verifyMsg = buildSignMessage('a.md', hashFileContent(tampered));

      const signer = new SshSigner();
      const sign = signer.sign({ message: signMsg, keyPath });
      expect(sign.kind).toBe('ok');
      if (sign.kind !== 'ok') return;

      const verifier = new SshVerifier();
      const verify = verifier.verify({
        message: verifyMsg,
        signatureBlob: sign.signature.blob,
        allowedSignersContent: allowedSigners,
        signerFingerprint: sign.signature.signer,
      });
      expect(verify.kind).toBe('signature-invalid');
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    }
  });

  test('signature by untrusted key reports untrusted-signer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'warden-ssh-rt-'));
    try {
      const keyA = join(dir, 'a');
      const keyB = join(dir, 'b');
      spawnSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', keyA, '-C', 'a'], {
        encoding: 'utf8',
      });
      spawnSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-f', keyB, '-C', 'b'], {
        encoding: 'utf8',
      });
      const pubB = readFileSync(`${keyB}.pub`, 'utf8').trim().split(/\s+/);
      // allowed_signers contains only B; we'll sign with A.
      const allowedSigners = `b@example namespaces="warden" ssh-ed25519 ${pubB[1]}\n`;

      const content = new TextEncoder().encode('hi\n');
      const message = buildSignMessage('a.md', hashFileContent(content));
      const signer = new SshSigner();
      const sign = signer.sign({ message, keyPath: keyA });
      expect(sign.kind).toBe('ok');
      if (sign.kind !== 'ok') return;

      const verifier = new SshVerifier();
      const verify = verifier.verify({
        message,
        signatureBlob: sign.signature.blob,
        allowedSignersContent: allowedSigners,
        signerFingerprint: sign.signature.signer,
      });
      expect(verify.kind).toBe('untrusted-signer');
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    }
  });
});
