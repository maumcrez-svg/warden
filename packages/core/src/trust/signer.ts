// Signer / Verifier abstractions. Spec: ADR 0012 §8.
//
// One concrete implementation (`SshSigner`/`SshVerifier`) shells out to
// `ssh-keygen -Y sign|verify`. A `MockSigner`/`MockVerifier` lives in
// tests/ for unit-test seams. The interfaces exist *only* for that
// seam — not as a multi-scheme abstraction. Adding a second scheme
// (Sigstore, minisign) would revisit the contract.
//
// Cold-path: this module spawns subprocesses. It is explicitly NOT
// part of the scanner hot path (`docs/ARCHITECTURE.md` §4). It is
// invoked from `warden trust sign|verify` and from `scan-trust.ts`
// when trust is enforced.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { fingerprintFromKeyData, parseAllowedSigners } from './allowed-signers.ts';
import { SSH_SIGN_NAMESPACE } from './sign-message.ts';

export type Signature = {
  // Base64 of the sshsig blob with PEM armor stripped (ADR 0012 §2).
  readonly blob: string;
  // Fingerprint of the public key that signed.
  readonly signer: string;
};

export type SignResult =
  | { readonly kind: 'ok'; readonly signature: Signature }
  | { readonly kind: 'error'; readonly message: string };

export type VerifyOk = { readonly kind: 'ok' };
export type VerifyFail =
  | { readonly kind: 'signature-invalid'; readonly message: string }
  | { readonly kind: 'untrusted-signer'; readonly message: string }
  | { readonly kind: 'setup-error'; readonly message: string };
export type VerifyResult = VerifyOk | VerifyFail;

export type SignParams = {
  readonly message: Uint8Array;
  readonly keyPath: string;
};

export type VerifyParams = {
  readonly message: Uint8Array;
  readonly signatureBlob: string;
  readonly allowedSignersContent: string;
  readonly signerFingerprint: string;
};

export interface Signer {
  sign(params: SignParams): SignResult;
}

export interface Verifier {
  verify(params: VerifyParams): VerifyResult;
}

const SSHSIG_BEGIN = '-----BEGIN SSH SIGNATURE-----';
const SSHSIG_END = '-----END SSH SIGNATURE-----';

function armorSignature(blob: string): string {
  // ssh-keygen accepts a single-line base64 between BEGIN/END, but
  // canonical output wraps at 70 chars. Either is parsed.
  const wrapped = blob.replace(/(.{70})/g, '$1\n').trimEnd();
  return `${SSHSIG_BEGIN}\n${wrapped}\n${SSHSIG_END}\n`;
}

function stripArmor(armored: string): string | null {
  const begin = armored.indexOf(SSHSIG_BEGIN);
  const end = armored.indexOf(SSHSIG_END);
  if (begin === -1 || end === -1 || end <= begin) return null;
  const body = armored.slice(begin + SSHSIG_BEGIN.length, end);
  return body.replace(/\s+/g, '');
}

function readPubKey(keyPath: string): string | null {
  // Public keys live next to the private key as `<path>.pub`. The
  // file contains a single line: `<keytype> <base64> <comment>`.
  try {
    return readFileSync(`${keyPath}.pub`, 'utf8');
  } catch {
    return null;
  }
}

function fingerprintOfKeyPair(keyPath: string): string | null {
  const pub = readPubKey(keyPath);
  if (pub === null) return null;
  const parts = pub.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const keyData = parts[1] as string;
  return fingerprintFromKeyData(keyData);
}

export class SshSigner implements Signer {
  sign(params: SignParams): SignResult {
    const fp = fingerprintOfKeyPair(params.keyPath);
    if (fp === null) {
      return {
        kind: 'error',
        message: `cannot read public key at ${params.keyPath}.pub`,
      };
    }
    const tmp = mkdtempSync(join(tmpdir(), 'warden-sign-'));
    const msgPath = join(tmp, 'message');
    try {
      writeFileSync(msgPath, params.message);
      const result = spawnSync(
        'ssh-keygen',
        ['-Y', 'sign', '-n', SSH_SIGN_NAMESPACE, '-f', params.keyPath, msgPath],
        { encoding: 'utf8' },
      );
      if (result.error !== undefined) {
        return { kind: 'error', message: `ssh-keygen not invokable: ${result.error.message}` };
      }
      if (result.status !== 0) {
        return {
          kind: 'error',
          message: `ssh-keygen sign failed (exit ${result.status}): ${result.stderr.trim()}`,
        };
      }
      let armored: string;
      try {
        armored = readFileSync(`${msgPath}.sig`, 'utf8');
      } catch (err) {
        return {
          kind: 'error',
          message: `ssh-keygen did not produce signature file: ${(err as Error).message}`,
        };
      }
      const blob = stripArmor(armored);
      if (blob === null) {
        return { kind: 'error', message: 'ssh-keygen produced malformed signature armor' };
      }
      return { kind: 'ok', signature: { blob, signer: fp } };
    } finally {
      try {
        rmSync(tmp, { recursive: true, force: true });
      } catch {
        // best-effort tmp cleanup
      }
    }
  }
}

export class SshVerifier implements Verifier {
  verify(params: VerifyParams): VerifyResult {
    const parsed = parseAllowedSigners(params.allowedSignersContent);
    if (parsed.errors.length > 0) {
      const first = parsed.errors[0];
      const msg = first !== undefined ? first.message : 'unknown';
      return {
        kind: 'setup-error',
        message: `allowed_signers malformed: ${msg}`,
      };
    }
    const principal = parsed.entries.find(
      (e) =>
        e.fingerprint === params.signerFingerprint &&
        (e.namespaces.length === 0 || e.namespaces.includes(SSH_SIGN_NAMESPACE)),
    );
    if (principal === undefined) {
      return {
        kind: 'untrusted-signer',
        message: `no allowed_signers entry matches fingerprint ${params.signerFingerprint}`,
      };
    }

    const tmp = mkdtempSync(join(tmpdir(), 'warden-verify-'));
    const msgPath = join(tmp, 'message');
    const sigPath = join(tmp, 'message.sig');
    const allowedPath = join(tmp, 'allowed_signers');
    try {
      writeFileSync(msgPath, params.message);
      writeFileSync(sigPath, armorSignature(params.signatureBlob));
      writeFileSync(allowedPath, params.allowedSignersContent);
      const result = spawnSync(
        'ssh-keygen',
        [
          '-Y',
          'verify',
          '-f',
          allowedPath,
          '-I',
          principal.principal,
          '-n',
          SSH_SIGN_NAMESPACE,
          '-s',
          sigPath,
        ],
        { input: params.message, encoding: 'utf8' },
      );
      if (result.error !== undefined) {
        return {
          kind: 'setup-error',
          message: `ssh-keygen not invokable: ${result.error.message}`,
        };
      }
      if (result.status === 0) return { kind: 'ok' };
      return {
        kind: 'signature-invalid',
        message: `ssh-keygen verify failed (exit ${result.status}): ${result.stderr.trim()}`,
      };
    } finally {
      try {
        rmSync(tmp, { recursive: true, force: true });
      } catch {
        // best-effort tmp cleanup
      }
    }
  }
}

// A MockSigner produces deterministic fixtures without invoking
// ssh-keygen. Pair with MockVerifier to round-trip in unit tests.
export class MockSigner implements Signer {
  constructor(
    private readonly opts: {
      readonly fingerprint: string;
      readonly stamp: (message: Uint8Array) => string;
    },
  ) {}
  sign(params: SignParams): SignResult {
    const blob = this.opts.stamp(params.message);
    return { kind: 'ok', signature: { blob, signer: this.opts.fingerprint } };
  }
}

export class MockVerifier implements Verifier {
  constructor(
    private readonly opts: {
      readonly trustedFingerprints: ReadonlyArray<string>;
      readonly stamp: (message: Uint8Array) => string;
    },
  ) {}
  verify(params: VerifyParams): VerifyResult {
    if (!this.opts.trustedFingerprints.includes(params.signerFingerprint)) {
      return {
        kind: 'untrusted-signer',
        message: `mock verifier: ${params.signerFingerprint} not in trusted set`,
      };
    }
    const expected = this.opts.stamp(params.message);
    if (expected !== params.signatureBlob) {
      return { kind: 'signature-invalid', message: 'mock verifier: stamp mismatch' };
    }
    return { kind: 'ok' };
  }
}
