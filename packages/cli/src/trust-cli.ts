// CLI implementations for `warden trust sign|verify|list|unlock` and
// `warden trust keys list`. Spec: ADR 0012 §4.
//
// All operations are CI-safe (no TTY required, no interactive prompts).
// Successful operations are silent per CLAUDE.md §Style; error messages
// carry inline fix hints.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir, hostname, userInfo } from 'node:os';
import { dirname, relative, resolve } from 'node:path';
import {
  type Manifest,
  type Signer,
  SshSigner,
  SshVerifier,
  type TrustEntry,
  type UnlockEntry,
  type Verifier,
  buildSignMessage,
  emptyManifest,
  findEntryByFingerprint,
  findTrust,
  hashFileContent,
  parseAllowedSigners,
  parseManifest,
  serializeManifest,
  upsertTrust,
  upsertUnlock,
} from '@warden-sh/core';

type Streams = {
  readonly stdout: { write(chunk: string): boolean | unknown; isTTY?: boolean };
  readonly stderr: { write(chunk: string): boolean | unknown };
};

const TRUST_DIR = '.warden/trust';
const MANIFEST_RELATIVE = `${TRUST_DIR}/manifest.toml`;
const ALLOWED_SIGNERS_RELATIVE = `${TRUST_DIR}/allowed_signers`;

function findRepoRoot(start: string): string {
  // Walk up looking for a directory containing either .git or .warden/.
  let cur = resolve(start);
  for (let i = 0; i < 64; i++) {
    if (existsSync(resolve(cur, '.git')) || existsSync(resolve(cur, '.warden'))) return cur;
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  // Fallback to the starting directory; sign/unlock will create
  // .warden/trust/ there.
  return resolve(start);
}

function repoRelative(repoRoot: string, p: string): string {
  const abs = resolve(p);
  const rel = relative(repoRoot, abs);
  return rel.replaceAll('\\', '/');
}

function readFileOrNull(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function readBytesOrNull(path: string): Uint8Array | null {
  try {
    return new Uint8Array(readFileSync(path));
  } catch {
    return null;
  }
}

function loadManifest(repoRoot: string): {
  readonly manifest: Manifest | null;
  readonly error: string | null;
} {
  const path = resolve(repoRoot, MANIFEST_RELATIVE);
  if (!existsSync(path)) return { manifest: null, error: null };
  const text = readFileOrNull(path);
  if (text === null) return { manifest: null, error: `cannot read ${path}` };
  const parsed = parseManifest(text);
  if (parsed.kind === 'error') return { manifest: null, error: parsed.message };
  return { manifest: parsed.manifest, error: null };
}

function writeManifest(repoRoot: string, manifest: Manifest): void {
  const dir = resolve(repoRoot, TRUST_DIR);
  mkdirSync(dir, { recursive: true });
  const path = resolve(repoRoot, MANIFEST_RELATIVE);
  writeFileSync(path, serializeManifest(manifest), { encoding: 'utf8' });
}

function defaultKeyPath(): string | null {
  // Resolution order per ADR 0012 §4.1:
  //   1. `git config user.signingkey` when `gpg.format = ssh`
  //   2. ~/.ssh/id_ed25519
  //   3. ~/.ssh/id_rsa
  const fmt = spawnSync('git', ['config', '--get', 'gpg.format'], { encoding: 'utf8' });
  if (fmt.status === 0 && fmt.stdout.trim() === 'ssh') {
    const sk = spawnSync('git', ['config', '--get', 'user.signingkey'], { encoding: 'utf8' });
    if (sk.status === 0) {
      const path = sk.stdout.trim();
      if (path.length > 0 && existsSync(path)) return path;
    }
  }
  const ed = resolve(homedir(), '.ssh', 'id_ed25519');
  if (existsSync(ed)) return ed;
  const rsa = resolve(homedir(), '.ssh', 'id_rsa');
  if (existsSync(rsa)) return rsa;
  return null;
}

function gitUserEmail(): string {
  const r = spawnSync('git', ['config', '--get', 'user.email'], { encoding: 'utf8' });
  if (r.status === 0) {
    const v = r.stdout.trim();
    if (v.length > 0) return v;
  }
  const info = userInfo({ encoding: 'utf8' });
  return `${info.username}@${hostname()}`;
}

export type TrustCliOptions = {
  readonly cwd?: string;
  readonly signer?: Signer;
  readonly verifier?: Verifier;
  readonly now?: () => Date;
};

// `warden trust sign <path>`
export function trustSign(
  pathArg: string,
  flags: { readonly key?: string; readonly reason?: string },
  streams: Streams,
  opts: TrustCliOptions = {},
): number {
  const cwd = opts.cwd ?? process.cwd();
  const repoRoot = findRepoRoot(cwd);
  const targetAbs = resolve(cwd, pathArg);
  if (!existsSync(targetAbs)) {
    streams.stderr.write(`trust sign: file does not exist: ${pathArg}\n`);
    return 2;
  }
  if (!statSync(targetAbs).isFile()) {
    streams.stderr.write(`trust sign: not a regular file: ${pathArg}\n`);
    return 2;
  }
  const bytes = readBytesOrNull(targetAbs);
  if (bytes === null) {
    streams.stderr.write(`trust sign: cannot read ${pathArg}\n`);
    return 2;
  }
  const relPath = repoRelative(repoRoot, targetAbs);

  let keyPath = flags.key ?? null;
  if (keyPath === null) {
    keyPath = defaultKeyPath();
    if (keyPath === null) {
      streams.stderr.write(
        'trust sign: no SSH key found. Tried: git config user.signingkey (gpg.format=ssh), ~/.ssh/id_ed25519, ~/.ssh/id_rsa\n',
      );
      streams.stderr.write('  generate one with: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519\n');
      return 2;
    }
  } else {
    if (!existsSync(keyPath)) {
      streams.stderr.write(`trust sign: --key path does not exist: ${keyPath}\n`);
      return 2;
    }
  }

  const hash = hashFileContent(bytes);
  const message = buildSignMessage(relPath, hash);
  const signer = opts.signer ?? new SshSigner();
  const result = signer.sign({ message, keyPath });
  if (result.kind === 'error') {
    streams.stderr.write(`trust sign: ${result.message}\n`);
    return 2;
  }

  const { manifest: existing, error: parseError } = loadManifest(repoRoot);
  if (parseError !== null) {
    streams.stderr.write(`trust sign: manifest parse error: ${parseError}\n`);
    return 2;
  }
  const base = existing ?? emptyManifest();

  const now = (opts.now ?? (() => new Date()))();
  const reasonValue =
    typeof flags.reason === 'string' && flags.reason.length > 0 ? flags.reason : null;
  const entry: TrustEntry = {
    path: relPath,
    hash,
    signer: result.signature.signer,
    signedAt: now.toISOString(),
    signature: result.signature.blob,
    reason: reasonValue,
  };

  const { manifest: updated, replaced } = upsertTrust(base, entry);
  if (replaced) {
    streams.stderr.write(`trust sign: replacing existing entry for ${relPath}\n`);
  }
  writeManifest(repoRoot, updated);
  return 0;
}

// `warden trust verify [path]`
export function trustVerify(
  pathArg: string | undefined,
  flags: { readonly allowedSigners?: string; readonly quiet?: true; readonly json?: true },
  streams: Streams,
  opts: TrustCliOptions = {},
): number {
  const cwd = opts.cwd ?? process.cwd();
  const repoRoot = findRepoRoot(cwd);

  const { manifest, error } = loadManifest(repoRoot);
  if (error !== null) {
    streams.stderr.write(`trust verify: ${error}\n`);
    return 2;
  }
  if (manifest === null) {
    streams.stderr.write(`trust verify: ${MANIFEST_RELATIVE} not found at ${repoRoot}\n`);
    return 2;
  }

  const allowedPath = flags.allowedSigners ?? resolve(repoRoot, ALLOWED_SIGNERS_RELATIVE);
  const allowedContent = readFileOrNull(allowedPath);
  if (allowedContent === null) {
    streams.stderr.write(`trust verify: cannot read allowed_signers at ${allowedPath}\n`);
    return 2;
  }
  const parsed = parseAllowedSigners(allowedContent);
  if (parsed.errors.length > 0) {
    const first = parsed.errors[0];
    streams.stderr.write(
      `trust verify: allowed_signers malformed at line ${first?.line ?? '?'}: ${first?.message ?? 'unknown'}\n`,
    );
    return 2;
  }

  const verifier = opts.verifier ?? new SshVerifier();

  type Row = { path: string; status: string; message: string };
  const rows: Row[] = [];
  let entries = manifest.trust;
  if (pathArg !== undefined) {
    const wanted = repoRelative(repoRoot, resolve(cwd, pathArg));
    const single = findTrust(manifest, wanted);
    if (single === null) {
      streams.stderr.write(`trust verify: no manifest entry for ${wanted}\n`);
      return 2;
    }
    entries = [single];
  }

  let anyFail = false;
  for (const entry of entries) {
    const abs = resolve(repoRoot, entry.path);
    const bytes = readBytesOrNull(abs);
    if (bytes === null) {
      rows.push({ path: entry.path, status: 'missing-file', message: 'file is absent on disk' });
      anyFail = true;
      continue;
    }
    const onDisk = hashFileContent(bytes);
    if (onDisk !== entry.hash) {
      rows.push({
        path: entry.path,
        status: 'mismatch',
        message: `on-disk hash ${onDisk} differs from manifest hash ${entry.hash}`,
      });
      anyFail = true;
      continue;
    }
    const principal = findEntryByFingerprint(parsed.entries, entry.signer);
    if (principal === null) {
      rows.push({
        path: entry.path,
        status: 'untrusted-signer',
        message: `signer ${entry.signer} is not in allowed_signers`,
      });
      anyFail = true;
      continue;
    }
    const message = buildSignMessage(entry.path, entry.hash);
    const result = verifier.verify({
      message,
      signatureBlob: entry.signature,
      allowedSignersContent: allowedContent,
      signerFingerprint: entry.signer,
    });
    if (result.kind === 'ok') {
      rows.push({ path: entry.path, status: 'ok', message: '' });
    } else if (result.kind === 'untrusted-signer') {
      rows.push({ path: entry.path, status: 'untrusted-signer', message: result.message });
      anyFail = true;
    } else if (result.kind === 'signature-invalid') {
      rows.push({ path: entry.path, status: 'mismatch', message: result.message });
      anyFail = true;
    } else {
      streams.stderr.write(`trust verify: setup error: ${result.message}\n`);
      return 2;
    }
  }

  if (flags.json === true) {
    const obj = {
      version: 'warden/trust-verify/v1',
      ok: !anyFail,
      results: rows,
    };
    streams.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
  } else if (flags.quiet !== true && rows.length > 0) {
    for (const r of rows) {
      if (r.status !== 'ok') {
        streams.stderr.write(`${r.path}: trust.${r.status} — ${r.message}\n`);
        if (r.status === 'mismatch') {
          streams.stderr.write(`  to re-sign, run: warden trust sign ${r.path}\n`);
        }
      }
    }
  }
  return anyFail ? 1 : 0;
}

// `warden trust list`
export function trustList(
  flags: { readonly json?: true; readonly verify?: true },
  streams: Streams,
  opts: TrustCliOptions = {},
): number {
  const cwd = opts.cwd ?? process.cwd();
  const repoRoot = findRepoRoot(cwd);

  const { manifest, error } = loadManifest(repoRoot);
  if (error !== null) {
    streams.stderr.write(`trust list: ${error}\n`);
    return 2;
  }
  if (manifest === null) {
    streams.stderr.write(`trust list: ${MANIFEST_RELATIVE} not found at ${repoRoot}\n`);
    return 2;
  }

  const verifyMap = new Map<string, string>();
  let verifyAnyFail = false;
  if (flags.verify === true) {
    const allowedPath = resolve(repoRoot, ALLOWED_SIGNERS_RELATIVE);
    const allowedContent = readFileOrNull(allowedPath);
    if (allowedContent === null) {
      streams.stderr.write(`trust list --verify: cannot read ${allowedPath}\n`);
      return 2;
    }
    const verifier = opts.verifier ?? new SshVerifier();
    for (const entry of manifest.trust) {
      const abs = resolve(repoRoot, entry.path);
      const bytes = readBytesOrNull(abs);
      if (bytes === null) {
        verifyMap.set(entry.path, 'missing-file');
        verifyAnyFail = true;
        continue;
      }
      const onDisk = hashFileContent(bytes);
      if (onDisk !== entry.hash) {
        verifyMap.set(entry.path, 'mismatch');
        verifyAnyFail = true;
        continue;
      }
      const message = buildSignMessage(entry.path, entry.hash);
      const result = verifier.verify({
        message,
        signatureBlob: entry.signature,
        allowedSignersContent: allowedContent,
        signerFingerprint: entry.signer,
      });
      if (result.kind === 'ok') verifyMap.set(entry.path, 'ok');
      else if (result.kind === 'untrusted-signer') {
        verifyMap.set(entry.path, 'untrusted-signer');
        verifyAnyFail = true;
      } else if (result.kind === 'signature-invalid') {
        verifyMap.set(entry.path, 'mismatch');
        verifyAnyFail = true;
      } else {
        streams.stderr.write(`trust list --verify: setup error: ${result.message}\n`);
        return 2;
      }
    }
  }

  type Row = {
    path: string;
    hashPrefix: string;
    signerShort: string;
    signedAt: string;
    status?: string;
  };
  const sorted = [...manifest.trust].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  const rows: Row[] = sorted.map((t) => {
    const hashHex = t.hash.replace(/^[^:]+:/, '');
    const hashPrefix = hashHex.slice(0, 12);
    const signerShort = t.signer.slice(0, 24);
    const row: Row = {
      path: t.path,
      hashPrefix,
      signerShort,
      signedAt: t.signedAt,
    };
    if (flags.verify === true) {
      row.status = verifyMap.get(t.path) ?? '?';
    }
    return row;
  });

  if (flags.json === true) {
    const obj = {
      version: 'warden/trust-list/v1',
      entries: rows,
    };
    streams.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
  } else {
    if (rows.length === 0) {
      streams.stdout.write('(no entries)\n');
    } else {
      for (const r of rows) {
        let line = `${r.path}  ${r.hashPrefix}  ${r.signerShort}  ${r.signedAt}`;
        if (r.status !== undefined) line += `  ${r.status}`;
        streams.stdout.write(`${line}\n`);
      }
    }
  }
  return verifyAnyFail ? 1 : 0;
}

// `warden trust unlock <path> --reason <text>`
export function trustUnlock(
  pathArg: string,
  flags: { readonly reason?: string },
  streams: Streams,
  opts: TrustCliOptions = {},
): number {
  const cwd = opts.cwd ?? process.cwd();
  const repoRoot = findRepoRoot(cwd);
  const reason = typeof flags.reason === 'string' ? flags.reason.trim() : '';
  if (reason.length === 0) {
    streams.stderr.write('trust unlock: --reason is required and must be non-empty\n');
    return 2;
  }

  const targetAbs = resolve(cwd, pathArg);
  const relPath = repoRelative(repoRoot, targetAbs);

  const { manifest: existing, error } = loadManifest(repoRoot);
  if (error !== null) {
    streams.stderr.write(`trust unlock: manifest parse error: ${error}\n`);
    return 2;
  }
  const base = existing ?? emptyManifest();
  const now = (opts.now ?? (() => new Date()))();
  const entry: UnlockEntry = {
    path: relPath,
    reason,
    unlockedAt: now.toISOString(),
    unlockedBy: gitUserEmail(),
  };
  const { manifest: updated } = upsertUnlock(base, entry);
  writeManifest(repoRoot, updated);
  return 0;
}

// `warden trust keys list`
export function trustKeysList(
  flags: { readonly json?: true },
  streams: Streams,
  opts: TrustCliOptions = {},
): number {
  const cwd = opts.cwd ?? process.cwd();
  const repoRoot = findRepoRoot(cwd);

  const allowedPath = resolve(repoRoot, ALLOWED_SIGNERS_RELATIVE);
  const repoContent = readFileOrNull(allowedPath);
  const extraPath = resolve(homedir(), '.warden', 'extra_allowed_signers');
  const extraContent = existsSync(extraPath) ? readFileOrNull(extraPath) : null;

  type Row = {
    principal: string;
    keyType: string;
    fingerprint: string;
    comment: string;
    source: 'repo' | 'local';
  };
  const rows: Row[] = [];

  if (repoContent !== null) {
    const parsed = parseAllowedSigners(repoContent, 'repo');
    if (parsed.errors.length > 0) {
      const first = parsed.errors[0];
      streams.stderr.write(
        `trust keys list: ${ALLOWED_SIGNERS_RELATIVE} malformed at line ${first?.line ?? '?'}: ${first?.message ?? 'unknown'}\n`,
      );
      return 2;
    }
    for (const e of parsed.entries) {
      rows.push({
        principal: e.principal,
        keyType: e.keyType,
        fingerprint: e.fingerprint,
        comment: e.comment,
        source: 'repo',
      });
    }
  }
  if (extraContent !== null) {
    const parsed = parseAllowedSigners(extraContent, 'local');
    for (const e of parsed.entries) {
      rows.push({
        principal: e.principal,
        keyType: e.keyType,
        fingerprint: e.fingerprint,
        comment: e.comment,
        source: 'local',
      });
    }
  }

  if (flags.json === true) {
    const obj = { version: 'warden/trust-keys-list/v1', entries: rows };
    streams.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
  } else {
    if (rows.length === 0) {
      streams.stdout.write('(no keys)\n');
    } else {
      for (const r of rows) {
        streams.stdout.write(
          `${r.principal}  ${r.keyType}  ${r.fingerprint}  ${r.comment}  [${r.source}]\n`,
        );
      }
    }
  }
  return 0;
}
