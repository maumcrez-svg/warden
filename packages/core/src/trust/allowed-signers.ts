// Parser for the OpenSSH `allowed_signers` file format used by
// `ssh-keygen -Y verify`. Each non-blank, non-comment line is:
//
//   <principal> [option=value ...] <keytype> <base64-keydata> [comment...]
//
// We only consume what M5 needs: principal, options (`namespaces=...`),
// keytype, keydata, comment. Fingerprint (`SHA256:<base64>`) is
// computed from the binary keydata so verify can find the principal
// for a stored manifest entry without a `ssh-keygen` round-trip.
//
// Reference: ssh-keygen(1) ALLOWED SIGNERS section (OpenSSH 8.0+).

import { sha256 } from '@noble/hashes/sha2.js';

export type AllowedSignerEntry = {
  readonly principal: string;
  readonly namespaces: ReadonlyArray<string>;
  readonly keyType: string;
  readonly keyData: string;
  readonly comment: string;
  readonly fingerprint: string;
  readonly source: 'repo' | 'local';
  readonly lineNumber: number;
};

export type ParseError = { readonly line: number; readonly message: string };

export type AllowedSignersParseResult = {
  readonly entries: ReadonlyArray<AllowedSignerEntry>;
  readonly errors: ReadonlyArray<ParseError>;
};

function base64Decode(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  } catch {
    return null;
  }
}

function base64Encode(buf: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i] as number);
  return btoa(bin);
}

export function fingerprintFromKeyData(keyData: string): string | null {
  const decoded = base64Decode(keyData);
  if (decoded === null) return null;
  const digest = sha256(decoded);
  // SHA256 fingerprints are base64-encoded, padding stripped — matches
  // `ssh-keygen -lf <key>` output format.
  return `SHA256:${base64Encode(digest).replace(/=+$/, '')}`;
}

// Tokenize a single allowed_signers line. Quoted values with double
// quotes are honored for the options field (which is what holds
// `namespaces="..."` in practice). Backslash-escapes inside quotes are
// minimal: `\\` and `\"`.
function tokenize(line: string): ReadonlyArray<string> {
  const out: string[] = [];
  let i = 0;
  while (i < line.length) {
    while (i < line.length && (line[i] === ' ' || line[i] === '\t')) i++;
    if (i >= line.length) break;
    let token = '';
    let inQuotes = false;
    while (i < line.length) {
      const ch = line[i] as string;
      if (inQuotes) {
        if (ch === '\\' && i + 1 < line.length) {
          const next = line[i + 1] as string;
          token += next;
          i += 2;
          continue;
        }
        if (ch === '"') {
          inQuotes = false;
          token += ch;
          i++;
          continue;
        }
        token += ch;
        i++;
        continue;
      }
      if (ch === '"') {
        inQuotes = true;
        token += ch;
        i++;
        continue;
      }
      if (ch === ' ' || ch === '\t') break;
      token += ch;
      i++;
    }
    out.push(token);
  }
  return out;
}

function stripQuotes(value: string): string {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return value;
}

function parseOptions(token: string): {
  readonly namespaces: ReadonlyArray<string>;
} {
  const eq = token.indexOf('=');
  if (eq === -1) return { namespaces: [] };
  const key = token.slice(0, eq).toLowerCase();
  if (key !== 'namespaces') return { namespaces: [] };
  const raw = stripQuotes(token.slice(eq + 1));
  return {
    namespaces: raw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  };
}

const KEY_TYPES = new Set([
  'ssh-rsa',
  'ssh-dss',
  'ssh-ed25519',
  'ssh-ed25519-cert-v01@openssh.com',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'sk-ssh-ed25519@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com',
]);

export function parseAllowedSigners(
  content: string,
  source: 'repo' | 'local' = 'repo',
): AllowedSignersParseResult {
  const entries: AllowedSignerEntry[] = [];
  const errors: ParseError[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] as string;
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;

    const tokens = tokenize(line);
    if (tokens.length < 3) {
      errors.push({ line: i + 1, message: 'too few tokens for allowed_signers entry' });
      continue;
    }
    const principal = tokens[0] as string;

    // Tokens 1..N may include options like `namespaces="..."`, followed
    // by the keytype and keydata, then optional comment.
    let cursor = 1;
    let namespaces: ReadonlyArray<string> = [];
    while (cursor < tokens.length) {
      const t = tokens[cursor] as string;
      if (KEY_TYPES.has(t)) break;
      const opt = parseOptions(t);
      if (opt.namespaces.length > 0) namespaces = opt.namespaces;
      cursor += 1;
    }
    if (cursor >= tokens.length - 1) {
      errors.push({ line: i + 1, message: 'missing keytype or keydata' });
      continue;
    }
    const keyType = tokens[cursor] as string;
    const keyData = tokens[cursor + 1] as string;
    const comment = tokens.slice(cursor + 2).join(' ');

    const fp = fingerprintFromKeyData(keyData);
    if (fp === null) {
      errors.push({ line: i + 1, message: 'invalid base64 keydata' });
      continue;
    }
    entries.push({
      principal,
      namespaces,
      keyType,
      keyData,
      comment,
      fingerprint: fp,
      source,
      lineNumber: i + 1,
    });
  }
  return { entries, errors };
}

export function findEntryByFingerprint(
  entries: ReadonlyArray<AllowedSignerEntry>,
  fingerprint: string,
): AllowedSignerEntry | null {
  for (const e of entries) {
    if (e.fingerprint === fingerprint) return e;
  }
  return null;
}
