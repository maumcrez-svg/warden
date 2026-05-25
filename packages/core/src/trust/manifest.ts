// Manifest parser/serializer for `.warden/trust/manifest.toml`.
// Schema spec: ADR 0012 §2.
//
// Hand-rolled, intentionally limited to the grammar the spec defines:
//
//   schema = "v1"
//   # optional comments
//   [[trust]]
//   path = "<string>"
//   hash = "<string>"
//   signer = "<string>"
//   signed-at = "<string>"
//   signature = "<string>"
//   reason = "<string>"        # optional
//
//   [[unlock]]
//   path = "<string>"
//   reason = "<string>"
//   unlocked-at = "<string>"
//   unlocked-by = "<string>"
//
// No nested tables, no inline tables, no datetimes, no numbers/bools
// (dates are stored as ISO 8601 strings). Quoted-string values only,
// with `\\` and `\"` escapes.
//
// Serialization invariants (ADR 0012 §2):
// - First line is always `schema = "v1"`.
// - `[[trust]]` blocks are sorted alphabetically by `path`.
// - `[[unlock]]` blocks are sorted alphabetically by `path`.
// - Field order inside each block is fixed.

export const MANIFEST_SCHEMA = 'v1';

export type TrustEntry = {
  readonly path: string;
  readonly hash: string;
  readonly signer: string;
  readonly signedAt: string;
  readonly signature: string;
  readonly reason: string | null;
};

export type UnlockEntry = {
  readonly path: string;
  readonly reason: string;
  readonly unlockedAt: string;
  readonly unlockedBy: string;
};

export type Manifest = {
  readonly schema: 'v1';
  readonly trust: ReadonlyArray<TrustEntry>;
  readonly unlock: ReadonlyArray<UnlockEntry>;
};

export type ManifestParseResult =
  | { readonly kind: 'ok'; readonly manifest: Manifest }
  | { readonly kind: 'error'; readonly message: string };

function unescapeString(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    if (ch === '\\' && i + 1 < s.length) {
      const next = s[i + 1] as string;
      if (next === '\\') {
        out += '\\';
        i++;
        continue;
      }
      if (next === '"') {
        out += '"';
        i++;
        continue;
      }
      if (next === 'n') {
        out += '\n';
        i++;
        continue;
      }
      if (next === 't') {
        out += '\t';
        i++;
        continue;
      }
    }
    out += ch;
  }
  return out;
}

function escapeString(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function parseKeyValue(line: string): { key: string; value: string } | null {
  const eq = line.indexOf('=');
  if (eq === -1) return null;
  const key = line.slice(0, eq).trim();
  const rest = line.slice(eq + 1).trim();
  // Strip trailing comments outside the string.
  if (!rest.startsWith('"')) return null;
  // Find closing quote, accounting for escapes.
  let i = 1;
  while (i < rest.length) {
    const ch = rest[i];
    if (ch === '\\' && i + 1 < rest.length) {
      i += 2;
      continue;
    }
    if (ch === '"') break;
    i++;
  }
  if (i >= rest.length) return null;
  const value = unescapeString(rest.slice(1, i));
  return { key, value };
}

type BlockKind = 'trust' | 'unlock';

type RawBlock = {
  readonly kind: BlockKind;
  readonly line: number;
  readonly fields: Map<string, string>;
};

export function parseManifest(content: string): ManifestParseResult {
  const lines = content.split('\n');
  let schemaSeen = false;
  let topLevelDone = false;
  let currentBlock: RawBlock | null = null;
  const blocks: RawBlock[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    const trimmed = raw.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    if (trimmed === '[[trust]]') {
      currentBlock = { kind: 'trust', line: i + 1, fields: new Map() };
      blocks.push(currentBlock);
      topLevelDone = true;
      continue;
    }
    if (trimmed === '[[unlock]]') {
      currentBlock = { kind: 'unlock', line: i + 1, fields: new Map() };
      blocks.push(currentBlock);
      topLevelDone = true;
      continue;
    }
    if (trimmed.startsWith('[')) {
      return {
        kind: 'error',
        message: `unexpected block header at line ${i + 1}: ${trimmed}`,
      };
    }

    const kv = parseKeyValue(trimmed);
    if (kv === null) {
      return { kind: 'error', message: `malformed line at line ${i + 1}: ${trimmed}` };
    }
    if (!topLevelDone && currentBlock === null) {
      if (kv.key === 'schema') {
        if (kv.value !== MANIFEST_SCHEMA) {
          return {
            kind: 'error',
            message: `unsupported schema "${kv.value}"; this Warden expects "${MANIFEST_SCHEMA}"`,
          };
        }
        schemaSeen = true;
      } else {
        return {
          kind: 'error',
          message: `expected schema declaration before any block at line ${i + 1}`,
        };
      }
      continue;
    }
    if (currentBlock === null) {
      return {
        kind: 'error',
        message: `key/value outside of block at line ${i + 1}`,
      };
    }
    if (currentBlock.fields.has(kv.key)) {
      return {
        kind: 'error',
        message: `duplicate field "${kv.key}" in block at line ${currentBlock.line}`,
      };
    }
    currentBlock.fields.set(kv.key, kv.value);
  }

  if (!schemaSeen) {
    return { kind: 'error', message: 'manifest is missing required `schema = "v1"` declaration' };
  }

  const trust: TrustEntry[] = [];
  const unlock: UnlockEntry[] = [];
  for (const b of blocks) {
    if (b.kind === 'trust') {
      const required = ['path', 'hash', 'signer', 'signed-at', 'signature'];
      for (const field of required) {
        if (!b.fields.has(field)) {
          return {
            kind: 'error',
            message: `[[trust]] block at line ${b.line} is missing required field "${field}"`,
          };
        }
      }
      trust.push({
        path: b.fields.get('path') as string,
        hash: b.fields.get('hash') as string,
        signer: b.fields.get('signer') as string,
        signedAt: b.fields.get('signed-at') as string,
        signature: b.fields.get('signature') as string,
        reason: b.fields.get('reason') ?? null,
      });
    } else {
      const required = ['path', 'reason', 'unlocked-at', 'unlocked-by'];
      for (const field of required) {
        if (!b.fields.has(field)) {
          return {
            kind: 'error',
            message: `[[unlock]] block at line ${b.line} is missing required field "${field}"`,
          };
        }
      }
      unlock.push({
        path: b.fields.get('path') as string,
        reason: b.fields.get('reason') as string,
        unlockedAt: b.fields.get('unlocked-at') as string,
        unlockedBy: b.fields.get('unlocked-by') as string,
      });
    }
  }

  return { kind: 'ok', manifest: { schema: 'v1', trust, unlock } };
}

function emitField(key: string, value: string): string {
  return `${key} = "${escapeString(value)}"\n`;
}

export function serializeManifest(manifest: Manifest): string {
  const trustSorted = [...manifest.trust].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  const unlockSorted = [...manifest.unlock].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );

  let out = `schema = "${MANIFEST_SCHEMA}"\n`;
  for (const t of trustSorted) {
    out += '\n[[trust]]\n';
    out += emitField('path', t.path);
    out += emitField('hash', t.hash);
    out += emitField('signer', t.signer);
    out += emitField('signed-at', t.signedAt);
    out += emitField('signature', t.signature);
    if (t.reason !== null) out += emitField('reason', t.reason);
  }
  for (const u of unlockSorted) {
    out += '\n[[unlock]]\n';
    out += emitField('path', u.path);
    out += emitField('reason', u.reason);
    out += emitField('unlocked-at', u.unlockedAt);
    out += emitField('unlocked-by', u.unlockedBy);
  }
  return out;
}

export function emptyManifest(): Manifest {
  return { schema: 'v1', trust: [], unlock: [] };
}

export function upsertTrust(
  manifest: Manifest,
  entry: TrustEntry,
): {
  readonly manifest: Manifest;
  readonly replaced: boolean;
} {
  const others = manifest.trust.filter((t) => t.path !== entry.path);
  const replaced = others.length !== manifest.trust.length;
  return {
    manifest: { ...manifest, trust: [...others, entry] },
    replaced,
  };
}

export function upsertUnlock(
  manifest: Manifest,
  entry: UnlockEntry,
): {
  readonly manifest: Manifest;
  readonly replaced: boolean;
} {
  const others = manifest.unlock.filter((u) => u.path !== entry.path);
  const replaced = others.length !== manifest.unlock.length;
  return {
    manifest: { ...manifest, unlock: [...others, entry] },
    replaced,
  };
}

export function findTrust(manifest: Manifest, path: string): TrustEntry | null {
  for (const t of manifest.trust) if (t.path === path) return t;
  return null;
}

export function findUnlock(manifest: Manifest, path: string): UnlockEntry | null {
  for (const u of manifest.unlock) if (u.path === path) return u;
  return null;
}
