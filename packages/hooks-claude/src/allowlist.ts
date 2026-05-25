// Allowlist parser for `.warden/hooks/allow.toml`. Spec: ADR 0013 §6.
//
// Mirrors the minimal TOML grammar that
// packages/core/src/trust/manifest.ts already validates against — same
// schema = "v1" front line, same quoted-string-only values, no nested
// tables, no inline tables. Diverges only in the block name
// (`[[allow]]` instead of `[[trust]]`) and the optional `command-pattern`
// field.

export const ALLOWLIST_SCHEMA = 'v1';

export type AllowEntry = {
  // Rule ID the entry applies to (e.g. `hooks.credential-file-read`).
  readonly rule: string;
  // Path glob (`**`, `*`, `?` semantics matching credentials.ts) the
  // allowance is scoped to. `null` when the entry uses
  // `command-pattern` instead.
  readonly path: string | null;
  // Regex pattern (JS syntax) matched against the full shell command
  // for Bash tool calls. `null` when the entry uses `path` instead.
  readonly commandPattern: string | null;
  readonly reason: string;
};

export type Allowlist = {
  readonly schema: 'v1';
  readonly entries: ReadonlyArray<AllowEntry>;
};

export type AllowlistParseResult =
  | { readonly kind: 'ok'; readonly allowlist: Allowlist }
  | { readonly kind: 'error'; readonly message: string; readonly line: number };

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

function parseKeyValue(line: string): { key: string; value: string } | null {
  const eq = line.indexOf('=');
  if (eq === -1) return null;
  const key = line.slice(0, eq).trim();
  const rest = line.slice(eq + 1).trim();
  if (!rest.startsWith('"')) return null;
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
  return { key, value: unescapeString(rest.slice(1, i)) };
}

type RawBlock = {
  readonly line: number;
  readonly fields: Map<string, string>;
};

export function parseAllowlist(content: string): AllowlistParseResult {
  const lines = content.split('\n');
  let schemaSeen = false;
  let topLevelDone = false;
  let currentBlock: RawBlock | null = null;
  const blocks: RawBlock[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i] as string;
    const trimmed = raw.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;

    if (trimmed === '[[allow]]') {
      currentBlock = { line: i + 1, fields: new Map() };
      blocks.push(currentBlock);
      topLevelDone = true;
      continue;
    }
    if (trimmed.startsWith('[')) {
      return {
        kind: 'error',
        message: `unexpected block header: ${trimmed}`,
        line: i + 1,
      };
    }

    const kv = parseKeyValue(trimmed);
    if (kv === null) {
      return { kind: 'error', message: `malformed line: ${trimmed}`, line: i + 1 };
    }
    if (!topLevelDone && currentBlock === null) {
      if (kv.key === 'schema') {
        if (kv.value !== ALLOWLIST_SCHEMA) {
          return {
            kind: 'error',
            message: `unsupported schema "${kv.value}"; this Warden expects "${ALLOWLIST_SCHEMA}"`,
            line: i + 1,
          };
        }
        schemaSeen = true;
      } else {
        return {
          kind: 'error',
          message: 'expected `schema = "v1"` before any [[allow]] block',
          line: i + 1,
        };
      }
      continue;
    }
    if (currentBlock === null) {
      return { kind: 'error', message: `key/value outside of block: ${trimmed}`, line: i + 1 };
    }
    if (currentBlock.fields.has(kv.key)) {
      return {
        kind: 'error',
        message: `duplicate field "${kv.key}" in block at line ${currentBlock.line}`,
        line: i + 1,
      };
    }
    currentBlock.fields.set(kv.key, kv.value);
  }

  if (!schemaSeen) {
    return {
      kind: 'error',
      message: 'allow.toml is missing required `schema = "v1"` declaration',
      line: 1,
    };
  }

  const entries: AllowEntry[] = [];
  for (const b of blocks) {
    const rule = b.fields.get('rule');
    const path = b.fields.get('path') ?? null;
    const commandPattern = b.fields.get('command-pattern') ?? null;
    const reason = b.fields.get('reason');

    if (typeof rule !== 'string' || rule.length === 0) {
      return {
        kind: 'error',
        message: '[[allow]] block requires `rule = "<rule-id>"`',
        line: b.line,
      };
    }
    if (path === null && commandPattern === null) {
      return {
        kind: 'error',
        message: '[[allow]] block requires `path` or `command-pattern`',
        line: b.line,
      };
    }
    if (path !== null && commandPattern !== null) {
      return {
        kind: 'error',
        message: '[[allow]] block accepts at most one of `path` / `command-pattern`',
        line: b.line,
      };
    }
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      return {
        kind: 'error',
        message: '[[allow]] block requires `reason = "<non-empty text>"`',
        line: b.line,
      };
    }
    if (commandPattern !== null) {
      // Validate the regex compiles. A bad regex blocks the
      // allowlist from loading rather than silently disabling the
      // entry — fail loudly per CLAUDE.md §Style.
      try {
        new RegExp(commandPattern);
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        return {
          kind: 'error',
          message: `invalid command-pattern regex: ${msg}`,
          line: b.line,
        };
      }
    }
    entries.push({ rule, path, commandPattern, reason });
  }

  return { kind: 'ok', allowlist: { schema: 'v1', entries } };
}

export function emptyAllowlist(): Allowlist {
  return { schema: 'v1', entries: [] };
}
