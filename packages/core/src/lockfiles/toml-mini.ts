// Minimal TOML reader. Spec: just enough to parse the M9 lockfile
// shapes (Cargo.lock, poetry.lock, uv.lock) and the manifests they
// depend on (pyproject.toml, Cargo.toml) for direct-vs-transitive
// detection.
//
// This is intentionally NOT a complete TOML implementation. ADR 0016
// §2 commits to no new external deps. The lockfile shapes we target
// use a constrained subset:
//
//   - top-level `key = value` pairs
//   - `[section.dotted.path]` tables
//   - `[[section]]` array-of-tables
//   - string values (basic "..." and literal '...')
//   - integer values
//   - array values [...] (possibly multi-line)
//   - inline tables { k = v, ... } on a single line
//   - `#` line comments
//
// What it does NOT handle (none of our target files need these):
//   - multi-line strings ("""..."""")
//   - escape sequences beyond \\, \", \n, \t
//   - dates / times / floats
//   - heterogeneous arrays
//
// Pure functions; no I/O.

export type TomlValue =
  | string
  | number
  | boolean
  | ReadonlyArray<TomlValue>
  | { readonly [k: string]: TomlValue };

export type TomlTable = { readonly [k: string]: TomlValue };

export type TomlParseResult =
  | { readonly kind: 'ok'; readonly root: TomlTable }
  | { readonly kind: 'error'; readonly message: string; readonly line: number };

// Walk the input and assemble a tree. The walker is line-oriented but
// arrays/inline tables can span continuations within a single "logical"
// line (we glue continuation lines that follow an unclosed `[` or `{`).
export function parseTomlMini(input: string): TomlParseResult {
  const rawLines = input.split(/\r?\n/);
  const logicalLines = collapseContinuations(rawLines);

  const root: Record<string, TomlValue> = {};
  // Active table where bare `key = value` lines land. Starts at root.
  let current: Record<string, TomlValue> = root;

  for (const ll of logicalLines) {
    const trimmed = ll.text.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('[[') && trimmed.endsWith(']]')) {
      const path = trimmed.slice(2, -2).trim();
      const tableArr = ensureArrayOfTables(root, path, ll.line);
      if (typeof tableArr === 'string') return { kind: 'error', message: tableArr, line: ll.line };
      const fresh: Record<string, TomlValue> = {};
      tableArr.push(fresh);
      current = fresh;
      continue;
    }

    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const path = trimmed.slice(1, -1).trim();
      const tbl = ensureTable(root, path, ll.line);
      if (typeof tbl === 'string') return { kind: 'error', message: tbl, line: ll.line };
      current = tbl;
      continue;
    }

    // key = value
    const eq = findTopLevelEquals(trimmed);
    if (eq === -1) {
      return { kind: 'error', message: `expected key = value, got: ${trimmed}`, line: ll.line };
    }
    const key = trimmed.slice(0, eq).trim();
    const rawValue = trimmed.slice(eq + 1).trim();
    const valueResult = parseValue(rawValue);
    if (valueResult.kind === 'error') {
      return { kind: 'error', message: valueResult.message, line: ll.line };
    }
    current[key] = valueResult.value;
  }

  return { kind: 'ok', root };
}

type LogicalLine = { readonly text: string; readonly line: number };

// Glue continuation lines for unclosed `[` / `{` brackets. TOML spec
// permits arrays and inline tables to span lines (arrays officially,
// inline tables in newer revisions of the spec — we accept it). The
// walker tracks bracket depth and joins until balanced.
function collapseContinuations(lines: ReadonlyArray<string>): ReadonlyArray<LogicalLine> {
  const out: LogicalLine[] = [];
  let buf = '';
  let bufStartLine = 1;
  let depth = 0;
  let inString: '"' | "'" | null = null;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i] ?? '';
    if (buf === '') {
      bufStartLine = i + 1;
    } else {
      // Preserve a separating space — array elements rely on it.
      buf += ' ';
    }
    for (let k = 0; k < ln.length; k++) {
      const ch = ln[k];
      if (inString !== null) {
        if (ch === '\\' && inString === '"') {
          // Skip next char (escape).
          buf += ch;
          k++;
          const nx = ln[k];
          if (nx !== undefined) buf += nx;
          continue;
        }
        if (ch === inString) inString = null;
        buf += ch;
        continue;
      }
      if (ch === '#' && depth === 0) {
        // Rest of line is a comment.
        break;
      }
      if (ch === '"' || ch === "'") {
        inString = ch;
        buf += ch;
        continue;
      }
      if (ch === '[' || ch === '{') depth++;
      else if (ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      buf += ch;
    }
    if (depth === 0 && inString === null) {
      out.push({ text: buf, line: bufStartLine });
      buf = '';
    }
  }
  if (buf.trim() !== '') {
    out.push({ text: buf, line: bufStartLine });
  }
  return out;
}

function splitDottedPath(path: string): ReadonlyArray<string> {
  // Bare dotted keys: simplest case. We don't honor quoted dotted keys
  // (none of our lockfiles use them).
  return path.split('.').map((s) => s.trim());
}

function ensureTable(
  root: Record<string, TomlValue>,
  path: string,
  _line: number,
): Record<string, TomlValue> | string {
  const parts = splitDottedPath(path);
  let cur: Record<string, TomlValue> = root;
  for (let i = 0; i < parts.length; i++) {
    const key = parts[i] ?? '';
    const next = cur[key];
    if (next === undefined) {
      const tbl: Record<string, TomlValue> = {};
      cur[key] = tbl;
      cur = tbl;
    } else if (typeof next === 'object' && !Array.isArray(next)) {
      cur = next as Record<string, TomlValue>;
    } else if (Array.isArray(next)) {
      const last = next[next.length - 1];
      if (typeof last === 'object' && last !== null && !Array.isArray(last)) {
        cur = last as Record<string, TomlValue>;
      } else {
        return `cannot redefine "${parts.slice(0, i + 1).join('.')}" as a table`;
      }
    } else {
      return `cannot redefine "${parts.slice(0, i + 1).join('.')}" as a table`;
    }
  }
  return cur;
}

function ensureArrayOfTables(
  root: Record<string, TomlValue>,
  path: string,
  line: number,
): TomlValue[] | string {
  const parts = splitDottedPath(path);
  const leaf = parts[parts.length - 1];
  if (leaf === undefined) return 'empty array-of-tables path';
  const parent = parts.length > 1 ? ensureTable(root, parts.slice(0, -1).join('.'), line) : root;
  if (typeof parent === 'string') return parent;
  const existing = parent[leaf];
  if (existing === undefined) {
    const arr: TomlValue[] = [];
    parent[leaf] = arr;
    return arr;
  }
  if (Array.isArray(existing)) {
    return existing as TomlValue[];
  }
  return `cannot redefine "${path}" as array-of-tables`;
}

// Find the first top-level `=` (not inside a string).
function findTopLevelEquals(s: string): number {
  let inString: '"' | "'" | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inString !== null) {
      if (ch === '\\' && inString === '"') {
        i++;
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = ch;
      continue;
    }
    if (ch === '=') return i;
  }
  return -1;
}

type ParseValueResult =
  | { readonly kind: 'ok'; readonly value: TomlValue }
  | { readonly kind: 'error'; readonly message: string };

function parseValue(raw: string): ParseValueResult {
  const trimmed = raw.trim();
  if (trimmed === '') return { kind: 'error', message: 'empty value' };

  // String literals.
  if (trimmed.startsWith('"')) return parseBasicString(trimmed);
  if (trimmed.startsWith("'")) return parseLiteralString(trimmed);

  // Boolean.
  if (trimmed === 'true') return { kind: 'ok', value: true };
  if (trimmed === 'false') return { kind: 'ok', value: false };

  // Array.
  if (trimmed.startsWith('[')) return parseArray(trimmed);

  // Inline table.
  if (trimmed.startsWith('{')) return parseInlineTable(trimmed);

  // Integer (signed, no underscores in our use cases).
  if (/^-?\d+$/.test(trimmed)) {
    const n = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(n)) return { kind: 'error', message: `cannot parse number "${trimmed}"` };
    return { kind: 'ok', value: n };
  }

  return { kind: 'error', message: `unsupported value: ${trimmed}` };
}

function parseBasicString(input: string): ParseValueResult {
  if (!input.endsWith('"')) return { kind: 'error', message: 'unterminated string' };
  const body = input.slice(1, -1);
  // Minimal escape handling.
  const unescaped = body
    .replaceAll('\\"', '"')
    .replaceAll('\\\\', '\\')
    .replaceAll('\\n', '\n')
    .replaceAll('\\t', '\t');
  return { kind: 'ok', value: unescaped };
}

function parseLiteralString(input: string): ParseValueResult {
  if (!input.endsWith("'")) return { kind: 'error', message: 'unterminated literal string' };
  return { kind: 'ok', value: input.slice(1, -1) };
}

// Split a bracketed body on top-level commas (not inside nested
// strings/arrays/inline tables).
function splitTopLevel(body: string): ReadonlyArray<string> {
  const out: string[] = [];
  let depth = 0;
  let inString: '"' | "'" | null = null;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (inString !== null) {
      if (ch === '\\' && inString === '"') {
        i++;
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = ch;
      continue;
    }
    if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) {
      out.push(body.slice(start, i));
      start = i + 1;
    }
  }
  const tail = body.slice(start);
  if (tail.trim() !== '') out.push(tail);
  return out;
}

function parseArray(input: string): ParseValueResult {
  if (!input.endsWith(']')) return { kind: 'error', message: 'unterminated array' };
  const body = input.slice(1, -1);
  const parts = splitTopLevel(body);
  const out: TomlValue[] = [];
  for (const p of parts) {
    const v = parseValue(p);
    if (v.kind === 'error') return v;
    out.push(v.value);
  }
  return { kind: 'ok', value: out };
}

function parseInlineTable(input: string): ParseValueResult {
  if (!input.endsWith('}')) return { kind: 'error', message: 'unterminated inline table' };
  const body = input.slice(1, -1);
  const parts = splitTopLevel(body);
  const out: Record<string, TomlValue> = {};
  for (const p of parts) {
    const eq = findTopLevelEquals(p);
    if (eq === -1) {
      return { kind: 'error', message: `inline table key without "=": ${p.trim()}` };
    }
    const k = p.slice(0, eq).trim();
    const rawV = p.slice(eq + 1).trim();
    const v = parseValue(rawV);
    if (v.kind === 'error') return v;
    out[k] = v.value;
  }
  return { kind: 'ok', value: out };
}

// Convenience accessors used by the lockfile parsers. Keep them
// permissive — invalid shapes return undefined rather than throwing,
// since lockfiles can be partially malformed without it being our job
// to reject the whole file.

export function tomlString(v: TomlValue | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

export function tomlArray(v: TomlValue | undefined): ReadonlyArray<TomlValue> | undefined {
  return Array.isArray(v) ? v : undefined;
}

export function tomlTable(v: TomlValue | undefined): TomlTable | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'object') return undefined;
  if (Array.isArray(v)) return undefined;
  return v as TomlTable;
}
