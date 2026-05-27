// Inline "payload-fixture" marker parser. Spec: docs/DECISIONS/0010-payload-fixture-marker-convention.md.
//
// A marker is one line in a file's header zone (leading comment block,
// optionally after a shebang) that declares the file legitimately contains
// attack-shaped content. The scanner reports findings normally, then
// suppresses (without dropping) findings that match the marker's declared
// families and scope. Cross-category findings still fire — that is the
// product property M3.1 ships.
//
// Grammar (strict ASCII): SENTINEL " payload-fixture " <family>
//   [" " <family>...] [" scope:file" | " scope:lines:N-M"] " -- " <reason>
//
// The authoritative grammar with the literal sentinel inlined lives in
// ADR 0010 §2. The sentinel string is built at module load from two
// fragments (see SENTINEL below) so no // comment line in this parser
// source matches the in-header detection when dogfood scans marker.ts
// — that would self-trigger and require an exception. Malformed
// markers are scan errors (exit 2), not warnings. See ADR 0010 §6.

export type FindingCategory = 'unicode' | 'prompt-injection' | 'mcp' | 'supply-chain';

export type MarkerFamily =
  | 'trapdoor-unicode'
  | 'prompt-injection-pattern'
  | 'mcp-config'
  | 'supply-chain-fixture'
  | 'rules-data'
  | 'detector-test';

export type MarkerScope =
  | { readonly kind: 'file' }
  | { readonly kind: 'lines'; readonly start: number; readonly end: number };

export type Marker = {
  readonly directive: 'payload-fixture';
  readonly families: ReadonlyArray<MarkerFamily>;
  readonly scope: MarkerScope;
  readonly reason: string;
  readonly line: number;
};

export type MarkerParseResult =
  | { readonly kind: 'none' }
  | { readonly kind: 'ok'; readonly marker: Marker }
  | { readonly kind: 'error'; readonly message: string };

// Each family declares which finding categories it suppresses. The wildcard
// '*' means "all current and future categories" — used by broad-scope role
// families that act as trust escalations for whole files. Narrow families
// list only the categories whose payloads are expected.
const FAMILY_CATEGORIES: Readonly<Record<MarkerFamily, ReadonlyArray<FindingCategory | '*'>>> = {
  'trapdoor-unicode': ['unicode'],
  'prompt-injection-pattern': ['prompt-injection'],
  'mcp-config': ['mcp'],
  'supply-chain-fixture': ['supply-chain'],
  'rules-data': ['*'],
  'detector-test': ['*'],
};

// Path restrictions for broad-scope families — enforced before any
// suppression takes effect. A broad-scope marker outside its allowed
// directory is a hard parse error, never silently honored. The
// `display` string is the human-readable form used in error messages
// (the regex's escaped backslashes hurt readability for reviewers).
const PATH_RESTRICTIONS: Readonly<
  Partial<Record<MarkerFamily, { readonly regex: RegExp; readonly display: string }>>
> = {
  'rules-data': {
    regex: /^packages\/rules\/src\/data\//,
    display: 'packages/rules/src/data/**',
  },
  'detector-test': {
    regex: /^packages\/[^/]+\/tests\//,
    display: 'packages/*/tests/**',
  },
  // ADR 0016 §7 — supply-chain fixtures live exclusively under
  // tests/fixtures/supply-chain/. A marker of this family outside that
  // directory is a hard parse error (exit 2), mirroring the broad-scope
  // families above. The family suppresses only `supply-chain` findings
  // (not unicode/PI/MCP/trust), so cross-category collateral scanning
  // (ARCHITECTURE.md §7) still fires inside marked lockfiles.
  'supply-chain-fixture': {
    regex: /^tests\/fixtures\/supply-chain\//,
    display: 'tests/fixtures/supply-chain/**',
  },
};

const KNOWN_FAMILIES = new Set<string>(Object.keys(FAMILY_CATEGORIES));

// Two-fragment construction so the literal sentinel never appears in a
// single token in marker.ts source — see the file header comment for why
// this matters during dogfood.
const SENTINEL = `${'w'}arden:`;

type CommentSyntax = {
  readonly extractMarker: (rawLine: string) => string | null;
  readonly isCommentLine: (rawLine: string) => boolean;
  // Returns true when the parser should skip warden-token detection on this
  // line because of file-format context (e.g. inside a markdown fenced code
  // block, where marker examples in documentation legitimately appear).
  readonly inSkipContext: (state: SkipState, rawLine: string) => boolean;
  // Mutates state in place to track fence open/close transitions before
  // each line is examined.
  readonly updateSkipState: (state: SkipState, rawLine: string) => void;
};

// Mutable scratch passed through the per-line scan. Each file scan owns one.
type SkipState = {
  inFence: boolean;
};

const TS_SYNTAX: CommentSyntax = {
  isCommentLine: (s) => /^\s*\/\//.test(s) || /^\s*\/\*/.test(s) || /^\s*\*/.test(s),
  extractMarker: (s) => {
    const m = s.match(/^\s*\/\/\s*(.*)$/);
    return m === null ? null : (m[1] ?? '').trimEnd();
  },
  inSkipContext: () => false,
  updateSkipState: () => undefined,
};

const MD_FENCE = /^\s*(```|~~~)/;

const MD_SYNTAX: CommentSyntax = {
  isCommentLine: (s) => /^\s*<!--/.test(s),
  extractMarker: (s) => {
    const m = s.match(/^\s*<!--\s*(.*?)\s*-->\s*$/);
    return m === null ? null : (m[1] ?? '').trimEnd();
  },
  // While inside a fenced code block we ignore warden: tokens — those are
  // documentation showing what a marker looks like, not real markers.
  // Out-of-header detection still fires on stray markers OUTSIDE fences.
  inSkipContext: (state) => state.inFence,
  updateSkipState: (state, line) => {
    if (MD_FENCE.test(line)) {
      state.inFence = !state.inFence;
    }
  },
};

function syntaxFor(filePath: string): CommentSyntax | null {
  const lower = filePath.toLowerCase();
  if (/\.(ts|tsx|js|mjs|cjs)$/.test(lower)) return TS_SYNTAX;
  if (/\.(md|mdc|markdown)$/.test(lower)) return MD_SYNTAX;
  return null;
}

function isJsonFile(filePath: string): boolean {
  return /\.json$/i.test(filePath);
}

function isTomlFile(filePath: string): boolean {
  // Cargo.lock + uv.lock + poetry.lock + *.toml. Lockfiles use the
  // `.lock` extension but are TOML-formatted; matching on extension
  // alone would miss them. Both file shapes are covered by the
  // TOML marker rules (top-level `_warden` string).
  return /\.toml$/i.test(filePath) || /\.lock$/i.test(filePath);
}

// JSON marker path per ADR 0011 §6: a top-level `_warden` string
// property carries the marker. The value's content is the same grammar
// as the line-comment marker, starting at the SENTINEL.
// TOML marker path per ADR 0016 §7 reuses the same key name; the
// extraction grammar differs but the suppression contract is identical.
const JSON_MARKER_KEY = '_warden';

// TOML marker grammar (ADR 0016 §7): the FIRST non-comment,
// non-whitespace line must be a top-level `_warden = "<marker>"`
// assignment. Anything later in the document is ignored. This is the
// hardening property that prevents an attacker who can append to a
// lockfile (e.g. a malicious PR that adds a transitive dep) from
// planting a suppression — they would have to also displace the first
// non-comment line, which is a far more visible diff.
//
// We intentionally do NOT pull in a TOML parser dependency. The marker
// is a single fixed-shape top-level key; a hand-written tokenizer is
// ~40 lines and keeps the dep count for `packages/core` under the
// CLAUDE.md target.
const TOML_MARKER_RE = /^\s*_warden\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')\s*(?:#.*)?$/;

function unquoteTomlString(quoted: string): string | null {
  if (quoted.length < 2) return null;
  const open = quoted[0];
  const close = quoted[quoted.length - 1];
  if (open !== close) return null;
  const body = quoted.slice(1, -1);
  if (open === "'") {
    // TOML literal strings: no escape processing.
    return body;
  }
  if (open === '"') {
    // Basic strings: minimal escape handling (the only forms we expect
    // in a marker value are `\n`, `\t`, `\\`, `\"`). Anything more
    // exotic is a malformed marker — we surface the offending raw
    // string and let the grammar parser reject it.
    return body
      .replaceAll('\\"', '"')
      .replaceAll('\\\\', '\\')
      .replaceAll('\\n', '\n')
      .replaceAll('\\t', '\t');
  }
  return null;
}

function parseTomlMarker(filePath: string, content: string): MarkerParseResult {
  const normalizedPath = filePath.replaceAll('\\', '/');
  const lines = content.split(/\r?\n/);
  const totalLines = lines.length;

  // Walk lines until we find the first non-comment, non-blank line.
  // If that line is a `_warden = "<marker>"` assignment, parse it.
  // Otherwise: no marker (TOML markers are header-zone-only by design).
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('#')) continue;
    const m = TOML_MARKER_RE.exec(line);
    if (m === null) {
      // First non-blank non-comment line is not a _warden assignment;
      // no marker in this file. (A `_warden` further down is ignored
      // by design — see ADR 0016 §7.)
      return { kind: 'none' };
    }
    const quoted = m[1] ?? '';
    const unquoted = unquoteTomlString(quoted);
    if (unquoted === null) {
      return {
        kind: 'error',
        message: `${normalizedPath}:${i + 1}: malformed _warden string literal`,
      };
    }
    if (!unquoted.startsWith(SENTINEL)) {
      return {
        kind: 'error',
        message: `${normalizedPath}:${i + 1}: "_warden" value must start with the warden marker sentinel`,
      };
    }
    return parseGrammar(normalizedPath, i + 1, unquoted, totalLines);
  }
  return { kind: 'none' };
}

function parseJsonMarker(filePath: string, content: string): MarkerParseResult {
  const normalizedPath = filePath.replaceAll('\\', '/');
  const totalLines = content.split(/\r?\n/).length;

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    // JSON parse errors are surfaced by scanMcp itself as a finding;
    // the marker parser stays quiet (no marker found) so we don't
    // double-report invalid JSON as a marker error.
    return { kind: 'none' };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { kind: 'none' };
  }

  const raw = (parsed as Record<string, unknown>)[JSON_MARKER_KEY];
  if (raw === undefined) return { kind: 'none' };
  if (typeof raw !== 'string') {
    return {
      kind: 'error',
      message: `${normalizedPath}: "${JSON_MARKER_KEY}" must be a JSON string (ADR 0011 §6)`,
    };
  }
  if (!raw.startsWith(SENTINEL)) {
    return {
      kind: 'error',
      message: `${normalizedPath}: "${JSON_MARKER_KEY}" value must start with the warden marker sentinel`,
    };
  }

  // Locate the `_warden` key line for diagnostic messages. Best-effort:
  // first physical line whose content contains the literal key in quotes.
  // The grammar parser appends its own filepath:line prefix, so passing
  // an approximate line is acceptable; this is reviewer ergonomics, not
  // correctness.
  const lines = content.split(/\r?\n/);
  let keyLine = 1;
  const needle = `"${JSON_MARKER_KEY}"`;
  for (let i = 0; i < lines.length; i++) {
    if ((lines[i] ?? '').includes(needle)) {
      keyLine = i + 1;
      break;
    }
  }

  return parseGrammar(normalizedPath, keyLine, raw, totalLines);
}

export function parseMarker(filePath: string, content: string): MarkerParseResult {
  if (isJsonFile(filePath)) return parseJsonMarker(filePath, content);
  if (isTomlFile(filePath)) return parseTomlMarker(filePath, content);

  const syntax = syntaxFor(filePath);
  if (syntax === null) return { kind: 'none' };

  const lines = content.split(/\r?\n/);
  const totalLines = lines.length;
  const normalizedPath = filePath.replaceAll('\\', '/');

  // Header zone walk: optional shebang on line 1, then blank + comment
  // lines until the first non-blank, non-comment line.
  let inHeader = true;
  let markerInHeader: { readonly line: number; readonly content: string } | null = null;
  const markersOutsideHeader: number[] = [];
  const skipState: SkipState = { inFence: false };

  let startIdx = 0;
  const firstLine = lines[0];
  if (firstLine?.startsWith('#!') === true) startIdx = 1;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    const isBlank = trimmed === '';

    // File-format context tracking (e.g. markdown fenced code blocks).
    // Done BEFORE the warden: detection so a fence-open line itself is
    // treated as in-fence for purposes of skipping its own content.
    const wasInSkip = syntax.inSkipContext(skipState, line);
    syntax.updateSkipState(skipState, line);
    const isInSkip = wasInSkip || syntax.inSkipContext(skipState, line);

    const isComment = !isBlank && syntax.isCommentLine(line);

    if (!isBlank && !isComment && !isInSkip) {
      inHeader = false;
    }

    if (isInSkip) continue;

    // A marker is recognized only when it satisfies the strict full-line
    // comment shape for the file's syntax (// ... for TS, <!-- ... --> for
    // MD). Documentation that mentions "warden:" inside an inline code
    // span or a line-wrapped quote does not match the shape and is
    // ignored. A full-line marker outside the header zone IS caught.
    if (isComment) {
      const extracted = syntax.extractMarker(line);
      if (extracted?.startsWith(SENTINEL) === true) {
        if (inHeader) {
          if (markerInHeader !== null) {
            return {
              kind: 'error',
              message: `${normalizedPath}:${i + 1}: multiple warden markers in header zone (first at line ${markerInHeader.line})`,
            };
          }
          markerInHeader = { line: i + 1, content: extracted };
        } else {
          markersOutsideHeader.push(i + 1);
        }
      }
    }
  }

  if (markersOutsideHeader.length > 0) {
    const first = markersOutsideHeader[0];
    return {
      kind: 'error',
      message: `${normalizedPath}:${first}: warden marker outside header zone (must appear in leading comment block before any code/content)`,
    };
  }

  if (markerInHeader === null) return { kind: 'none' };

  return parseGrammar(normalizedPath, markerInHeader.line, markerInHeader.content, totalLines);
}

function parseGrammar(
  normalizedPath: string,
  line: number,
  raw: string,
  totalLines: number,
): MarkerParseResult {
  const err = (msg: string): MarkerParseResult => ({
    kind: 'error',
    message: `${normalizedPath}:${line}: ${msg}`,
  });

  if (!raw.startsWith(SENTINEL)) return err('not a payload-fixture marker');
  const body = raw.slice(SENTINEL.length).trim();

  // Split on the literal " -- " ASCII separator. Em-dash is not accepted
  // (ADR 0010 §2).
  const splitIdx = body.indexOf(' -- ');
  if (splitIdx === -1) {
    return err(
      'marker is missing reason (expected " -- <reason>" with ASCII double hyphen-minus and single spaces around it)',
    );
  }

  const head = body.slice(0, splitIdx).trim();
  const reason = body.slice(splitIdx + 4).trim();

  if (reason === '') return err('marker reason is empty');

  if (head === '') return err('marker is empty (expected at least a directive)');

  const tokens = head.split(/\s+/);
  const directive = tokens[0];

  if (directive !== 'payload-fixture') {
    return err(`unknown directive "${directive ?? ''}" (expected "payload-fixture")`);
  }

  const families: MarkerFamily[] = [];
  let scope: MarkerScope = { kind: 'file' };
  let scopeSeen = false;

  for (let i = 1; i < tokens.length; i++) {
    const t = tokens[i] ?? '';
    if (t.startsWith('scope:')) {
      if (scopeSeen) return err('multiple scope tokens');
      scopeSeen = true;
      const sval = t.slice('scope:'.length);
      if (sval === 'file') {
        scope = { kind: 'file' };
      } else if (sval.startsWith('lines:')) {
        const range = sval.slice('lines:'.length);
        const m = range.match(/^(\d+)-(\d+)$/);
        if (m === null) {
          return err(`malformed scope "${t}" (expected "scope:lines:N-M" with positive integers)`);
        }
        const start = Number.parseInt(m[1] ?? '0', 10);
        const end = Number.parseInt(m[2] ?? '0', 10);
        if (start < 1) return err(`scope start ${start} must be >= 1`);
        if (start > end) return err(`scope start ${start} must be <= end ${end}`);
        if (end > totalLines) {
          return err(
            `scope end ${end} exceeds file length (${totalLines} lines) — marker is stale or malformed`,
          );
        }
        scope = { kind: 'lines', start, end };
      } else {
        return err(`unknown scope "${t}" (expected "scope:file" or "scope:lines:N-M")`);
      }
    } else {
      if (!KNOWN_FAMILIES.has(t)) {
        return err(`unknown family "${t}" (known: ${[...KNOWN_FAMILIES].sort().join(', ')})`);
      }
      families.push(t as MarkerFamily);
    }
  }

  if (families.length === 0) return err('marker declares no families');

  for (const fam of families) {
    const restriction = PATH_RESTRICTIONS[fam];
    if (restriction !== undefined && !restriction.regex.test(normalizedPath)) {
      return err(
        `broad-scope family "${fam}" requires file under ${restriction.display} (got "${normalizedPath}") -- see ADR 0010 §3`,
      );
    }
  }

  return {
    kind: 'ok',
    marker: { directive: 'payload-fixture', families, scope, reason, line },
  };
}

export function suppressedCategoriesOf(marker: Marker): ReadonlySet<FindingCategory | '*'> {
  const out = new Set<FindingCategory | '*'>();
  for (const fam of marker.families) {
    for (const cat of FAMILY_CATEGORIES[fam]) {
      out.add(cat);
    }
  }
  return out;
}

export function markerCoversCategory(marker: Marker, category: FindingCategory): boolean {
  const cats = suppressedCategoriesOf(marker);
  return cats.has('*') || cats.has(category);
}

// Byte-offset → 1-based line number table. Built once per file so per-finding
// translation is amortized log(N).
function buildLineStartsBytes(content: string): number[] {
  const starts: number[] = [0];
  let bytePos = 0;
  for (let i = 0; i < content.length; i++) {
    const code = content.charCodeAt(i);
    let advance: number;
    if (code < 0x80) advance = 1;
    else if (code < 0x800) advance = 2;
    else if (code >= 0xd800 && code <= 0xdbff) advance = 4;
    else if (code >= 0xdc00 && code <= 0xdfff) advance = 0;
    else advance = 3;
    bytePos += advance;
    if (code === 0x0a) starts.push(bytePos);
  }
  return starts;
}

function byteOffsetToLine(byteOffset: number, lineStartsBytes: ReadonlyArray<number>): number {
  let lo = 0;
  let hi = lineStartsBytes.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    const startAtMid = lineStartsBytes[mid] ?? 0;
    if (startAtMid <= byteOffset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export type ApplyMarkerResult<F> = {
  readonly kept: ReadonlyArray<F>;
  readonly suppressed: ReadonlyArray<F>;
};

export function applyMarker<F extends { readonly byteOffset: number }>(
  marker: Marker | null,
  category: FindingCategory,
  findings: ReadonlyArray<F>,
  content: string,
): ApplyMarkerResult<F> {
  if (marker === null || !markerCoversCategory(marker, category)) {
    return { kept: findings, suppressed: [] };
  }

  if (marker.scope.kind === 'file') {
    return { kept: [], suppressed: findings };
  }

  const lineStarts = buildLineStartsBytes(content);
  const kept: F[] = [];
  const suppressed: F[] = [];
  const { start, end } = marker.scope;
  for (const f of findings) {
    const line = byteOffsetToLine(f.byteOffset, lineStarts);
    if (line >= start && line <= end) suppressed.push(f);
    else kept.push(f);
  }
  return { kept, suppressed };
}
