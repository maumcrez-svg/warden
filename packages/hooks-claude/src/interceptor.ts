// PreToolUse interceptor for Claude Code. Spec: ADR 0013 §§2-4.
//
// Pure function over a (parsed JSON input, allowlist, $HOME, $cwd)
// tuple. No filesystem I/O; the CLI shim in index.ts wires up the
// real I/O surface around this.

import {
  CREDENTIAL_RULES,
  type ToolCallView,
  pathMatchesCredentialBlocklist,
} from '@warden-sh/rules';
import type { AllowEntry, Allowlist } from './allowlist.ts';

// JSON shape Claude Code sends on stdin for the PreToolUse hook event,
// per https://docs.anthropic.com/en/docs/claude-code/hooks (verified
// 2026-05-25). Fields we don't read are typed as `unknown` so a future
// agent version that grows the schema doesn't break the parser.
export type ClaudeToolUseInput = {
  readonly tool_name?: string;
  readonly tool_input?: {
    readonly file_path?: string;
    readonly command?: string;
    readonly content?: string;
    readonly [k: string]: unknown;
  };
  readonly session_id?: string;
  readonly transcript_path?: string;
  readonly [k: string]: unknown;
};

export type Decision =
  | { readonly kind: 'allow' }
  | {
      readonly kind: 'deny';
      readonly ruleId: string;
      readonly reason: string;
    }
  | {
      // Issued when the input is missing fields the hook needs to
      // classify the call. The runtime treats this as 'allow' (a
      // cooperative hook does not strand the developer on a schema
      // mismatch) but tests assert on the distinction.
      readonly kind: 'skip';
      readonly why: string;
    };

function normalizeTool(name: string | undefined): ToolCallView['tool'] {
  if (typeof name !== 'string') return 'other';
  const lower = name.toLowerCase();
  if (lower === 'read') return 'read';
  if (lower === 'edit' || lower === 'multiedit') return 'edit';
  if (lower === 'write') return 'write';
  if (lower === 'bash') return 'bash';
  return 'other';
}

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return `${home}/${p.slice(2)}`;
  return p;
}

function canonicalizePath(raw: string, home: string, cwd: string): string {
  const expanded = expandHome(raw, home);
  // Normalize Windows path separators upstream so the glob matcher
  // sees a POSIX path.
  const slashy = expanded.replaceAll('\\', '/');
  if (slashy.startsWith('/')) return slashy;
  // Drive letter (Windows). Treat as already absolute after the slash
  // normalization.
  if (/^[a-zA-Z]:\//.test(slashy)) return slashy;
  // Relative paths get resolved against the cwd. We avoid `path.resolve`
  // so this module stays I/O-free and self-contained — `cwd` and `home`
  // are passed in by callers and tests.
  const cwdSlashy = cwd.replaceAll('\\', '/');
  const prefix = cwdSlashy.endsWith('/') ? cwdSlashy : `${cwdSlashy}/`;
  return `${prefix}${slashy}`;
}

function tokenizeCommand(command: string, home: string, cwd: string): string[] {
  // Tokenizer covers the cases this rule pack needs:
  //   - Whitespace splits.
  //   - Pipes / redirections / `&&` / `||` / `;` act as separators
  //     (treated as whitespace).
  //   - Quoted strings ("..." and '...') preserve internal whitespace.
  // We expand `~` per token after splitting. This is not a full POSIX
  // shell tokenizer — variable interpolation, command substitution,
  // and brace expansion are out of scope (a command using them to
  // hide a credential path is a known false-negative; documented).
  const tokens: string[] = [];
  let buf = '';
  let quote: '"' | "'" | null = null;
  const flush = (): void => {
    if (buf.length > 0) {
      tokens.push(buf);
      buf = '';
    }
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i] as string;
    if (quote !== null) {
      if (ch === quote) {
        quote = null;
        continue;
      }
      buf += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (
      ch === ' ' ||
      ch === '\t' ||
      ch === '\n' ||
      ch === '|' ||
      ch === '&' ||
      ch === ';' ||
      ch === '<' ||
      ch === '>'
    ) {
      flush();
      continue;
    }
    buf += ch;
  }
  flush();
  // After tokenization, expand `~` and absolutize relative paths so
  // the rule pack's glob matcher sees the same shape it sees on the
  // Read/Edit/Write side.
  return tokens.map((t) => {
    // Only paths and shell verbs are interesting; we don't want to
    // mistake a flag like `-rsa` for a path. Skip absolutization for
    // tokens starting with `-` (flag) or that don't look like paths.
    if (t.startsWith('-')) return t;
    if (t.startsWith('~') || t.startsWith('/') || t.startsWith('./') || t.startsWith('../')) {
      return canonicalizePath(t, home, cwd);
    }
    return t;
  });
}

function buildView(input: ClaudeToolUseInput, home: string, cwd: string): ToolCallView | null {
  const tool = normalizeTool(input.tool_name);
  const ti = input.tool_input;
  if (ti === undefined || ti === null || typeof ti !== 'object') return null;

  if (tool === 'read' || tool === 'edit' || tool === 'write') {
    const raw = ti.file_path;
    if (typeof raw !== 'string' || raw.length === 0) return null;
    return {
      tool,
      raw,
      absPath: canonicalizePath(raw, home, cwd),
      commandTokens: [],
    };
  }
  if (tool === 'bash') {
    const raw = ti.command;
    if (typeof raw !== 'string' || raw.length === 0) return null;
    return {
      tool,
      raw,
      absPath: '',
      commandTokens: tokenizeCommand(raw, home, cwd),
    };
  }
  return {
    tool: 'other',
    raw: '',
    absPath: '',
    commandTokens: [],
  };
}

function matchAllowEntry(
  entry: AllowEntry,
  call: ToolCallView,
  home: string,
  cwd: string,
): boolean {
  if (entry.path !== null) {
    if (call.tool !== 'read' && call.tool !== 'edit' && call.tool !== 'write') return false;
    const target = canonicalizePath(entry.path, home, cwd);
    if (target === call.absPath) return true;
    // Glob-style allow: the entry's `path` is treated as a glob with
    // the same semantics as credentials.ts.
    return matchGlob(target, call.absPath);
  }
  if (entry.commandPattern !== null) {
    if (call.tool !== 'bash') return false;
    try {
      return new RegExp(entry.commandPattern).test(call.raw);
    } catch {
      return false;
    }
  }
  return false;
}

// Local copy of the credentials.ts glob matcher — kept inline so this
// module does not reach into rules internals, and so the allowlist
// matcher uses byte-identical semantics to the rule pack matcher.
function matchGlob(pattern: string, path: string): boolean {
  let regex = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === '*' && pattern[i + 1] === '*' && pattern[i + 2] === '/') {
      regex += '(?:.*/)?';
      i += 2;
      continue;
    }
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        regex += '.*';
        i++;
      } else {
        regex += '[^/]*';
      }
      continue;
    }
    if (ch === '?') {
      regex += '[^/]';
      continue;
    }
    if (/[\\.+^$(){}|[\]]/.test(ch)) {
      regex += `\\${ch}`;
      continue;
    }
    regex += ch;
  }
  regex += '$';
  return new RegExp(regex).test(path);
}

export type EvaluateContext = {
  readonly home: string;
  readonly cwd: string;
  readonly allowlist: Allowlist;
};

export function evaluateToolCall(input: ClaudeToolUseInput, ctx: EvaluateContext): Decision {
  const view = buildView(input, ctx.home, ctx.cwd);
  if (view === null) {
    return { kind: 'skip', why: 'tool_input missing required fields' };
  }
  if (view.tool === 'other') {
    return { kind: 'allow' };
  }

  for (const rule of CREDENTIAL_RULES) {
    const hits = rule.evaluate(view);
    if (hits.length === 0) continue;
    // Allowlist short-circuit. Per ADR 0013 §6, an allow entry matches
    // when its rule ID equals the firing rule AND its path/command
    // pattern matches the call. Both halves must match.
    const allowed = ctx.allowlist.entries.some(
      (entry) => entry.rule === rule.id && matchAllowEntry(entry, view, ctx.home, ctx.cwd),
    );
    if (allowed) continue;
    const firstHit = hits[0] as { readonly evidence: string };
    return {
      kind: 'deny',
      ruleId: rule.id,
      reason: `${rule.name}: ${firstHit.evidence}`,
    };
  }
  return { kind: 'allow' };
}

// Convenience: parse the credential-blocklist check without going
// through evaluateToolCall. Used by callers (CLI scan output, future
// adapters) that want to surface the path-only decision.
export { pathMatchesCredentialBlocklist };
