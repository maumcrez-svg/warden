// Cursor 1.7+ hook interceptor. Spec: ADR 0014 §§2-5.
//
// Pure function over a parsed Cursor hook input and an injected context
// (home, cwd, allowlist). No I/O. The CLI shim in run.ts wires the real
// I/O surface around this.
//
// Cursor's hook contract differs from Claude's PreToolUse in three
// places we care about (ADR 0014 §3):
//   1. Operation-specific fields live at the top level (file_path,
//      command), not nested under tool_input.
//   2. The event is named via hook_event_name, not tool_name.
//   3. beforeReadFile carries the file `content` — Warden ignores it
//      (the rule pack is path-based and content is potentially large).
//
// Decision shape (ADR 0014 §4) is Cursor-specific: top-level
// {"permission":"allow"|"deny","agent_message":"...","user_message":"..."}.
// The translation lives in run.ts, not here — the interceptor returns
// the same vendor-neutral Decision the M6 adapter does.

import type { AllowEntry, Allowlist } from '@warden-sh/hooks-claude';
import { CREDENTIAL_RULES, type ToolCallView } from '@warden-sh/rules';

// JSON shapes Cursor sends on stdin per
// https://cursor.com/docs/hooks (verified 2026-05-25). We only model
// the fields we read; everything else is `unknown` so a future Cursor
// version that grows the schema doesn't break the parser.

export type CursorHookInputBase = {
  readonly hook_event_name?: string;
  readonly conversation_id?: string;
  readonly generation_id?: string;
  readonly model?: string;
  readonly cursor_version?: string;
  readonly workspace_roots?: ReadonlyArray<string>;
  readonly user_email?: string | null;
  readonly transcript_path?: string | null;
  readonly [k: string]: unknown;
};

export type CursorBeforeReadFileInput = CursorHookInputBase & {
  readonly file_path?: string;
  // content is intentionally not modeled — we discard it without parsing.
};

export type CursorBeforeShellExecutionInput = CursorHookInputBase & {
  readonly command?: string;
  readonly cwd?: string;
  readonly sandbox?: boolean;
};

export type CursorBeforeMCPExecutionInput = CursorHookInputBase & {
  readonly tool_name?: string;
  readonly tool_input?: string;
};

export type CursorHookInput =
  | CursorBeforeReadFileInput
  | CursorBeforeShellExecutionInput
  | CursorBeforeMCPExecutionInput
  | CursorHookInputBase;

export type Decision =
  | { readonly kind: 'allow' }
  | {
      readonly kind: 'deny';
      readonly ruleId: string;
      readonly reason: string;
    }
  | {
      // Issued when the input is missing fields the hook needs to
      // classify the call, or when the event is one we explicitly
      // defer (beforeMCPExecution per ADR 0014 §10). Runtime treats
      // skip as allow; tests assert on the distinction.
      readonly kind: 'skip';
      readonly why: string;
    };

function expandHome(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/')) return `${home}/${p.slice(2)}`;
  return p;
}

function canonicalizePath(raw: string, home: string, cwd: string): string {
  const expanded = expandHome(raw, home);
  const slashy = expanded.replaceAll('\\', '/');
  if (slashy.startsWith('/')) return slashy;
  if (/^[a-zA-Z]:\//.test(slashy)) return slashy;
  const cwdSlashy = cwd.replaceAll('\\', '/');
  const prefix = cwdSlashy.endsWith('/') ? cwdSlashy : `${cwdSlashy}/`;
  return `${prefix}${slashy}`;
}

function tokenizeCommand(command: string, home: string, cwd: string): string[] {
  // Tokenizer matches the M6 hooks-claude implementation byte-for-byte
  // so the cross-vendor parity test (ADR 0014 §11) can rely on
  // identical evidence strings. See packages/hooks-claude/src/
  // interceptor.ts for the full rationale.
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
  return tokens.map((t) => {
    if (t.startsWith('-')) return t;
    if (t.startsWith('~') || t.startsWith('/') || t.startsWith('./') || t.startsWith('../')) {
      return canonicalizePath(t, home, cwd);
    }
    return t;
  });
}

function buildView(input: CursorHookInput, home: string, cwd: string): ToolCallView | null {
  const event = typeof input.hook_event_name === 'string' ? input.hook_event_name : '';

  if (event === 'beforeReadFile') {
    const ri = input as CursorBeforeReadFileInput;
    const raw = ri.file_path;
    if (typeof raw !== 'string' || raw.length === 0) return null;
    return {
      tool: 'read',
      raw,
      absPath: canonicalizePath(raw, home, cwd),
      commandTokens: [],
    };
  }

  if (event === 'beforeShellExecution') {
    const si = input as CursorBeforeShellExecutionInput;
    const raw = si.command;
    if (typeof raw !== 'string' || raw.length === 0) return null;
    // Cursor sends the shell's working directory in `cwd`; prefer it
    // over the supplied context cwd because that's the directory the
    // shell will actually run in. Falls back to workspace_roots[0],
    // then the supplied cwd.
    const shellCwd =
      typeof si.cwd === 'string' && si.cwd.length > 0
        ? si.cwd
        : Array.isArray(input.workspace_roots) && typeof input.workspace_roots[0] === 'string'
          ? input.workspace_roots[0]
          : cwd;
    return {
      tool: 'bash',
      raw,
      absPath: '',
      commandTokens: tokenizeCommand(raw, home, shellCwd),
    };
  }

  // beforeMCPExecution and any unknown event are deferred per
  // ADR 0014 §10 / §9. Returning null routes to a 'skip' Decision.
  return null;
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

// Local copy of the credentials.ts glob matcher — same posture as
// packages/hooks-claude/src/interceptor.ts. Allowlist matching uses
// byte-identical semantics to the rule pack matcher.
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

export function evaluateCursorToolCall(input: CursorHookInput, ctx: EvaluateContext): Decision {
  const event = typeof input.hook_event_name === 'string' ? input.hook_event_name : '';

  // Explicit defer (ADR 0014 §10): beforeMCPExecution is in Cursor's
  // hook surface but not yet a Warden rule target. Skip → allow.
  if (event === 'beforeMCPExecution') {
    return {
      kind: 'skip',
      why: 'beforeMCPExecution deferred to a future milestone (ADR 0014 §10)',
    };
  }
  // Unknown event names also skip → allow. Cursor may add events over
  // time; the cooperative-hook posture (ADR 0014 §3) says a schema
  // mismatch should not strand the developer.
  if (event !== 'beforeReadFile' && event !== 'beforeShellExecution') {
    return { kind: 'skip', why: `unrecognized hook_event_name: ${event || '<missing>'}` };
  }

  const view = buildView(input, ctx.home, ctx.cwd);
  if (view === null) {
    return { kind: 'skip', why: `${event} payload missing required fields` };
  }

  for (const rule of CREDENTIAL_RULES) {
    const hits = rule.evaluate(view);
    if (hits.length === 0) continue;
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
