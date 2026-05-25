// warden: payload-fixture rules-data -- regex literals and shell-token tables are attack-shaped by definition (ADR 0010)
//
// MCP (Model Context Protocol) configuration rule pack. Each rule cites
// threat T2 (GlassWorm — same MCP-config surface that GlassWorm-class
// attacks abuse to ship malicious extensions/servers).
//
// Severity tiers reuse the existing 'low' | 'medium' | 'high' union from
// unicode-ranges.ts and prompt-injection.ts. ADR 0011 §4 records why M4
// does not introduce an 'info' tier — no rule currently needs it.
//
// Detection design: the scanner walks each server entry under the
// top-level `mcpServers` object and runs each rule's `evaluate` on the
// individual server. Rules are pure functions over the parsed server
// entry so the rule data file stays JSON-shaped and the detector stays
// in packages/core/src/scan-mcp.ts.

import type { UnicodeSeverity } from './unicode-ranges.ts';

export type McpSeverity = UnicodeSeverity;

// Minimal structural view of an MCP server entry, common to Claude Code,
// Cursor, and Claude Desktop. Fields are optional because real-world
// configs omit defaults; the rule evaluators handle absence.
export type McpServerEntry = {
  readonly type?: string;
  readonly command?: string;
  readonly args?: ReadonlyArray<string>;
  readonly env?: Readonly<Record<string, string>>;
  readonly url?: string;
  readonly headers?: Readonly<Record<string, string>>;
};

export type McpRuleHit = {
  readonly evidence: string;
};

export type McpRule = {
  readonly id: string;
  readonly threatIds: ReadonlyArray<'T2'>;
  readonly name: string;
  readonly severity: McpSeverity;
  readonly citation: string;
  readonly verifiedDate: string;
  // Pure predicate. Returns one hit per concrete piece of evidence so a
  // single misconfiguration that triggers in two places (e.g. `npx` AND
  // a missing pin) still produces well-located findings.
  readonly evaluate: (server: McpServerEntry, name: string) => ReadonlyArray<McpRuleHit>;
};

// Commands whose presence in `command` is the "shell -c" pattern — an
// arbitrary-string execution surface in an agent context file. Listed as
// data rather than inlined into the regex so the audit trail is
// reviewable in one place.
const SHELL_COMMANDS = new Set<string>([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
]);

// Package runners whose package argument is conventionally a version-
// pinnable identifier. `npx -y @scope/pkg` without `@version` resolves
// the latest published version at agent-startup time — exactly the
// dormant-package-resurrection surface (T3) and the GlassWorm carrier
// (T2). `npx` flags like `-y`, `-p`, `--package` are recognized so the
// pin check looks at the actual package argument.
const PACKAGE_RUNNERS = new Set<string>(['npx', 'bunx', 'pnpx', 'pnpm']);

// System trust prefixes for absolute-path checks. Anything outside these
// roots, when used as an MCP server `command`, is a user-writable
// location and should be reviewed. The list is intentionally conservative
// — false positives are tunable, false negatives are exploitable.
const SYSTEM_PREFIXES_POSIX: ReadonlyArray<string> = [
  '/usr/',
  '/bin/',
  '/sbin/',
  '/opt/',
  '/Library/',
  '/System/',
];

const SYSTEM_PREFIXES_WIN: ReadonlyArray<string> = [
  'c:\\windows\\',
  'c:\\program files\\',
  'c:\\program files (x86)\\',
];

function isSystemPath(absPath: string): boolean {
  for (const prefix of SYSTEM_PREFIXES_POSIX) {
    if (absPath.startsWith(prefix)) return true;
  }
  const lower = absPath.toLowerCase();
  for (const prefix of SYSTEM_PREFIXES_WIN) {
    if (lower.startsWith(prefix)) return true;
  }
  return false;
}

function isAbsolutePathCommand(command: string): boolean {
  return command.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(command);
}

// Pull the package argument out of an `npx`-style invocation. Skips flag
// tokens (`-y`, `--yes`, etc.) and `--package <pkg>` pairs. Returns null
// when the args list contains no positional package argument.
function extractPackageArg(args: ReadonlyArray<string>): string | null {
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? '';
    if (a === '-p' || a === '--package') {
      const next = args[i + 1];
      if (next !== undefined) return next;
      continue;
    }
    if (a.startsWith('-')) continue;
    return a;
  }
  return null;
}

function isPinned(packageArg: string): boolean {
  if (packageArg.startsWith('@')) {
    const afterScope = packageArg.indexOf('/');
    if (afterScope === -1) return false;
    const rest = packageArg.slice(afterScope + 1);
    return rest.includes('@');
  }
  return packageArg.includes('@');
}

function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isLoopback(host: string): boolean {
  if (host === 'localhost') return true;
  if (host === '127.0.0.1') return true;
  if (host === '::1') return true;
  if (host === '[::1]') return true;
  return host.endsWith('.localhost');
}

export const MCP_RULES: ReadonlyArray<McpRule> = [
  {
    id: 'mcp.command-not-pinned',
    threatIds: ['T2'],
    name: 'MCP server package not version-pinned',
    severity: 'medium',
    citation:
      'npm dormant-package-resurrection pattern (Mini Shai-Hulud, 2025); a package runner without an @version pin resolves the latest published version at agent-startup time.',
    verifiedDate: '2026-05-25',
    evaluate: (server, name) => {
      const cmd = server.command;
      if (typeof cmd !== 'string') return [];
      const runner = cmd.toLowerCase();
      if (!PACKAGE_RUNNERS.has(runner)) return [];
      const args = server.args ?? [];
      const pkg = extractPackageArg(args);
      if (pkg === null) return [];
      if (isPinned(pkg)) return [];
      return [{ evidence: `server "${name}": ${cmd} ${pkg} (no @version pin)` }];
    },
  },
  {
    id: 'mcp.absolute-path-untrusted-binary',
    threatIds: ['T2'],
    name: 'MCP server command is an absolute path outside system prefixes',
    severity: 'medium',
    citation:
      'GlassWorm advisory: invisible-Unicode VS Code extensions launched binaries from user-writable paths via MCP-style entries (Socket, May 2026).',
    verifiedDate: '2026-05-25',
    evaluate: (server, name) => {
      const cmd = server.command;
      if (typeof cmd !== 'string' || cmd === '') return [];
      if (!isAbsolutePathCommand(cmd)) return [];
      if (isSystemPath(cmd)) return [];
      return [
        { evidence: `server "${name}": absolute path "${cmd}" outside system trust prefixes` },
      ];
    },
  },
  {
    id: 'mcp.http-transport-external',
    threatIds: ['T2'],
    name: 'MCP server uses HTTP/SSE transport to a non-localhost host',
    severity: 'high',
    citation:
      'OWASP LLM03:2025 Supply Chain (https://genai.owasp.org/llmrisk/llm03-supply-chain/) — third-party MCP endpoints over the network are an unbounded egress surface for agent context and tool output.',
    verifiedDate: '2026-05-25',
    evaluate: (server, name) => {
      const type = (server.type ?? '').toLowerCase();
      if (type !== 'http' && type !== 'sse' && type !== 'streamable-http') {
        if (typeof server.url !== 'string') return [];
      }
      const url = server.url;
      if (typeof url !== 'string' || url === '') return [];
      const host = hostnameOf(url);
      if (host === null) return [];
      if (isLoopback(host)) return [];
      return [{ evidence: `server "${name}": ${type || 'http'} transport → ${host}` }];
    },
  },
  {
    id: 'mcp.shell-exec-command',
    threatIds: ['T2'],
    name: 'MCP server command is a shell with -c/-Command (arbitrary execution)',
    severity: 'high',
    citation:
      'GlassWorm (Socket, May 2026): MCP server entries using `sh -c <string>` and `powershell -Command <string>` to stage shell payloads through the agent runtime.',
    verifiedDate: '2026-05-25',
    evaluate: (server, name) => {
      const cmd = server.command;
      if (typeof cmd !== 'string') return [];
      const base = cmd.split(/[\\/]/).pop()?.toLowerCase() ?? '';
      if (!SHELL_COMMANDS.has(base)) return [];
      const args = server.args ?? [];
      const hasExecFlag = args.some((a) => a === '-c' || a.toLowerCase() === '-command');
      if (!hasExecFlag) return [];
      return [
        { evidence: `server "${name}": ${cmd} invoked with -c/-Command (shell exec surface)` },
      ];
    },
  },
];

// Sentinel rule id used by the parser when JSON.parse fails or the
// document is not a top-level object. Surfaced as a finding rather than
// dropping the file silently — visibility-first.
export const MCP_INVALID_JSON_RULE = {
  id: 'mcp.invalid-json',
  threatIds: ['T2'] as ReadonlyArray<'T2'>,
  name: 'MCP config is not valid JSON or not a top-level object',
  severity: 'high' as McpSeverity,
  citation:
    'Defensive default: an unparseable or shape-violating MCP config is presented as a finding so reviewers see the file at all (instead of being skipped silently).',
  verifiedDate: '2026-05-25',
} as const;
