// MCP (Model Context Protocol) configuration static analyzer. Pure
// function over a UTF-8 string; no filesystem, no subprocess, no
// network. The sandbox guarantee from docs/ARCHITECTURE.md §6 is
// enforced for this file by the Biome `noRestrictedImports` override in
// biome.json (ADR 0011 §2): importing child_process, net, dgram, or
// fs/promises here fails lint.
//
// Vendor shapes covered: Claude Code (mcp.json + ~/.claude.json),
// Cursor (.cursor/mcp.json), Claude Desktop (claude_desktop_config.json).
// All three use the `mcpServers` top-level key with the same per-server
// schema. Cursor's alternate `servers` shape is out of M4 scope (ADR
// 0011 §1).
//
// Threat coverage: T2 (GlassWorm) — see docs/THREAT_MODEL.md and
// per-rule citations in packages/rules/src/data/mcp.ts.

import { MCP_INVALID_JSON_RULE, MCP_RULES, type McpServerEntry } from '@warden-sh/rules';
import type { McpFinding } from './findings.ts';

// The `_warden` root property is the JSON marker key per ADR 0011 §6.
// It is stripped from the parsed structure before rule evaluation so the
// marker itself never appears as an MCP finding.
const JSON_MARKER_KEY = '_warden';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function coerceServerEntry(value: unknown): McpServerEntry | null {
  if (!isPlainObject(value)) return null;
  const entry: { -readonly [K in keyof McpServerEntry]: McpServerEntry[K] } = {};
  if (typeof value.type === 'string') entry.type = value.type;
  if (typeof value.command === 'string') entry.command = value.command;
  if (Array.isArray(value.args)) {
    const args: string[] = [];
    for (const a of value.args) {
      if (typeof a === 'string') args.push(a);
    }
    entry.args = args;
  }
  if (isPlainObject(value.env)) {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(value.env)) {
      if (typeof v === 'string') env[k] = v;
    }
    entry.env = env;
  }
  if (typeof value.url === 'string') entry.url = value.url;
  if (isPlainObject(value.headers)) {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(value.headers)) {
      if (typeof v === 'string') headers[k] = v;
    }
    entry.headers = headers;
  }
  return entry;
}

function invalidJsonFinding(evidence: string): McpFinding {
  return {
    ruleId: MCP_INVALID_JSON_RULE.id,
    threatIds: MCP_INVALID_JSON_RULE.threatIds,
    ruleName: MCP_INVALID_JSON_RULE.name,
    severity: MCP_INVALID_JSON_RULE.severity,
    serverName: null,
    evidence,
    byteOffset: 0,
  };
}

export function scanMcp(content: string): McpFinding[] {
  if (content.length === 0) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return [invalidJsonFinding(`JSON parse error: ${msg}`)];
  }

  if (!isPlainObject(parsed)) {
    return [invalidJsonFinding('MCP config root must be a JSON object')];
  }

  const serversRaw = parsed.mcpServers;
  if (serversRaw === undefined) return [];
  if (!isPlainObject(serversRaw)) {
    return [invalidJsonFinding('"mcpServers" must be a JSON object')];
  }

  const findings: McpFinding[] = [];

  // Deterministic iteration order: sort server names so two scans of
  // the same input emit findings in the same order. Object.entries
  // order is insertion-order in modern engines but sorting removes the
  // dependency on parser quirks.
  const serverNames = Object.keys(serversRaw)
    .filter((k) => k !== JSON_MARKER_KEY)
    .sort();

  for (const name of serverNames) {
    const entry = coerceServerEntry(serversRaw[name]);
    if (entry === null) {
      findings.push(invalidJsonFinding(`server "${name}": entry must be a JSON object`));
      continue;
    }

    for (const rule of MCP_RULES) {
      const hits = rule.evaluate(entry, name);
      for (const hit of hits) {
        findings.push({
          ruleId: rule.id,
          threatIds: rule.threatIds,
          ruleName: rule.name,
          severity: rule.severity,
          serverName: name,
          evidence: hit.evidence,
          byteOffset: 0,
        });
      }
    }
  }

  // Stable order: server name, then rule id. Deterministic reports are
  // a precondition for reviewer-trustable diffs (ARCHITECTURE.md §3).
  findings.sort((a, b) => {
    const an = a.serverName ?? '';
    const bn = b.serverName ?? '';
    if (an !== bn) return an.localeCompare(bn);
    return a.ruleId.localeCompare(b.ruleId);
  });

  return findings;
}
