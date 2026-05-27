# ADR 0011 — MCP config static analyzer (and JSON marker syntax)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M4 design pass
**Extends:** ADR 0010 §7 (the deferred JSON marker syntax decision)

---

## Context

M4 adds Warden's first non-text scanner: the MCP (Model Context
Protocol) configuration analyzer. Three vendors ship MCP configs that
agents read at startup: Claude Code (`mcp.json` /
`~/.claude.json#mcpServers`), Cursor (`.cursor/mcp.json`), and Claude
Desktop (`claude_desktop_config.json`). Each entry under `mcpServers`
declares a process the agent will spawn (`type: "stdio"`) or an
endpoint it will call (`type: "http" | "sse"`). A misconfigured or
adversary-supplied MCP server entry has the same blast radius as a
compromised dev dependency: the agent runs it with the user's
credentials, on the user's machine, every session.

The flagship requirement is in `docs/ARCHITECTURE.md` §6: the analyzer
**must not spawn** the declared servers. Tools that spawn-to-introspect
inherit the risk of executing attacker-controlled binaries — exactly
the threat surface Warden exists to reduce.

A second decision falls out of the first fixture: standard JSON does
not allow comments, so the inline `// warden: payload-fixture …`
convention from ADR 0010 cannot apply directly. ADR 0010 §7 deferred
this and required a new ADR before any JSON fixture lands. This ADR
specifies the JSON marker syntax alongside the analyzer.

---

## Decision

### 1. Pure-function parser, JSON-only, no I/O on the hot path

The analyzer is a single exported function:

```ts
scanMcp(content: string): McpFinding[]
```

It accepts the raw bytes of the config file as a UTF-8 string,
`JSON.parse`s them, walks the `mcpServers` map, and applies each rule
in `packages/rules/src/data/mcp.ts`. No filesystem access, no
subprocess, no network. Parse errors are surfaced as a single finding
of rule `mcp.invalid-json` so the file's presence stays visible in the
report rather than being silently dropped.

The same parser handles the three vendor shapes because all three use
the `mcpServers` top-level key with the same per-server schema. Cursor
fixtures that use `servers` instead of `mcpServers` are out of scope
for M4 — defer to a follow-up milestone if a real Cursor config in
that shape surfaces.

### 2. Sandbox guarantee enforced by Biome `noRestrictedImports`

The Biome lint config gains an override that targets
`packages/core/src/scan-mcp.ts` and forbids importing any of:

- `node:child_process`, `child_process`
- `node:net`, `net`
- `node:dgram`, `dgram`
- `node:fs/promises` (the parser is sync and uses only the
  caller-supplied string anyway; writes are linted out elsewhere by
  `noRestrictedImports` if needed)

If a future contributor reaches for `spawn` "just to confirm the
binary exists," the lint fails. This is the policy claim from
`docs/ARCHITECTURE.md` §6 promoted to a machine-checked invariant.

### 3. Detection rules (M4 ships five)

All rules cite threat **T2 (GlassWorm)** — MCP configs are the
agent-context surface GlassWorm-class attacks abuse. Each rule has a
primary-source citation and a verifiedDate per `docs/THREAT_MODEL.md`
§"Citation Policy".

| Rule ID                                | Severity | What it detects                                              |
|----------------------------------------|----------|--------------------------------------------------------------|
| `mcp.invalid-json`                     | high     | The file is not valid JSON or is not a top-level object.     |
| `mcp.command-not-pinned`               | medium   | stdio server uses `npx`/`bunx`/`pnpm dlx` etc. without `@version` pin on the package argument. |
| `mcp.absolute-path-untrusted-binary`   | medium   | stdio server's `command` is an absolute path outside the system trust prefixes (`/usr/`, `/bin/`, `/sbin/`, `/opt/`, Windows `C:\Windows\`). |
| `mcp.http-transport-external`          | high     | HTTP/SSE server's `url` host is not localhost (loopback). Egress-to-internet by config. |
| `mcp.shell-exec-command`               | high     | stdio server's `command` is a shell (`sh`, `bash`, `zsh`, `cmd`, `powershell`) with `-c`/`-Command`. Arbitrary string execution.|

The four ROADMAP M4 fixtures map onto rules 2-5 (and the minimal-correct
fixture exercises the zero-finding path). The `invalid-json` rule
exists so that a malformed config still produces a finding rather than
disappearing silently.

The `unscoped env var` check from the ROADMAP plain-English list
folds into M5 work on credential blocklists — keeping it out of M4
avoids a rule whose false-positive shape isn't yet validated against
real-world configs.

### 4. Severity model

Reuses the existing `'low' | 'medium' | 'high'` severity union (same
as `UnicodeSeverity` and `PromptInjectionSeverity`). The ROADMAP
mentions `info` as a fourth tier; defer that until a rule actually
needs it. Three tiers is what every existing severity-aware code path
(SARIF mapping, pretty reporter ANSI palette) handles today.

> **Resolved by ADR 0016 §4 (M9).** The `info` tier was added system-wide
> when M9's `supply-chain.osv-known-vulnerability` rule needed it for
> transitive LOW advisories. ADR 0016 §4 documents the system-wide
> impact (reporters, JSON schema, `--strict` gate). New rules emitting
> `info` outside the `supply-chain.*` namespace need explicit ADR
> justification (ADR 0016 §Consequences).

### 5. New file kinds

`detectFormat` gains two recognitions:

- `claude_desktop_config.json` → existing `mcp-json` kind.
- `.cursor/mcp.json` → existing `mcp-json` kind (matched via path
  prefix; bare `mcp.json` continues to match).

No new `FileKind` variant. The format detector's role is "is this a
candidate for scanning?" and all three vendor files want the same
scanner.

### 6. JSON marker syntax (extends ADR 0010 §7)

The fixture set introduces JSON files that legitimately contain
payloads. Standard JSON does not allow comments, so the line-comment
marker convention from ADR 0010 §2 does not apply. This ADR specifies
the JSON marker shape:

> The marker for a `.json` file is a top-level string property
> **`_warden`** whose value begins with `warden:` and follows the
> ADR 0010 §2 grammar verbatim from the sentinel onwards.

Example:

```json
{
  "_warden": "warden: payload-fixture mcp-config -- T2 fixture: missing version pin",
  "mcpServers": {
    "demo": { "command": "npx", "args": ["@scope/server"] }
  }
}
```

Rules:

- The property must be at the JSON document's **root object**. Nested
  occurrences are ignored (no header-zone concept in JSON — the root
  property serves the same purpose: visible at the top of the file,
  visible in the diff).
- The property value must be a single JSON string. Arrays, objects,
  and non-string scalars are parse errors.
- The grammar after `warden:` is identical to ADR 0010 §2 — same
  directives, families, scopes, `--` reason separator, ASCII-only.
- `scope:lines:N-M` is supported with the same semantics; line numbers
  count the raw file (the JSON-parsed structure's source positions).
- Multiple `_warden` keys are impossible (JSON objects collapse
  duplicates), so the "multiple markers" parse error from ADR 0010 §6
  does not apply here. A single key with a value that fails grammar
  validation is still a hard parse error (exit 2).
- The `_warden` key name is chosen because:
  - It starts with `_`, the conventional "metadata, not config"
    prefix in JSON tooling.
  - It is not a recognized key in any of the three vendor MCP schemas
    audited (Claude Code, Cursor, Claude Desktop), so adding it to a
    real config is inert in production tooling.
  - Reviewers diffing a PR see `"_warden":` adjacent to `"mcpServers":`
    — the trust escalation is glaring, the same property the marker
    grammar elsewhere demands.

The MCP parser strips `_warden` from the parsed object before applying
detection rules, so the marker itself never appears as a finding.

### 7. New marker family

`packages/core/src/marker.ts` gains one narrow-scope family:

```
mcp-config  →  suppresses category 'mcp'  (narrow)
```

Path restriction: none (same posture as `trapdoor-unicode` and
`prompt-injection-pattern`). Cross-category poisoning still fires: a
file marked `mcp-config` that also contains invisible Unicode in a
string value will still report the Unicode finding, because the
`unicode` category is not in the `mcp-config` family's coverage set.

A new `FindingCategory` variant `'mcp'` is added to the marker
parser's category union and to `scanPath`'s suppression bookkeeping.

### 8. Wiring into `scanPath`

`FileReport` gains two additive fields:

- `mcpFindings: ReadonlyArray<McpFinding>`
- `suppressedMcpFindings: ReadonlyArray<McpFinding>`

`ScanReport.suppressedByCategory` gains an `mcp: number` field.
`findingCount` / `highCount` / `mediumCount` / `lowCount` aggregate MCP
findings the same way they aggregate Unicode and prompt-injection.

JSON output remains on `warden/scan/v2` — these are additive within
v2, same rationale as ADR 0010 §8 (no version-discriminator inflation
for additive fields whose absence in v1-era consumers degrades
gracefully).

### 9. Reporters

- **Pretty:** MCP findings render in the same per-file block as
  Unicode and prompt-injection findings, with the same severity-color
  palette.
- **JSON:** additive fields on each `files[]` entry.
- **SARIF:** MCP rules emit into `tool.driver.rules[]` when used,
  results carry the same `suppressions[]` shape from ADR 0010 §9 when
  a marker suppresses them.

---

## Consequences

**Positive:**

- The flagship `--sandbox` claim from `docs/ARCHITECTURE.md` §6 is
  lint-enforced for the MCP parser, not just documented.
- JSON fixtures are now first-class with a marker syntax that mirrors
  the existing one — the operational rule in ADR 0010 §7 is satisfied
  without re-introducing `.wardenignore` directory exclusions.
- The MCP rule set is small and citation-backed; future expansion
  (env-var scope, header-leak detection, scope creep into Cursor's
  `servers` shape) lands in follow-up milestones rather than M4.

**Negative:**

- `_warden` adds a non-vendor key to MCP configs that adopt it. Real
  vendor parsers might warn about unknown keys (audited:
  Claude/Cursor/Claude Desktop accept unknown root keys today; revisit
  if a future vendor turns this into a hard error).
- The MCP parser is now a third bespoke detector. As the count grows,
  pressure to abstract a "Detector" interface will rise. M4 keeps the
  copy-paste shape because two prior detectors share little structural
  similarity; abstraction is a future refactor.

---

## Known limitations (named by M4.1)

Three limitations were identified in post-M4 review. Each has a
tracking issue with a resolution path; none invalidate the M4
acceptance criteria.

- **Path discovery covers three repo-local patterns by default.**
  `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`.
  `.mcp/config.json`, `.vscode/mcp.json`, and
  `.codeium/windsurf/mcp_config.json` are not detected at default
  scan time; user-global configs under `~/` are only scanned when the
  user passes the path explicitly (correct privacy stance). See
  `docs/ISSUES.md` #003 for the resolution path.
- **Tool description scanning is not implemented as a dedicated MCP
  rule.** Inline description fields in configs receive collateral
  coverage via `scanUnicode` and `scanPromptInjection` on the raw
  JSON content (see `docs/ARCHITECTURE.md` §7 "Cross-category
  collateral scanning"). Runtime tool poisoning via the `tools/list`
  protocol response is structurally out of scope per §2 of this ADR
  (no-spawn invariant). See `docs/ISSUES.md` #004.
- **Transport-aware tiering for `mcp.http-transport-external` is
  deferred until the `.warden.toml` config schema lands (v1.0).**
  Current rule treats `stdio` / `sse` / `streamable-http` uniformly:
  any non-loopback URL fires HIGH. Users running legitimate remote
  SSE servers (Anthropic reference servers, GitHub MCP) can suppress
  per-file via marker until the allowlist schema arrives. See
  `docs/ISSUES.md` #005.

---

## Revisit triggers

Reopen if any of:

- A real-world MCP vendor adds a key that overlaps `_warden`, or
  rejects unknown root keys.
- A Cursor `servers` (no `mcp` prefix) shape appears in the wild and
  needs detection.
- ~~The `info` severity tier becomes necessary (e.g., advisory rule that
  warns on localhost HTTP without flagging it).~~ **Triggered and
  resolved** by ADR 0016 §4 (M9) — `info` is now a system-wide tier
  hosting transitive LOW supply-chain findings. New MCP rules wanting
  `info` no longer need a fresh ADR for the tier itself; they just
  need to justify the tier choice the same way new HIGH-severity
  rules do.
- The lint-based sandbox boundary proves insufficient (e.g., a
  transitive import sneaks a forbidden symbol in) — promote to
  packaging-level isolation.
