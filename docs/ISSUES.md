# Tracked technical debt

Local tracker. Migrate to GitHub Issues when repo goes public.

## #001 — SARIF output not validated against official OASIS schema

**Status:** open
**Milestone:** pre-1.0 (must close before public v1.0)
**Severity:** medium
**Origin:** M2 review, see ADR 0007 §2

Current SARIF output passes manual structural assertions in
packages/cli/tests/report-sarif.test.ts (required fields, level enum,
version string). It is NOT validated against the official
sarif-2.1.0-schema.json from OASIS.

Risk: SARIF may be syntactically correct but semantically off-spec.
GitHub Code Scanning may reject output that our manual asserts accept.

Resolution: add ajv + sarif-2.1.0-schema.json as devDependency, add a
test that validates real scan output against schema. Decision on runtime
validation (always-on vs --strict flag) deferred to that task.

## #002 — Broad-scope marker families lack explicit file allowlist

**Status:** open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M3.1 review, see ADR 0010 §"Open after M3.1"

Broad-scope marker families (`rules-data`, `detector-test`) currently
restrict to a directory regex, not an explicit file list. A PR that adds
both a new file under the restricted directory AND a marker on the first
line of that new file creates a scanner dead zone, defended only by code
review.

Resolution path: either (a) replace regex restriction with explicit
file allowlist in `packages/core/src/marker.ts`, OR (b) implement
pattern-aware suppression where marker declares specific literal
substrings to suppress, anything else fires. Decision pending real-world
attack data or M4 MCP fixture requirements.

Tracker: revisit when a second broad-scope family is proposed, or when
the repo goes public and CODEOWNERS becomes enforceable.

Sub-task: the M3.2 `.github/CODEOWNERS` file references
`@warden-sh/maintainers` as a placeholder team handle. The final
team/handle is pending the public-repo / GitHub-org decision tracked
in ADR 0004. When that resolves, update CODEOWNERS in the same PR
that flips ADR 0004 from "tentative" to "accepted".

## #003 — MCP config path discovery coverage gaps

**Status:** open
**Milestone:** pre-1.0
**Severity:** low
**Origin:** M4 review

Warden's MCP config detection (`packages/core/src/detect-format.ts`)
covers three patterns by basename or path segment:

- `mcp.json` (any depth)
- `claude_desktop_config.json` (any depth)
- `.cursor/mcp.json` (path segment)

Known gaps (not detected by default):

- `.mcp/config.json` — alternative convention in some setups
- `.vscode/mcp.json` — VS Code MCP convention (recent)
- `.codeium/windsurf/mcp_config.json` — Windsurf-specific
- User-global configs at `~/.cursor/mcp.json`,
  `~/Library/Application Support/Claude/claude_desktop_config.json`,
  `~/.codeium/windsurf/mcp_config.json` — only scanned when the user
  passes the path explicitly (correct privacy stance, intentional)

Resolution path: add the three repo-local patterns to
`detect-format.ts` when usage data confirms prevalence. User-global
config scanning stays opt-in via explicit argument; do not change
default behavior to walk the home directory.

## #004 — MCP tool description scanning not implemented as dedicated rule

**Status:** open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M4 review

The MCP tool poisoning vector (malicious tool description injected via
`tools/list` protocol response at runtime, or inline in config) is
explicitly out of scope for static MCP analysis per ADR 0011 §2 —
runtime tool poisoning requires spawning the server, which violates
the no-exec invariant.

The inline-in-config subcase (config declares `tools[].description` or
similar text fields) is partially covered by collateral scanning:
`scan-path.ts` runs `scanUnicode` and `scanPromptInjection` on the raw
JSON content before `scan-mcp.ts` runs structural analysis. A
description containing override-prior-context phrasing or invisible
Unicode fires as a prompt-injection or Unicode finding on the MCP file
(not as an MCP finding). This is defense-in-depth by design, but not
by dedicated MCP rule.

Decision: track as known gap. Do not add a dedicated MCP rule for
description fields yet — risk of duplicate findings (one
prompt-injection + one MCP) without clear severity tier. Revisit when
(a) real MCP description-injection attacks surface publicly, or
(b) M5 trust-signing proposes signed-config semantics that need this
category formally.

## #005 — MCP http-transport-external rule does not differentiate transport types

**Status:** open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M4 review

The rule `mcp.http-transport-external`
(`packages/rules/src/data/mcp.ts`) fires HIGH for any non-loopback
URL, regardless of transport type (`http`, `sse`, `streamable-http`).
This produces high false-positive rates for developers using
legitimate remote MCP servers via SSE (Anthropic reference servers,
GitHub MCP, fetch-mcp at user-controlled endpoints).

Threat profile differs by transport:

- `stdio` — typosquatting risk on command/args (covered by separate
  rules `mcp.command-not-pinned` and
  `mcp.absolute-path-untrusted-binary`)
- `sse` — replay attacks, URL spoofing; risk is domain-trust dependent
- `streamable-http` — stream hijacking + SSE risks

Resolution path: introduce transport-aware tiering. Suggested split:

- INFO for any documented MCP at any remote endpoint
- MEDIUM for unsigned remote endpoints
- HIGH for non-loopback endpoints not in a user allowlist
  (`.warden.toml` declares allowed domains)

Decision deferred: requires a `.warden.toml` config schema, which is a
v1.0 concern. Until then, users can suppress the rule per-file via
marker if the false-positive rate is unacceptable.
