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
