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
