---
description: Full check — lint, tests, dogfood scan. Run before every commit.
---

# /verify

Run the full verification suite for the Warden repo. All steps must pass before any commit is created.

## Steps

1. **Lint** — `bunx biome check .` — must report 0 errors. Warnings are acceptable but should be addressed before milestone closure.
2. **Type-check** — `bunx tsc --noEmit` — must report 0 errors.
3. **Tests** — `bun test` — must pass all suites in all packages.
4. **Dogfood scan** — `bun packages/cli/src/index.ts scan .` — must exit 0 (no high-severity findings). The `.wardenignore` at the repo root excludes intentional payload fixtures.

## Reporting

For each step, print one line:
- `OK <step>` on success
- `FAIL <step>` on failure, followed by the first 20 lines of the failure output

Exit non-zero if any step fails. The agent must not proceed to a commit on a non-zero exit.

## State

- M0: scaffolding only — step 3 had no tests, step 4 had no scanner. Both expected to no-op or report missing.
- M1: scanner exists. Step 3 runs the scan-unicode suite; step 4 ran the dogfood scan via Bun's test runner (`tests/dogfood.test.ts`) since the CLI did not yet exist.
- M2: CLI walker + reporter shipped. Step 4 now invokes `warden scan .` via `bun packages/cli/src/index.ts`. The original `tests/dogfood.test.ts` remains and is exercised by `bun test` in step 3.

Update this file as steps become real, not before.
