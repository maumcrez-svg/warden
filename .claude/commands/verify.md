---
description: Full check — lint, tests, dogfood scan. Run before every commit.
---

# /verify

Run the full verification suite for the Warden repo. All steps must pass before any commit is created.

## Steps

1. **Lint** — `bunx biome check .` — must report 0 errors. Warnings are acceptable but should be addressed before milestone closure.
2. **Type-check** — `bunx tsc --noEmit` — must report 0 errors.
3. **Tests** — `bun test` — must pass all suites in all packages.
4. **Dogfood scan** — `bun test tests/dogfood.test.ts` — scans first-party Warden source via `scanUnicode` and must report 0 findings. Replaces a full `warden scan .` until the CLI lands in M2.

## Reporting

For each step, print one line:
- `OK <step>` on success
- `FAIL <step>` on failure, followed by the first 20 lines of the failure output

Exit non-zero if any step fails. The agent must not proceed to a commit on a non-zero exit.

## State

- M0: scaffolding only — step 3 had no tests, step 4 had no scanner. Both expected to no-op or report missing.
- M1: scanner exists. Step 3 runs the scan-unicode suite; step 4 runs the dogfood scan via Bun's test runner.
- M2 (planned): step 4 graduates to `bun run packages/cli/src/index.ts scan .` once the CLI walker and reporter ship.

Update this file as steps become real, not before.
