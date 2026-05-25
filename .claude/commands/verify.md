---
description: Full check — lint, tests, dogfood scan. Run before every commit.
---

# /verify

Run the full verification suite for the Warden repo. All steps must pass before any commit is created.

## Steps

1. **Lint** — `bunx biome check .` — must report 0 errors. Warnings are acceptable but should be addressed before milestone closure.
2. **Type-check** — `bunx tsc --noEmit` — must report 0 errors.
3. **Tests** — `bun test` — must pass all suites in all packages.
4. **Dogfood scan** — `bun run packages/cli/src/index.ts scan .` (or `warden scan .` if installed) — must report 0 high-severity findings in the Warden repo itself.

## Reporting

For each step, print one line:
- `OK <step>` on success
- `FAIL <step>` on failure, followed by the first 20 lines of the failure output

Exit non-zero if any step fails. The agent must not proceed to a commit on a non-zero exit.

## M0 Note

During M0 (skeleton phase), step 3 finds no tests and step 4 fails because no scanner exists yet. Both are expected. This file documents the *target* behavior of `/verify` once M1 lands. Update this file as steps become real, not before.
