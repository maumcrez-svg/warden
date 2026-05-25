# ADR 0004 — GitHub organization placeholder

**Status:** Tentative
**Date:** 2026-05-24
**Deciders:** Project bootstrap

---

## Context

The Warden project needs a GitHub organization (or owner namespace) for the repository, and an npm scope for published packages. Both should match to reduce user confusion when navigating between `github.com/<org>/warden` and `npmjs.com/package/@<scope>/cli`.

No organization has been created yet. The project bootstrap session declined to commit to a final name pending domain verification (see ADR 0002) and a broader brand-availability check.

---

## Decision

Use **`warden-sh`** as the placeholder GitHub organization name and **`@warden-sh`** as the placeholder npm scope, consistently across:

- `package.json` `name` fields in every `packages/*/package.json`.
- `README.md` install commands.
- Internal cross-package import paths (`@warden-sh/core`, `@warden-sh/rules`, etc.).
- ADR cross-references.

Rationale for the specific choice:
- Alignment with the most likely fallback domain (`warden.sh`) from ADR 0002 — consistent branding if that is where we land.
- Hyphenated form increases the chance the npm scope is actually available (the bare `@warden` scope is more likely already taken).
- `-sh` suffix is a recognizable CLI-tool naming convention.

---

## Status: Tentative

This ADR is **tentative** — the placeholder may be swapped before M2 ships if:
- A domain decision in ADR 0002 lands on something other than `warden.sh`.
- The `@warden-sh` scope is not actually available on npm.
- A stakeholder (currently TBD — see PRD §2 ownership) has a stronger preference.

If swapped, the refactor is a flat sed across the repo plus a new ADR superseding this one. The choice of placeholder is deliberately easy to find-and-replace.

---

## Consequences

- Every reference to `warden-sh` in M0 docs and package metadata is provisional.
- The first external user who clones the repo sees `@warden-sh/cli`; the README notes this is provisional until ADR 0004 flips to "Accepted".
- No DNS, npm, or GitHub registration is performed in M0.

---

## TODO (to flip Status → Accepted)

- [ ] Check npm scope availability for `@warden-sh`.
- [ ] Check GitHub org availability for `warden-sh`.
- [ ] Cross-check against ADR 0002 domain decision.
- [ ] Create the GitHub org.
- [ ] Reserve the npm scope (publish a placeholder package).
- [ ] Update this ADR; sweep repo for divergent references.
