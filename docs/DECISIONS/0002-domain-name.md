# ADR 0002 — Domain name (deferred)

**Status:** Deferred (placeholder in use)
**Date:** 2026-05-24
**Deciders:** Project bootstrap

---

## Context

Warden needs a primary domain for:
- The curl-pipe install script (`curl -fsSL https://<domain>/install.sh | sh`).
- The documentation site (post-MVP).
- The trust-system convention for the dedicated GPG key identifier (`warden-trust@<domain>`), if M5 chooses to ship a project-owned key.
- A contact email.

`warden.dev` is the preferred candidate. Availability has not been verified during M0 bootstrap.

---

## Decision

Use `warden.dev` as a **placeholder** throughout all M0 documentation and configuration. Do not block M0 on domain procurement.

A follow-up task **before M2** (when the README will be exposed to first external readers via demo links) must:

1. Check `warden.dev` registration status.
2. If unavailable, evaluate fallbacks in priority order:
   - `warden.sh` (consistent with placeholder npm scope `@warden-sh` — see ADR 0004).
   - `warden.tools`
   - `getwarden.dev`
   - `usewarden.dev`
3. Register the chosen domain.
4. Open this ADR, flip status to "Accepted", record the chosen domain, sweep the repo for `warden.dev` references and update.

---

## Consequences

- All references to `warden.dev` in M0 docs are non-load-bearing strings. The install script does not exist yet; the docs site does not exist yet; the GPG key is not generated yet (see ADR 0003).
- Any code, link, or signature that would depend on the actual domain must wait until this ADR resolves.

---

## TODO

- [ ] Check `warden.dev` whois.
- [ ] Decide between primary and fallbacks.
- [ ] Register the chosen domain.
- [ ] Update this ADR with the final decision (flip Status → Accepted).
- [ ] Sweep repo for `warden.dev` references and update.
