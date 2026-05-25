# ADR 0003 — Trust GPG key generation (deferred to M5)

**Status:** Deferred
**Date:** 2026-05-24
**Deciders:** Project bootstrap

---

## Context

M5 introduces `warden trust sign|verify|unlock`, a GPG-based signing system for agent context files. The question raised at bootstrap was: does Warden ship with a project-owned GPG key (a "vendor" key, e.g. `warden-trust@warden.dev`), or does it require users to bring their own?

This is a meaningful security and operational decision. A vendor key creates a centralized trust anchor — good for UX, bad if compromised. A bring-your-own model is more honest about the trust model but introduces friction for solo developers who do not already have a GPG key.

---

## Decision

**Defer the decision to M5.** M0 documents the trust system's design surface (see `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` §M5) but does **not** generate any key, recommend any specific key model, or commit to a key fingerprint.

Rationale for deferring:
- M0 produces no code that depends on a key existing.
- The right answer becomes clearer after M4, when the MCP analyzer ships and we see how users actually want to express trust over MCP configs (often the same trust expression a user would want for a signed `CLAUDE.md`).
- Generating a project-owned GPG key prematurely creates an artifact we must protect, rotate, and document key-loss procedures for — premature operational complexity.

---

## Open questions for M5

When this ADR is reopened during M5 scoping, answer:

1. **Vendor key or BYO?** If vendor key: who holds the private half, where, with what rotation policy?
2. **Single key or hierarchy?** A root key + per-rule-pack signing subkey is conventional; is it warranted at our scale?
3. **Sigstore / keyless?** A keyless model may be a better fit for an OSS tool than long-lived GPG keys. Worth a separate ADR.
4. **CI integration:** Verify-on-pull-request flow needs the same answer for GitHub Actions and self-hosted runners.

---

## Consequences

- No M0 artifact references a real key fingerprint.
- M1–M4 ship without trust-system integration; trust is bolted on cleanly in M5 against an unsigned baseline.
- Any user who wants to sign `CLAUDE.md` before M5 lands can do so manually with `gpg --detach-sign`; Warden simply will not consume the signature until M5.
