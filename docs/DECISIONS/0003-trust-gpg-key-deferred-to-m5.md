# ADR 0003 — Trust key bootstrap (reopened and resolved in M5)

**Status:** Accepted (reopened from Deferred in M5 planning, 2026-05-25)
**Date:** 2026-05-24 (original); 2026-05-25 (resolution)
**Deciders:** Project bootstrap (original); M5 design pass (resolution)
**Related:** ADR 0012 (M5 trust signing specification)

---

## Context

M5 introduces `warden trust sign|verify|unlock`, a signing system for
agent context files. The question raised at bootstrap was: does Warden
ship with a project-owned key (a "vendor" key, originally framed as
`warden-trust@warden.dev` GPG), or does it require users to bring their
own?

This is a meaningful security and operational decision. A vendor key
creates a centralized trust anchor — good for UX, bad if compromised. A
bring-your-own model is more honest about the trust model but introduces
friction for solo developers who do not already have a usable key.

The original framing assumed **GPG** as the crypto layer. M5 planning
(see ADR 0012 §1) revisited and rejected GPG in favor of **SSH
signatures via `ssh-keygen -Y sign`**. The resolution below reflects the
SSH-based world; the original GPG framing is preserved in the historical
section for traceability.

---

## Decision (original, 2026-05-24)

**Defer the decision to M5.** M0 documents the trust system's design
surface (see `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` §M5) but does
**not** generate any key, recommend any specific key model, or commit to
a key fingerprint.

Rationale for deferring:
- M0 produces no code that depends on a key existing.
- The right answer becomes clearer after M4, when the MCP analyzer ships
  and we see how users actually want to express trust over MCP configs
  (often the same trust expression a user would want for a signed
  `CLAUDE.md`).
- Generating a project-owned key prematurely creates an artifact we
  must protect, rotate, and document key-loss procedures for —
  premature operational complexity.

---

## Open questions for M5 (original, 2026-05-24)

When this ADR is reopened during M5 scoping, answer:

1. **Vendor key or BYO?** If vendor key: who holds the private half,
   where, with what rotation policy?
2. **Single key or hierarchy?** A root key + per-rule-pack signing
   subkey is conventional; is it warranted at our scale?
3. **Sigstore / keyless?** A keyless model may be a better fit for an
   OSS tool than long-lived keys. Worth a separate ADR.
4. **CI integration:** Verify-on-pull-request flow needs the same
   answer for GitHub Actions and self-hosted runners.

---

## Resolution (2026-05-25, M5 planning)

The four open questions resolve as follows. Each answer is load-bearing
for ADR 0012's M5 specification.

### 1. Vendor key or BYO? — **Hybrid, vendor key as bootstrap only.**

The Warden repository ships a `.warden/trust/allowed_signers` whose
**single bootstrap entry** is the SSH public key of the project
maintainer (Rezende). Concrete consequences:

- The bootstrap key is the SSH key the maintainer already uses to push
  to the repository — no new key generation, no new artifact to rotate
  or back up, no key-loss recovery procedure unique to Warden.
- Public half is committed in `.warden/trust/allowed_signers`. Private
  half lives on the maintainer's machine and never touches the repo.
- Downstream users (other devs adopting Warden) **bring their own SSH
  keys** and add them to the `allowed_signers` of *their* repos.
  Warden's bootstrap key only signs Warden's own M5 fixtures; it is not
  a CA, not a root for anyone else's tree.
- Additional maintainers are added by editing `allowed_signers`, gated
  by CODEOWNERS review on the file. Same governance as the
  new-file-plus-new-marker mitigation from M3.2 (ADR 0010
  §"new-file-plus-new-marker").

This deliberately rejects the "vendor key as universal trust anchor"
model the original ADR worried about. There is no `warden-trust@…`
identity, no key escrow, no rotation policy beyond "edit allowed_signers
when the human's key rotates."

### 2. Single key or hierarchy? — **Single key. No hierarchy.**

Flat trust root. The `allowed_signers` is a set of equals; any key in
the set can sign any context file. No subkey delegation, no rule-pack
signing tier, no certificate chains.

Justification: M5's scope is agent context files (`CLAUDE.md`, MCP
configs, etc.) — not release artifacts. Hierarchical key models earn
their complexity at release-signing scale (many signers, separation of
duties); at M5 scale (one or two maintainers signing N context files),
the hierarchy is overhead without payoff. If a future tier (release
signing, rule-pack distribution) needs hierarchy, that ADR addresses
it — M5 does not pre-commit to a model that does not yet have a use
case.

### 3. Sigstore / keyless? — **Deferred to post-M5, tracked in ISSUES #006.**

Sigstore (keyless signing via OIDC-attested identity) is the strongest
known answer to the "trust-root substitution" cenário (ADR 0012 §5.6)
because it removes the local trust root as a single point of failure:
the trust anchor becomes "any signature whose OIDC subject matches a
declared GitHub identity," not "any signature whose key is in the
committed file."

It is not in M5 because:
- It requires a network dependency at verify time (Sigstore's
  transparency log Rekor and Fulcio CA). M5's design constraint is
  offline-pure verification (ADR 0012 §4.2 — `warden trust verify` is
  CI-friendly with zero network calls).
- It requires OIDC token plumbing in CI (workload identity / GitHub
  Actions `id-token: write`) that not every user has.
- The right time to add it is when a real user requests
  enterprise-grade non-repudiation, not preemptively.

**TOFU (trust-on-first-use, the `~/.ssh/known_hosts` model) is
explicitly rejected**, not deferred. See ADR 0012 §6.4 and ISSUES #006
for the rejection rationale.

### 4. CI integration — **`warden trust verify --strict` in workflow YAML.**

GitHub Actions and self-hosted runners use the same command: `warden
trust verify --strict` against the committed `.warden/trust/manifest.toml`
+ `.warden/trust/allowed_signers`. Verify is offline-pure (only needs
the pubkey file + signature bytes + `ssh-keygen -Y verify`), so it
works identically in any runner with OpenSSH installed.

The reusable Action template (`warden-sh/trust-verify-action`) is
**deferred to v1.0** per M5 planning §9.8. M5 ships inline workflow
examples in `docs/USAGE-TRUST.md` §CI.

---

## Consequences

**Closed by this resolution:**

- The "do we need a vendor key" question is resolved: yes, exactly one,
  and only for Warden's own M5 fixtures. Not a CA. Not for downstream
  users.
- The "do we need a hierarchy" question is resolved: no, single tier,
  flat set.
- The crypto-layer question (GPG vs SSH vs minisign vs Sigstore) is
  resolved in ADR 0012 §1: SSH signatures.

**Open after this resolution (tracked elsewhere):**

- External anchor for the trust root (Sigstore / threshold trust /
  alternative pinning) — `docs/ISSUES.md` #006.
- Rotation policy for the bootstrap key beyond "edit allowed_signers" —
  not formalized; revisit if a second maintainer joins or if the
  bootstrap key is ever compromised.

**Replaces in the historical record:**

- The "GPG-based" framing of M5 in `ROADMAP.md §M5`, `ARCHITECTURE.md`,
  `README.md`, and `PRD.md` is superseded by the SSH-based design in
  ADR 0012. All four documents are updated in the **same commit that
  introduces this resolution** — governance docs cannot ship internally
  contradictory across the same SHA.
