# `warden trust` — usage

Companion to **ADR 0012 — M5 trust signing**. ADR 0012 is the
authoritative specification (default-behavior matrix, abstraction shape,
threat model). This document is the operator-facing how-to.

---

## Prerequisites

- `ssh-keygen` on `PATH` (OpenSSH 8.0 or newer). macOS ships it; on Linux
  install `openssh-client`; on Windows 10+ enable the OpenSSH Client
  optional feature.
- An SSH keypair. Generate one with:
  ```
  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
  ```

---

## First sign

From the repo root, with your SSH key resolvable by Warden (the default
resolution order is `git config user.signingkey` when `gpg.format = ssh`,
then `~/.ssh/id_ed25519`, then `~/.ssh/id_rsa`):

```
warden trust sign CLAUDE.md
```

Outcome: a new `.warden/trust/manifest.toml` is created (or updated)
containing a `[[trust]]` entry for `CLAUDE.md`. Successful operations
emit nothing on stdout. The committed manifest is the durable record;
the signature itself sits inline in the manifest.

You also need to commit your public SSH key to
`.warden/trust/allowed_signers` so verify can resolve the fingerprint to
a principal. The file uses the OpenSSH `allowed_signers` format
(`ssh-keygen -Y verify` reference):

```
you@example namespaces="warden" ssh-ed25519 AAAAC3Nz... your@laptop
```

Warden never edits `allowed_signers` for you — trust-root edits force
visual review on the diff (same lesson as `gh codeowner add` not
existing). See ADR 0012 §4.5.

---

## Verify

Offline, no network, no TTY:

```
warden trust verify              # verify every manifest entry
warden trust verify CLAUDE.md    # verify a single entry
warden trust verify --json       # warden/trust-verify/v1 output
```

Exit codes:

- `0` — every entry verifies cleanly.
- `1` — at least one entry failed (mismatch, untrusted-signer, or missing
  file).
- `2` — setup error (manifest absent, `allowed_signers` malformed,
  `ssh-keygen` not on PATH).

---

## List

```
warden trust list
warden trust list --verify       # add a status column
warden trust list --json
```

`--json` emits a `warden/trust-list/v1` document.

---

## Unlock

For a file you intentionally choose not to sign (a draft, an
auto-generated CLAUDE.md, etc.):

```
warden trust unlock experimental/draft-claude.md --reason "draft em iteração; assinar quando estabilizar"
```

`--reason` is required. Unlock writes an `[[unlock]]` block to
`manifest.toml` and suppresses **only** `trust.unsigned`. It has no
effect on `trust.signature-mismatch` or `trust.untrusted-signer` (ADR
0012 §3 matrix).

Under `--strict`, unlocks are ignored entirely. Production posture
bypasses the escape hatch.

---

## Keys

Read-only inventory of the trust root:

```
warden trust keys list
warden trust keys list --json
```

Shows entries from `.warden/trust/allowed_signers` (committed,
authoritative) and `~/.warden/extra_allowed_signers` (per-machine,
additive, ignored under `--strict`).

There is no `warden trust keys add|remove`. Edits to the trust root
are manual by design — see ADR 0012 §4.5.

---

## Sentinel — opt-in enforcement without `--strict`

An empty (or comment-only) file at `.warden/trust-required`, when
committed, tells `warden scan` to enforce trust even without
`--strict`:

```
echo "# enable trust enforcement, 2026-05-25" > .warden/trust-required
```

A repo without the sentinel keeps the friendly migration path (trust is
silent until the first manifest entry lands). A repo with the sentinel
treats manifest absence as an alarm.

---

## CI integration

Minimum GitHub Actions snippet:

```yaml
- name: Verify Warden trust
  run: bunx warden trust verify --strict
```

Verify is offline-pure — no network, no TTY — and works in any runner
with OpenSSH installed. The reusable `warden-sh/trust-verify-action`
template is deferred to v1.0 alongside the public-repo migration
(ADR 0004 + ADR 0012 §10).

---

## Troubleshooting

| Error                                                                   | Fix                                                                                          |
|-------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `trust sign: no SSH key found`                                          | Generate one: `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`.                                  |
| `trust verify: ssh-keygen not on PATH`                                  | Install OpenSSH (`openssh-client` on Linux; built-in on macOS; OpenSSH feature on Windows).  |
| `trust.signature-mismatch — to re-sign, run: warden trust sign <path>`  | Re-sign after the legitimate edit.                                                           |
| `trust.untrusted-signer`                                                | Add the signer's public key to `.warden/trust/allowed_signers`, or re-sign with an allowed key. |
| `--strict requires .warden/trust/manifest.toml to be present`           | Adopt trust (run `warden trust sign` on at least one file), or drop `--strict`.              |
| `unlock has no effect on trust.signature-mismatch`                      | Working as designed (ADR 0012 §3). Re-sign to clear mismatch; unlock only suppresses unsigned. |
