# ADR 0012 — M5 trust signing (`warden trust sign|verify|list|unlock`)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M5 design pass (review by project maintainer)
**Resolves:** ADR 0003 §3 (crypto choice) and §1 (vendor key model)
**Updates in the same commit:** `ROADMAP.md §M5`, `ARCHITECTURE.md`
(cold-path + ADR list), `README.md`, `PRD.md` — all rewritten from
"GPG-based" to "SSH signatures via `ssh-keygen -Y sign`" so governance
docs do not contradict across the same SHA.

---

## Context

M5 adds Warden's first system that **writes state** rather than just
reading it: `warden trust sign|verify|list|unlock`. The product
question is "how does a maintainer assert that a specific version of an
agent context file (`CLAUDE.md`, `.cursorrules`, `mcp.json`, etc.) is
the one approved for the AI agent to read?"

The original ROADMAP.md §M5 phrasing assumed GPG as the crypto layer
and `.warden/trust/<file>.sig` as the storage layout. M5 planning
revisited both assumptions plus eight open questions (vendor key vs
BYO, manifest vs sidecar, default behavior, CLI surface, trust roots,
marker interaction, sentinel, abstraction shape). A working
`docs/M5-PLANNING.md` carried the analysis; it was deleted in the same
commit that introduces this ADR, since this document is the durable
specification.

The threat model is the same one ADR 0010 and ADR 0011 already
target: an attacker who can write to the agent context surface (PR
contributor, dependency author, dotfile sync compromise) replaces or
augments instructions the agent will read. Signing lets the agent's
**reader-side** policy (M6 hooks; future verify-on-read) say "I will
only feed the agent context that a trusted maintainer signed at this
exact byte sequence."

---

## Decision

### 1. Crypto: SSH signatures (`ssh-keygen -Y sign`), single scheme

Warden uses `ssh-keygen -Y sign|verify` for all M5 signing. No GPG,
no minisign, no Sigstore, no hybrid.

The decision matrix:

| Scheme    | Verdict                                                        |
|-----------|----------------------------------------------------------------|
| **GPG**   | Rejected. UX hostile (subkeys, agent state, key generation as onboarding cliff), large parser surface (OpenPGP v4/v5, multi-algorithm), CVE history (e.g., SigSpoof CVE-2018-12020). Reuses git-signing infra, but SSH signing has filled that role since git 2.34 (2021). |
| **age**   | Rejected as category error. age is encryption, not signing. Spec explicit: "age does not provide authentication of the sender." |
| **minisign** | Rejected on adoption. Cleanest crypto in the group, but isolated trust universe — every dev must generate a new key. Loses to SSH on the dominant criterion (reuse of existing developer key material). |
| **SSH**   | **Accepted.** Standardized in `PROTOCOL.sshsig` (OpenSSH 8.0, 2019). `ssh-keygen` ubiquitous on every modern dev OS. Reuses the SSH key the developer already trusts for repo access. Adopted by git for commit signing (2.34) and GitHub for the "Verified" badge (2022). Implementation = subprocess shell-out to `ssh-keygen`, no embedded crypto. |
| **Hybrid (SSH + minisign or SSH + GPG)** | Rejected as premature. Doubles parser/format/test/docs surface for no current user. Adoption-driven, not preventive: add a second scheme when a concrete user requests it. |

Rationale weight order:
1. Reuses developer's existing SSH key. Zero new-key generation in the
   onboarding path.
2. `ssh-keygen` is universal (macOS, all Linux distros, Windows 10+).
   No "install GnuPG first" step.
3. Smallest attack surface among schemes with existing git/GitHub
   integration (`sshsig` format is minimal; reuses OpenSSH's audited
   Ed25519/RSA pipeline).
4. Implementation = subprocess. Warden does not embed or reimplement
   any cryptographic primitive.

Residual risk: a critical CVE in `ssh-keygen -Y verify` would
compromise Warden's verify path. Same risk git carries today; accepted.

### 2. Storage: single manifest at `.warden/trust/manifest.toml`

All trust state lives in one TOML file, **not** per-file sidecars.

Schema (versioned):

```toml
schema = "v1"

[[trust]]
path = "CLAUDE.md"
hash = "blake3:abcd1234..."
signer = "SHA256:xyz..."
signed-at = "2026-05-25T03:14:00Z"
signature = "<base64 sshsig blob>"
reason = "optional free text"  # only present if --reason was given

[[trust]]
path = "packages/core/src/scan-mcp.ts"
# ...

[[unlock]]
path = "experimental/draft-claude.md"
reason = "draft em iteração; assinar quando estabilizar"
unlocked-at = "2026-05-25T03:00:00Z"
unlocked-by = "maumcrez@gmail.com"
```

Rules:

- **First line is `schema = "v1"`.** Single-line version discriminator;
  parsers reject any unknown major schema and fail with exit 2. Future
  schema bumps land via new ADR.
- **`[[trust]]` entries are sorted alphabetically by `path`.** Stable
  serialization makes merge conflicts syntactic (resolvable line-by-line)
  rather than semantic.
- **Field order inside each block is fixed:** `path`, `hash`, `signer`,
  `signed-at`, `signature`, optional `reason`. Stable per-block layout
  is the second half of the merge-conflict mitigation.
- **`hash` is `blake3:<hex>`**. Blake3 chosen over SHA-256 for speed
  (~5× faster on large files) and over SHA-3 for ecosystem maturity in
  Bun/Node land. The `blake3:` prefix permits future algorithm
  agility without a schema bump.
- **`signer` is the SSH key fingerprint** in `SHA256:base64` form (the
  same format `ssh-keygen -lf` emits). Not the full pubkey; the pubkey
  is in `.warden/trust/allowed_signers`.
- **`signature` is the base64-encoded sshsig blob** (the contents of
  what `ssh-keygen -Y sign` writes to `<file>.sig`, minus the
  PEM-style armor). Signing is over the byte sequence `path || hash`,
  ensuring signature reuse across paths or content swaps is detectable.

Storage choice (manifest vs per-file `.sig`): manifest wins on the
single criterion that drove the decision — **explicit hash declaration
makes drift a first-class finding category**, not an implicit failure
mode. A per-file `.sig` validates or fails to validate against current
file bytes with no in-band assertion of "the bytes the maintainer
intended" — drift becomes invisible to a diff reviewer. The manifest
declares `hash = H` explicitly; verify compares filesystem hash to
declared hash and emits `trust.signature-mismatch` if they diverge,
distinct from "signature is cryptographically invalid."

Trade-off accepted: merge conflicts on parallel PRs that each add a
`[[trust]]` entry. Mitigated by alphabetical sort + fixed field order
(makes the conflict a textually trivial three-way merge in 90% of
cases). Revisit trigger: monorepo adoption pattern where conflicts
become daily pain — partition manifest by directory at that point.

The `.warden/trust/` directory contents are:

| File              | Purpose                                          | Committed? |
|-------------------|--------------------------------------------------|------------|
| `manifest.toml`   | Trust state (entries + unlocks).                 | Yes        |
| `allowed_signers` | Trust root: SSH keys whose signatures verify.    | Yes        |
| `trust-required`  | Sentinel; if present, scan enforces even without `--strict` (§6). | Yes (empty file or comment-only). |

### 3. Default behavior matrix (context-dependent)

There is no single "default behavior on invalid signature." The
correct default depends on **which command** is running and whether
`--strict` is set. The matrix:

| Context                                | Manifest absent | Unsigned file                    | Hash mismatch                       | Untrusted signer                    | Orphan entry                        |
|----------------------------------------|-----------------|----------------------------------|-------------------------------------|-------------------------------------|-------------------------------------|
| `warden scan` (no `--strict`, no sentinel) | Silent: trust not enforced. | Ignored.                  | N/A (no manifest)                   | N/A                                 | N/A                                 |
| `warden scan` (no `--strict`, manifest present) | N/A           | `trust.unsigned` **medium**. Suppressible by `unlock`. | `trust.signature-mismatch` **high**. **Not** suppressible. | `trust.untrusted-signer` **high**. **Not** suppressible. | `trust.orphan-entry` **warning** (not bloqueante). Exit 0 if sole finding. |
| `warden scan --strict`                 | Exit 2 (invocation error: `--strict` requires manifest). | `trust.unsigned` **high**. Unlock **ignored**. | **high**. Unlock ignored. | **high**. Unlock ignored. | `trust.orphan-entry` **medium**, contributes to exit 1. |
| `warden scan` (no `--strict`, sentinel present, manifest absent) | Exit 1: all walked agent-context files emit `trust.unsigned`. Sentinel makes enforcement implicit. | N/A (manifest absent is the trigger) | — | — | — |
| `warden trust verify` (no path arg)    | Exit 2.         | Exit 1 (`trust.unsigned`). Unlock honored. | Exit 1. Unlock **not** honored. | Exit 1. Unlock **not** honored. | Exit 1 (`trust.orphan-entry` becomes blocking when verify is the intent). |
| `warden trust verify <path>`           | Exit 2.         | Same as above for that path.    | Same.                               | Same.                               | If `<path>` corresponds to an orphan entry: exit 1. |

Two principles encoded in the matrix:

**Why `signature-mismatch` and `untrusted-signer` are NOT
unlock-suppressible.** Allowing unlock to suppress mismatch is
equivalent to "I forgot to re-sign, no problem" — exactly the vector
to defend against. A malicious PR could remove the `[[trust]]` entry,
add an `[[unlock]]` for the same path, and edit the file in the same
diff: the finding silences. This is the **trust-layer mirror** of the
M3.2 new-file-plus-new-marker class. We refuse to ship that surface.

**Unlock is for files that were never signed.** Not for files that
**stopped validating**. Semantic distinction, defensively load-bearing.

**Migration path.** `warden scan` on a pre-M5 repository (no manifest,
no sentinel) behaves identically to M4: trust simply does not enforce.
Adoption is opt-in until the first manifest commit, at which point the
`medium`-tier `trust.unsigned` findings begin to surface for unsigned
agent-context files. The sentinel (§6) is the explicit knob for "I
want enforcement even without `--strict`."

### 4. CLI surface

Four subcommands. All inherit Warden's "successful operations are
silent" convention (CLAUDE.md §Style).

#### 4.1 `warden trust sign <path>`

Sign a single file. Updates `.warden/trust/manifest.toml`.

- **Argument:** `<path>` — required, positional.
- **Flags:**
  - `--key <path>` — SSH private key to sign with. Default: read
    `git config user.signingkey` when `gpg.format = ssh`; else
    `~/.ssh/id_ed25519`; else `~/.ssh/id_rsa`. If none exist, exit 2
    with a message naming all paths tried.
  - `--reason "<text>"` — optional free-text annotation stored in the
    manifest entry's `reason` field.
- **CI behavior:** works headlessly when the key has no passphrase OR
  when `SSH_AUTH_SOCK` is set with an agent that holds the key. If a
  passphrase is required and neither condition holds, exit 2 with a
  message naming `SSH_AUTH_SOCK`.
- **Replacement semantics:** if a `[[trust]]` entry for `<path>`
  already exists, the new entry replaces it AND the command emits
  `warden trust sign: replacing existing entry for <path>` to stderr.
  Silent overwrite is rejected — re-signing is auditable.
- **Exit codes:** 0 on success, 2 on any error.

#### 4.2 `warden trust verify [path]`

Verify signatures. Read-only; never mutates the manifest.

- **Argument:** `[path]` — optional. If absent, verify every
  `[[trust]]` entry. If present, verify only that one.
- **Flags:**
  - `--allowed-signers <path>` — override the default
    `.warden/trust/allowed_signers`.
  - `--quiet` — suppress per-file output; rely on exit code only.
  - `--json` — emit `warden/trust-verify/v1` shape (see §10 wire
    format).
- **Exit codes:** 0 on full pass; 1 if any entry fails verification
  (mismatch, untrusted signer, missing signed file with `--strict`
  semantics); 2 on setup error (manifest absent, malformed,
  `allowed_signers` missing, `ssh-keygen` not on PATH).
- **CI behavior:** offline-pure. No network, no TTY. Verify is the
  command CI workflows invoke.

#### 4.3 `warden trust list`

Read-only inventory of the manifest.

- **Argument:** none.
- **Flags:**
  - `--json` — structured output (`warden/trust-list/v1`).
  - `--verify` — run verify on each entry and add a `status` column
    (`ok`, `mismatch`, `untrusted-signer`, `missing-file`).
- **Output:** table sorted by `path` with columns `path`,
  `hash-prefix` (first 12 hex chars of blake3 digest), `signer-short`
  (fingerprint's first 16 chars), `signed-at`, and `status` when
  `--verify` is set.
- **Exit codes:** 0; 1 if `--verify` and any entry fails; 2 on setup
  error.

#### 4.4 `warden trust unlock <path>`

Mark a path as intentionally unsigned. Suppresses `trust.unsigned`
only (per §3 matrix).

- **Argument:** `<path>` — required.
- **Flags:**
  - `--reason "<text>"` — **required**. Empty reason → exit 2.
- **Semantics:**
  - Writes an `[[unlock]]` block to the manifest with
    `unlocked-at = <UTC now ISO 8601>` and `unlocked-by` taken from
    `git config user.email` (falls back to `$USER@$HOSTNAME` when git
    config is absent).
  - **Suppresses only `trust.unsigned`.** Has no effect on
    `signature-mismatch` or `untrusted-signer` (§3 rationale).
  - **`--strict` ignores unlock entirely.** Production posture
    bypasses the escape hatch.
- **Exit codes:** 0 on success; 2 on missing/empty reason or write
  failure.

#### 4.5 `warden trust keys list`

**Read-only.** Lists the entries in `.warden/trust/allowed_signers`
plus (additively) `~/.warden/extra_allowed_signers` if present.

- **Flags:**
  - `--json` — structured output.
- **Output:** columns `principal`, `key-type`, `fingerprint`,
  `comment`, `source` (`repo` or `local`).
- **Exit codes:** 0; 2 if `allowed_signers` malformed.

**Explicitly absent: `warden trust keys add|remove`.** The trust root
file is the M5 artifact with the highest blast radius. Hiding edits
behind a CLI command creates a reflexive adoption path that bypasses
visual review of the diff (same lesson as `gh codeowner add` not
existing for `.github/CODEOWNERS`). Forcing manual edit forces visual
inspection.

#### 4.6 TTY-independence summary

| Command           | Requires TTY?           |
|-------------------|-------------------------|
| `trust sign`      | No (with key without passphrase or `SSH_AUTH_SOCK`). |
| `trust verify`    | No (pubkey-only crypto). |
| `trust list`      | No (read-only).          |
| `trust unlock`    | No (manifest write).     |
| `trust keys list` | No (read-only).          |

Every command is CI-safe. Zero interactive prompts on any path.

### 5. Trust root: hybrid model

Trust root is a **two-tier additive** file set:

- **Primary:** `.warden/trust/allowed_signers` — committed in the
  repo. Format = `ssh-keygen -Y verify`'s allowed_signers format, one
  key per line:
  ```
  rezende@example namespaces="warden" ssh-ed25519 AAAAC3Nz... rezende@laptop
  ```
- **Local extension (optional):** `~/.warden/extra_allowed_signers` —
  same format. Per-machine, never committed. Additive: a signature
  validates if its signer appears in EITHER file.

Three properties:

- `--strict` mode **ignores `~/.warden/extra_allowed_signers`**.
  Production runs only trust the repo-committed root.
- Bootstrap entry in `.warden/trust/allowed_signers` is the project
  maintainer's SSH key (ADR 0003 §1 resolution). No vendor identity,
  no escrow.
- The `namespaces="warden"` qualifier scopes the signature to
  Warden's signing context. The same key can be used for git commit
  signing (`namespaces="git"`) without cross-tier confusion.

Trust-root model rationale:

| Model                          | Cloneable? | New-key-in-PR defense | Onboarding |
|--------------------------------|------------|------------------------|------------|
| Local-only (`~/.warden/...`)   | No (CI needs secrets management) | Total (root not in repo) | Painful (first-clone fatal) |
| Repo-only (`.warden/trust/...`) | Yes        | None at tool layer (governance only) | Easy |
| **Hybrid (chosen)**            | Yes        | None at tool layer (same as repo-only) | Easy + flexible solo-extension |

The new-key-plus-payload-in-PR cenário is the **trust-layer mirror**
of M3.2's new-file-plus-new-marker (ADR 0010 §"new-file-plus-new-marker").
Same defense posture applies: governance, not tool. M5 mitigations:

- `.github/CODEOWNERS` gains entries for `/.warden/trust/`,
  `/.warden/trust/allowed_signers`, `/.warden/trust/manifest.toml`.
- `CLAUDE.md` §"What NOT to Touch Without Asking" adds
  `/.warden/trust/*`.
- This ADR (§5.6 of the threat model below) names the limitation
  explicitly.
- ISSUES #006 tracks the deferred technical mitigation (Sigstore,
  threshold trust; TOFU rejected).

### 6. Sentinel: `.warden/trust-required`

An empty (or comment-only) file at `.warden/trust-required`,
committed. When present:

- `warden scan` (no `--strict`) treats trust as enforced even if no
  `--strict` flag is passed: missing manifest → exit 1 with all
  walked agent-context files as `trust.unsigned` high.
- Cheap insurance against accidental or malicious deletion of
  `.warden/trust/manifest.toml`. Without the sentinel, the
  matrix from §3 treats missing-manifest as "trust not enforced,"
  which is the right default for migration but the wrong default for
  a repo that has explicitly adopted trust.

The sentinel is the **opt-in commitment marker**. A repo without it
gets the friendly migration path; a repo with it tells Warden "trust
state is load-bearing here; treat its absence as an alarm."

The sentinel file's contents are ignored. Convention: a single
comment line explaining when the sentinel was added.

### 7. Marker × signature interaction (orthogonal in mechanics,
correlated in risk-scoring)

Marker (ADR 0010) and signature (this ADR) address **different
threats** and are mechanically independent. The full interaction
matrix:

| # | Marker             | Signature       | Result                                                        |
|---|--------------------|-----------------|---------------------------------------------------------------|
| 1 | `payload-fixture`  | absent          | Marker suppresses detector findings. Trust finding fires if manifest present. |
| 2 | `payload-fixture`  | valid           | Marker suppresses detector findings. Trust passes. Clean.     |
| 3 | broad (`rules-data` or `detector-test`) | absent | All detector findings suppressed. Trust `unsigned` finding fires at **HIGH** (see risk-scoring nuance below). |
| 4 | broad              | valid           | Detector suppressed + trust passes. Clean.                    |
| 5 | no marker          | absent          | Detectors run normally. Trust `unsigned` fires.               |
| 6 | no marker          | valid           | Detectors run normally. Trust passes.                         |

**Risk-scoring nuance (rows 3 and 4).** When trust is enabled (manifest
present), files carrying a **broad-scope** marker (`rules-data`,
`detector-test`) that are unsigned receive `trust.unsigned` at
**HIGH** instead of medium. Same elevation applies to
`trust.signature-mismatch` on a broad-marker file.

Rationale: a broad-scope marker is an explicit "I disable detection in
this critical file" declaration. Pairing that with "not signed yet" (or
"signed but bytes changed") is **risk inflation** — exactly the
intersection where silent tampering causes the most damage (rule data
swapped → broken detector; detector test swapped → silent regression).

This is **not** trust-as-prerequisite-for-marker. Markers still work
without signatures (§7.1 below). It is correlated severity scoring
between two **independent** axes; the axes themselves remain
mechanically orthogonal.

Narrow-scope markers (`trapdoor-unicode`, `prompt-injection-pattern`,
`mcp-config`) do **not** get elevated. The universe of narrow-marker
files is the fixture corpus, where unsigned is the expected default.

#### 7.1 Trust is NOT a prerequisite for broad-scope markers

Argument-for (steelman): if a broad-scope marker required a valid
signature from a trusted key, the new-file-plus-new-marker class
(ADR 0010) gains a technical gate.

Rejected because:

- An attacker with write access to `packages/rules/src/data/` is a
  contributor with repo write access; they almost certainly also
  have an SSH key in `allowed_signers`. Marginal barrier near zero.
- UX cost is high: every edit to fixture data forces re-sign. Continuous
  friction for null defense.
- The correct defense for ISSUES #002 (new-file-plus-new-marker) is
  pattern-aware suppression or file allowlist, not signing. Trust is
  the wrong layer.

**Markers and trust stay strictly orthogonal at the mechanism level.**
Risk-scoring correlation is the only coupling.

#### 7.2 Marker + signature are complementary, not redundant

- **Marker** = "fixture intentional; detector that fires here is a
  false positive." Covers noise.
- **Signature** = "these exact bytes are the ones the maintainer
  approved at timestamp T." Covers tampering.

An unsigned fixture can be post-merge tampered with. A signed file
without a marker still emits detector noise from contained patterns.
Layers compose cleanly with no redundancy.

#### 7.3 Walker excludes `.warden/trust/`

`packages/core/src/walk.ts` excludes `.warden/trust/` from scan by
default, same posture as `.git/`. Without this exclusion the
manifest's hash fields (base64 → false-positive for credential
detection) and reason fields (free text → potential prompt-injection
match) would self-trigger findings.

Verify reads the manifest as data; it never feeds the manifest into
detectors.

### 8. Abstraction: `Signer` / `Verifier` interfaces for testability only

`packages/core/src/signer.ts` defines two interfaces:

```ts
interface Signer {
  sign(path: string, content: Uint8Array, key: string): Promise<Signature>;
}

interface Verifier {
  verify(
    path: string,
    content: Uint8Array,
    signature: Signature,
    allowedSigners: string,
  ): Promise<VerifyResult>;
}
```

Single concrete implementation: `SshSigner` / `SshVerifier`, each a
thin wrapper that shells out to `ssh-keygen -Y sign|verify`. The
interface exists **for testability** — a `MockSigner` in tests
returns deterministic fixtures without invoking `ssh-keygen` in CI.

**This is not multi-scheme groundwork.** The interface signature is
shaped around what SSH needs (path, content, key file path). Adding a
second scheme (Sigstore, minisign) would require revisiting the
contract. M5 commits to one scheme; the abstraction is purely a
unit-test seam.

Dependency injection is via constructor, no runtime polymorphism, no
plugin registry.

### 9. Onboarding UX

Two complementary mechanisms:

- **Inline hints in error messages.** Every error mode emits a
  one-line stderr message naming the fix command. Examples:
  - `CLAUDE.md: trust.signature-mismatch — to re-sign, run: warden trust sign CLAUDE.md`
  - `trust sign: no SSH key found at ~/.ssh/id_ed25519 — generate one with: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519`
  - `trust verify: ssh-keygen not on PATH — install OpenSSH (macOS: built-in; Linux: openssh-client; Windows: enable OpenSSH client feature)`
- **`docs/USAGE-TRUST.md`** (created in M5 implementation commit)
  covers the full flow: generating a key, adding to allowed_signers,
  first sign, onboarding a new contributor, troubleshooting CI/agent
  setup.

No interactive wizard. CLAUDE.md §Style requires successful operations
to be silent; error messages carry the wizard's content as one-shot
hints.

### 10. CI integration

M5 documents the workflow inline in `docs/USAGE-TRUST.md` §CI:

```yaml
- name: Verify Warden trust
  run: bunx warden trust verify --strict
```

A reusable `warden-sh/trust-verify-action` template is **deferred to
v1.0**. The action template ships with the GitHub-org migration tracked
in ADR 0004; until then, the inline workflow above is the supported
integration.

**Wire formats** for `--json` outputs (versioned via discriminator,
same pattern as `warden/scan/v2`):

- `warden/trust-verify/v1` — verify result per entry, summary counts,
  setup-error details.
- `warden/trust-list/v1` — sorted entries, signer fingerprints,
  optional verify status when `--verify` flag is passed.

Future field additions are absorbed within v1 (additive only); a v2
bump requires a new ADR.

---

## Threat model — M5-specific scenarios

Each cenário with Warden's response. "Not detected" entries are
honest about what M5 leaves out; out-of-scope items follow the same
posture as ADR 0011's "Known limitations" section.

| ID    | Cenário                                            | Detected? | Defense                                       |
|-------|----------------------------------------------------|-----------|-----------------------------------------------|
| M5-T1 | `.warden/trust/` deleted entirely                  | Partial   | Sentinel (§6) + CODEOWNERS + commit signing.  |
| M5-T2 | Manifest swapped with valid sigs over malicious bytes | No     | Out-of-scope: key or contributor compromise.  |
| M5-T3 | Signature entry for one file removed in a PR       | Yes       | `trust.unsigned` fires; CODEOWNERS on manifest forces review of removal-plus-unlock subcase. |
| M5-T4 | Signed file modified post-sign                     | Yes       | `trust.signature-mismatch` HIGH; canonical tampering case. |
| M5-T5 | Sign attempt with key not in `allowed_signers`     | Yes       | `trust.untrusted-signer` HIGH.                |
| M5-T6 | Trust root file (`allowed_signers`) substituted    | No        | Governance: CODEOWNERS + CLAUDE.md; technical fix deferred → ISSUES #006 (Sigstore). |
| M5-T7 | Legitimate contributor edits and forgets to re-sign | Yes (CI) | `trust.signature-mismatch` in CI; inline hint cites fix command. |
| M5-T8 | TOCTOU between verify and agent read               | No        | Out-of-scope: Warden is static-and-offline, not an EDR. |

The table above is the durable specification.

### 5.6 expanded — trust-root substitution

Out-of-scope at the tool layer **by the same logic as M3.2's
new-file-plus-new-marker** (ADR 0010 §"new-file-plus-new-marker").
Both are: attacker adds key/marker + payload in the same PR; both
diffs are syntactically valid; tool cannot distinguish "legitimate
new maintainer adding their key" from "attacker adding their own key
to whitewash a payload."

Active mitigations: CODEOWNERS on `.warden/trust/allowed_signers`,
CLAUDE.md guidance, code review.

Deferred technical mitigations: ISSUES #006 (Sigstore identity-bound
signing, threshold trust). **TOFU explicitly rejected** as a candidate
— it is the disease, not the cure (the `~/.ssh/known_hosts` history
shows TOFU degrades to blind acceptance precisely at key-rotation
moments).

### Citation policy

M5's threats (trust-root substitution, manifest swap, signed-file
tampering) are **applied-cryptography fundamentals** without
single-CVE attribution. THREAT_MODEL.md §"Citation Policy" requires
primary-source citations for **detection rules**; structural threats
are documented via ADRs (this one, ADR 0010, ADR 0011) without an
external CVE. Same framing as ADR 0010 §"Open after M3.1" and ADR
0011 §"Known limitations."

---

## Non-goals (explicit out-of-scope)

| Item                                | Why not in M5                                  |
|-------------------------------------|------------------------------------------------|
| Automatic key rotation              | Rotation is org policy; M5 supports manual `allowed_signers` edit + re-verify. Automation = v1.0. |
| CRL / revocation lists              | Stateful and heavy. Remove key from `allowed_signers` instead. Old sigs continue to verify against current trust state — correct posture. |
| Signature expiration                | `ssh-keygen -Y sign` lacks native expiration without certificate wrapping. Add parser complexity for negative value. Remove-from-allowed_signers handles intent organically. |
| Multi-signature M-of-N (threshold)  | High-value for trust-root edits; complexity (quorum designation, transition semantics, partial recovery) out of proportion for M5 maintainer count. Tracked in ISSUES #006. |
| Hardware-token (YubiKey/Nitrokey) workflows | `ssh-keygen -t ed25519-sk` works for free via SSH path. Dedicated touch-policy / FIDO2 attestation support is out of M5. |
| Signing of non-agent-context files  | Out of scope. Use git-sign / gpg-sign for general repo content. |
| Lost-key recovery                   | "Team agrees on new key, edits the file." Same as losing SSH access. Not Warden's problem. |
| Manifest encryption                 | Manifest contents (hashes, signatures) are public by design. Encryption adds key-management complexity for zero security gain. |
| Web-of-trust / endorsement chains   | Trust root is flat. Chains belong in Sigstore (ISSUES #006). |
| Telemetry of sign/verify usage      | CLAUDE.md §Anti-Patterns: no telemetry, ever, in the OSS core. |
| `.warden.toml` config schema        | Deferred to v1.0 (also blocks ISSUES #005). M5 uses CLI flags only. |
| Reusable GitHub Action template     | Deferred to v1.0 alongside the github-org migration (ADR 0004). |

---

## Fixtures

The M5 implementation commit (`eec31a4`) produces a fixture pack under
`tests/fixtures/trust/`:

- `signed-clean/` — small `CLAUDE.md` with a valid `[[trust]]` entry.
  Verify passes, exit 0.
- `signature-mismatch/` — same `CLAUDE.md` content modified by one
  byte after sign. Verify emits HIGH, exit 1.
- `untrusted-signer/` — entry signed by a key NOT in
  `allowed_signers`. Verify emits HIGH, exit 1.
- `unsigned-with-manifest/` — manifest present but no entry for the
  scanned file. Scan emits medium; verify exits 1.
- `unsigned-with-unlock/` — file unsigned but covered by `[[unlock]]`.
  Scan exits 0 (suppressed); strict scan exits 1 (unlock ignored).
- `orphan-entry/` — `[[trust]]` exists, on-disk file absent. Scan
  emits warning (exit 0 if sole finding); verify exits 1.
- `sentinel-no-manifest/` — sentinel file present, manifest absent.
  Scan exits 1 even without `--strict`.

**Note (M5 calibration):** the broad-marker + unsigned risk-scoring
rule (§7) is exercised by a unit test
(`packages/core/tests/trust-scan.test.ts → "broad-marker + unsigned →
trust.unsigned elevated to HIGH"`) rather than a filesystem fixture,
because the `rules-data` marker is path-restricted to
`packages/rules/src/data/**` by ADR 0010 §3. A fixture under
`tests/fixtures/trust/broad-marker-unsigned/` would be rejected by the
marker parser at exit 2. The unit test instead constructs the
broad-marker + unsigned state in-memory (via `TrustFileInput`'s
`hasBroadMarker: true`) and asserts the elevation to HIGH. The
fixture-pack count drops from 8 to 7 with the §7 interaction fully
covered.

Each fixture's `[[trust]]` entries are signed by Warden's bootstrap
maintainer key (ADR 0003 §1 resolution). A `MockSigner` covers the
unit-test layer; the fixture pack exercises the real `ssh-keygen`
path through CI.

---

## Consequences

**Positive:**

- Warden gains a first-class trust expression for agent context. Drift
  becomes a categorical finding, not an implicit failure.
- SSH-only crypto means no embedded cryptographic primitive in
  Warden's TypeScript source. Audit surface is OpenSSH (already
  audited at scale) plus a TOML parser plus a shell-out.
- Manifest-as-source-of-truth makes future Team-tier features (shared
  trust roots, signed trust-root distribution) tractable in v1.0
  without redesigning storage.
- ADR 0003 closes after being deferred. `ROADMAP.md §M5`,
  `ARCHITECTURE.md`, `README.md`, and `PRD.md` are rewritten from
  "GPG-based" to "SSH signatures" in the same commit, so the
  governance docs share a consistent view at every SHA.

**Negative:**

- Merge conflicts on parallel-sign PRs require manual resolution.
  Alphabetical sort + fixed field order mitigates ~90%; the remaining
  10% is a textual conflict in a stable position.
- Trust-root substitution (M5-T6) is governance-defended, not
  tool-defended. Same posture as ISSUES #002, but at a higher blast
  radius. Honestly named in §5.6 and ISSUES #006.
- Adoption is now opt-in (sentinel) but a real default for new repos
  is still TBD. M5 documents the path; M6+ will revisit if onboarding
  data shows trust adoption stalls.

---

## Revisit triggers

Reopen this ADR if any of:

- Real adoption surfaces a workflow where merge conflicts on the
  manifest are daily pain → partition the manifest by directory.
- A second user requests a second crypto scheme with a concrete use
  case (e.g., Sigstore for enterprise non-repudiation) → revisit §1
  and the `Signer`/`Verifier` interface.
- OpenSSH ships a critical CVE in `ssh-keygen -Y verify` → temporarily
  document the patch posture; long-term, this is the same risk git
  carries.
- The "trust as prerequisite for broad marker" question reopens with
  a real attack scenario → revisit §7.1.
- ISSUES #006 resolves (Sigstore or threshold trust ADR lands) → this
  ADR's §5 and §5.6 update to reflect the new technical defense.
