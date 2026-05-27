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

## #002 — Broad-scope marker families lack explicit file allowlist

**Status:** open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M3.1 review, see ADR 0010 §"Open after M3.1"

Broad-scope marker families (`rules-data`, `detector-test`) currently
restrict to a directory regex, not an explicit file list. A PR that adds
both a new file under the restricted directory AND a marker on the first
line of that new file creates a scanner dead zone, defended only by code
review.

Resolution path: either (a) replace regex restriction with explicit
file allowlist in `packages/core/src/marker.ts`, OR (b) implement
pattern-aware suppression where marker declares specific literal
substrings to suppress, anything else fires. Decision pending real-world
attack data or M4 MCP fixture requirements.

Tracker: revisit when a second broad-scope family is proposed, or when
the repo goes public and CODEOWNERS becomes enforceable.

Sub-task: the M3.2 `.github/CODEOWNERS` file references
`@warden-sh/maintainers` as a placeholder team handle. The final
team/handle is pending the public-repo / GitHub-org decision tracked
in ADR 0004. When that resolves, update CODEOWNERS in the same PR
that flips ADR 0004 from "tentative" to "accepted".

## #003 — MCP config path discovery coverage gaps

**Status:** open
**Milestone:** pre-1.0
**Severity:** low
**Origin:** M4 review

Warden's MCP config detection (`packages/core/src/detect-format.ts`)
covers three patterns by basename or path segment:

- `mcp.json` (any depth)
- `claude_desktop_config.json` (any depth)
- `.cursor/mcp.json` (path segment)

Known gaps (not detected by default):

- `.mcp/config.json` — alternative convention in some setups
- `.vscode/mcp.json` — VS Code MCP convention (recent)
- `.codeium/windsurf/mcp_config.json` — Windsurf-specific
- User-global configs at `~/.cursor/mcp.json`,
  `~/Library/Application Support/Claude/claude_desktop_config.json`,
  `~/.codeium/windsurf/mcp_config.json` — only scanned when the user
  passes the path explicitly (correct privacy stance, intentional)

Resolution path: add the three repo-local patterns to
`detect-format.ts` when usage data confirms prevalence. User-global
config scanning stays opt-in via explicit argument; do not change
default behavior to walk the home directory.

## #004 — MCP tool description scanning not implemented as dedicated rule

**Status:** open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M4 review

The MCP tool poisoning vector (malicious tool description injected via
`tools/list` protocol response at runtime, or inline in config) is
explicitly out of scope for static MCP analysis per ADR 0011 §2 —
runtime tool poisoning requires spawning the server, which violates
the no-exec invariant.

The inline-in-config subcase (config declares `tools[].description` or
similar text fields) is partially covered by collateral scanning:
`scan-path.ts` runs `scanUnicode` and `scanPromptInjection` on the raw
JSON content before `scan-mcp.ts` runs structural analysis. A
description containing override-prior-context phrasing or invisible
Unicode fires as a prompt-injection or Unicode finding on the MCP file
(not as an MCP finding). This is defense-in-depth by design, but not
by dedicated MCP rule.

Decision: track as known gap. Do not add a dedicated MCP rule for
description fields yet — risk of duplicate findings (one
prompt-injection + one MCP) without clear severity tier. Revisit when
(a) real MCP description-injection attacks surface publicly, or
(b) M5 trust-signing proposes signed-config semantics that need this
category formally.

## #005 — MCP http-transport-external rule does not differentiate transport types

**Status:** partially unblocked by M8 — `.warden.toml` schema v1 now exists; transport-tier tiering remains open
**Milestone:** pre-1.0
**Severity:** medium
**Origin:** M4 review

The rule `mcp.http-transport-external`
(`packages/rules/src/data/mcp.ts`) fires HIGH for any non-loopback
URL, regardless of transport type (`http`, `sse`, `streamable-http`).
This produces high false-positive rates for developers using
legitimate remote MCP servers via SSE (Anthropic reference servers,
GitHub MCP, fetch-mcp at user-controlled endpoints).

Threat profile differs by transport:

- `stdio` — typosquatting risk on command/args (covered by separate
  rules `mcp.command-not-pinned` and
  `mcp.absolute-path-untrusted-binary`)
- `sse` — replay attacks, URL spoofing; risk is domain-trust dependent
- `streamable-http` — stream hijacking + SSE risks

Resolution path: introduce transport-aware tiering. Suggested split:

- INFO for any documented MCP at any remote endpoint
- MEDIUM for unsigned remote endpoints
- HIGH for non-loopback endpoints not in a user allowlist
  (`.warden.toml` declares allowed domains)

**Status update (M8):** the blocking dependency on `.warden.toml`
landed with ADR 0015 §6 — the v1 schema now exists with an `[ioc]`
section. Adding an `[mcp]` section with transport-tier overrides is a
mechanical follow-up. The remaining work is the rule-tiering decision
itself (INFO vs MEDIUM vs HIGH per transport), which has not changed
substance since M4 review. Until then, users can suppress the rule
per-file via marker if the false-positive rate is unacceptable.

## #006 — Trust root lacks external anchor / pinning model (deferred to v1.0)

**Status:** open
**Milestone:** v1.0
**Severity:** medium
**Origin:** M5 planning (see ADR 0012 §6.4 and ADR 0003 resolution §3)

M5 trust signing (ADR 0012) commits the SSH `allowed_signers` file
inside the repo at `.warden/trust/allowed_signers`. This is the
**modelo CODEOWNERS** of trust roots: cloneable, CI-friendly, diff-visible
— but vulnerable to the structural attack class M3.2 named
"new-file-plus-new-marker." In the trust layer the equivalent is
**new-key-plus-payload-in-same-PR**: an attacker with PR access submits
a diff that (a) adds their SSH public key to `allowed_signers` and (b)
adds a signed payload signed by that same key. Both diffs are
syntactically valid. The technical gate passes; only code review
distinguishes legitimate from malicious.

Active mitigations (in M5):

- `.github/CODEOWNERS` entries for `/.warden/trust/`,
  `/.warden/trust/allowed_signers`, and `/.warden/trust/manifest.toml`
  force maintainer review on any change to the trust root.
- `CLAUDE.md` §"What NOT to Touch Without Asking" lists
  `/.warden/trust/*`.
- ADR 0012 §5.6 names the limitation explicitly with the same framing
  as ADR 0010's `new-file-plus-new-marker` subcase.

Same governance posture as ISSUES #002. The trust root is defended by
process, not by tool — and M5 documents this honestly rather than
pretending otherwise.

Resolution path (three candidates, ranked by likelihood of adoption):

1. **Sigstore identity-based signing.** Eliminates the local trust
   root as a single point of failure by binding signature → OIDC
   identity (e.g. a GitHub username) via Fulcio + Rekor. Verify
   becomes "does the signature attest to an identity in our allowed
   set?" rather than "is the signing key in our allowed_signers file?"
   Cost: requires network at verify time (Rekor transparency log
   lookup), OIDC plumbing in CI, and a new ADR specifying identity
   matching semantics. Most likely path.
2. **Threshold trust (M-of-N).** Mudanças em `allowed_signers`
   requerem N signatures de maintainers existentes. Resolve no nível
   estrutural correto — atacante precisaria comprometer N chaves
   simultaneamente. Cost: enorme — designar quorum, semantics de
   transição, recovery parcial, fora de proporção para o tamanho
   atual do projeto. Considerar quando time de maintainers crescer
   além de 2-3.
3. **TLOG-pinning sem Sigstore completo.** Append-only log local de
   mudanças em `allowed_signers` assinado por chave separada. Híbrido
   entre as duas anteriores. Sem precedente conhecido para validar
   custo/benefício.

**Explicitly rejected, not deferred:**

- **TOFU + URL pinning** (modelo `~/.ssh/known_hosts`). O histórico
  de `known_hosts` mostra que TOFU vira aceitação cega no momento de
  upgrade ou rotação de chave — exatamente o cenário em que o
  pinning deveria proteger. É a doença, não a cura. Não merece
  espaço no roadmap mesmo como opção deferida.

Tracker: revisit when (a) a first user with enterprise-grade
non-repudiation requirements appears, or (b) the project gains a third
active maintainer (threshold trust becomes practical), or (c) a real
new-key-plus-payload attack lands publicly in the OSS ecosystem.

## #007 — Cursor adapter has no credential-write coverage

**Status:** open
**Milestone:** post-1.0 (blocked on upstream Cursor change)
**Severity:** medium
**Origin:** M7 / ADR 0014 §§5, 9

Cursor 1.7+ exposes `beforeReadFile` and `beforeShellExecution` but no
`beforeFileEdit` / `beforeFileWrite` event. The only file-write-side
event is `afterFileEdit`, which fires after bytes are on disk and is
documented as fire-and-forget (no decision field, no return shape).

Consequence: an agent on Cursor instructed to write a credential-shaped
file via the agent's built-in Edit / Write tool (e.g.,
`Edit ~/.aws/credentials`) is **not** blocked at the hook layer. The
M6 Claude adapter covers the equivalent path because
`PreToolUse` fires on Edit / Write / MultiEdit. The
`hooks.credential-file-read` rule's `evaluate` function already accepts
`tool === 'edit'` or `'write'` — the gap is at the event surface, not
at the rule.

Sub-vectors covered by other Cursor events even without a pre-write
hook:

- `Bash echo … > ~/.ssh/id_rsa` → caught by `beforeShellExecution`.
- `Bash openssl … -out ~/.aws/credentials` → caught.
- Any shell-driven write → caught.

Sub-vectors uncovered:

- Direct Cursor-native `Edit` against a credential path.
- Direct Cursor-native `Write` against a credential path.

Resolution path: monitor the Cursor changelog for a pre-write event.
When one lands, extend `packages/hooks-cursor/src/install.ts`
`WARDEN_EVENTS` and `packages/hooks-cursor/src/interceptor.ts`
`buildView` to handle it. The rule pack itself needs no change.

Tracker: re-check the Cursor docs (`https://cursor.com/docs/hooks`)
quarterly until either a pre-write event ships or two release cycles
pass without one — at the second cycle, reopen the design question
("what is the right cooperative-defense alternative for write-side
coverage?") rather than continuing to wait.

## #008 — Cursor built-in tools may not all surface through hooks

**Status:** open
**Milestone:** post-1.0
**Severity:** low
**Origin:** M7 / ADR 0014 §"Sources" — Cursor community-forum thread on
PreToolUse + built-in Web Search

Cursor's documented hook events (`beforeReadFile`,
`beforeShellExecution`, `beforeMCPExecution`) cover the agent's main
tool-call surface, but at least one built-in tool (Web Search) has
been observed to fire none of them. There is no documented exhaustive
list of which built-in tools surface through hooks and which do not.

Consequence: a built-in tool that does not surface through hooks is
invisible to Warden by construction. The agent could, hypothetically,
have a future built-in tool that reads files or executes shell
without firing the documented hook events. Today's coverage of Read
(via `beforeReadFile`) and Bash (via `beforeShellExecution`) is
confirmed by the published docs; we cannot enumerate which other
built-ins might be silent.

Resolution path: track Cursor's release notes for new built-in tools
and whether they surface through hooks. When a credential-relevant
built-in is found to be silent, raise an upstream feature request and
document the gap here.

Tracker: revisit on every Cursor minor-version release that adds a
new agent tool category.

---

## #009 — Lockfile coverage gaps: yarn v1, pnpm-lock.yaml, bun.lockb

**Status:** open
**Milestone:** post-MVP
**Severity:** medium
**Origin:** M9 / ADR 0016 §1, §9 non-goals

M9 ships lockfile scanning for npm `package-lock.json` v2/v3, PyPI
`poetry.lock` + `uv.lock`, and Cargo `Cargo.lock`. Several common
lockfiles were explicitly deferred:

- **`yarn.lock` v1** — bespoke text format, needs a dedicated parser.
- **`pnpm-lock.yaml`** — YAML + virtual-store layout; its own design
  pass.
- **`bun.lockb`** — binary, unstable format. Deferred indefinitely
  unless Bun publishes a stable spec.
- **`requirements.txt`** — not a real lockfile; accepts ranges. A
  pinned-only subset would mislead users into thinking ranged entries
  were checked.
- **`Pipfile.lock`** — pipenv usage declining; revisit if fixture
  demand surfaces.

Consequence: a project that uses only yarn / pnpm / bun gets a
"clean" `warden scan` even when its pinned dependencies match known
OSV advisories. Honest framing in the README + threats table
(`supply-chain.osv-known-vulnerability` cites the exact ecosystems
covered).

Resolution path: each format is its own milestone (M9.1+ candidates).
Per-ecosystem parser + per-ecosystem direct/transitive detection
strategy. PEP 440 parser already shipped (M9) is reusable for
`requirements.txt` if its semantics ever justify inclusion.

Tracker: revisit when a real user reports a missed advisory because
they only have an unsupported lockfile, or when a high-profile
yarn-only / pnpm-only project is compromised.

---

## #010 — Supply-chain severity modulation ignores dev vs prod dependencies

**Status:** open
**Milestone:** post-MVP
**Severity:** low
**Origin:** M9 / ADR 0016 §4, §9 non-goals

ADR 0016 §4 modulates `supply-chain.osv-known-vulnerability` severity
by **position** (direct vs transitive) but **not** by **stage** (prod
vs dev). A CVE in a direct devDependency emits the same severity
tier as a CVE in a direct prod dependency.

Argument for the deferral: dev vs prod classification requires the
manifest reader to walk `devDependencies` (npm), `[tool.poetry.group.*.dependencies]`
(poetry), `[dev-dependencies]` (cargo) — each with its own quirks —
and the runtime impact differential is debatable for many dev tools
that ship into production CI environments anyway.

Argument for revisiting: long dev-dep trees (test runners, linters,
build tooling) can swamp `info`/`low` output on dev-heavy projects.

Resolution path: if M9 produces actionable dev-tree noise in real-
world reports, add a `stage: 'dev' | 'prod'` field on
`LockfileEntry` and modulate severity one tier down for dev.

Tracker: revisit when a Warden user reports turning off
`supply-chain.*` because of dev-noise.

---

## #011 — `info` severity tier needs governance to avoid degradation

**Status:** open
**Milestone:** post-MVP
**Severity:** low
**Origin:** M9 / ADR 0016 §Consequences

ADR 0016 §4 added the `info` severity tier system-wide, scoped (by
intent) to the `supply-chain.osv-known-vulnerability` rule's transitive
LOW case. Risk named in ADR 0016 §Consequences: future detector
authors over-use `info` to avoid hard severity calls, gradually
hollowing out the `low` tier.

Today the rule is informal — "`info` outside `supply-chain.*` needs
explicit ADR justification" lives in ADR 0016 §Consequences as prose,
not as a code-level guard or a CONTRIBUTING.md check.

Resolution path: when `CONTRIBUTING.md` is formalized (the doc is
still pending — see [`README.md` §Status]), add an explicit rule
that new rules emitting `info` outside `supply-chain.*` require a
dedicated ADR. Until then, this issue is the trail.

Tracker: revisit if a second `info`-emitting rule is proposed
without an ADR.

---

## #012 — `--strict` does not treat a stale IOC cache as an error

**Status:** open
**Milestone:** post-MVP
**Severity:** low
**Origin:** M9 / ADR 0016 §5

ADR 0016 §5 cache-state matrix:

| State    | Default mode               | `--strict` mode                    |
|----------|----------------------------|-------------------------------------|
| Absent   | Skip + stderr warn         | Exit 2 (config error) before scan   |
| Fresh    | Run normally               | Run normally                        |
| **Stale** (≥7d)  | **Run + stderr warn**      | **Run + stderr warn** (same)        |

A user running `warden scan --strict` against a stale cache gets
the warning but the scan still runs against possibly-outdated
advisories. Defensible default (better stale data than no data),
but `--strict` arguably should be "no degraded state tolerated."

Resolution path: when `.warden.toml` config schema lands (v1.0; see
ISSUES #005), add a `[ioc].strict_treats_stale_as_error = true`
opt-in. CI pipelines that wire `warden ioc sync` before every scan
would set this to fail-closed on cache freshness.

Tracker: revisit when a Warden user reports a missed CVE because
their CI cache was 30 days old and nobody noticed.

---

## #013 — No per-advisory allow-list for supply-chain findings

**Status:** open
**Milestone:** post-MVP
**Severity:** low
**Origin:** M9 / ADR 0016 §Consequences

The only way to suppress a `supply-chain.osv-known-vulnerability`
finding today is the `supply-chain-fixture` payload-fixture marker,
which suppresses **all** supply-chain findings in scope (file or
line-range). There is no "I accept the risk of advisory X for
package Y because Z" granular escape hatch.

Consequence: a CI pipeline on a dependency-heavy project that runs
`warden scan --strict` (which escalates `info` to a gate) and hits
a transitive LOW advisory that the team accepts has only two
options:

1. Drop the strict flag (gives up gating on real high-severity
   findings).
2. Apply a `supply-chain-fixture` marker that suppresses every
   supply-chain finding on the file (gives up gating on future
   advisories that appear in the same lockfile).

Both are blunt.

Resolution path: design a separate `.warden/supply-chain-allow.toml`
(mirroring `.warden/hooks/allow.toml` from M6) with `[[allow]]`
blocks keyed by `{ ecosystem, packageName, advisoryId, reason }`.
Verbose mode prints the list. CODEOWNERS protects the file like
`.warden/trust/`.

Tracker: revisit when the first Warden user files a feature request
to allow-list a specific advisory.
