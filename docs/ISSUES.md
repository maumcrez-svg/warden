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

**Status:** open
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

Decision deferred: requires a `.warden.toml` config schema, which is a
v1.0 concern. Until then, users can suppress the rule per-file via
marker if the false-positive rate is unacceptable.

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
