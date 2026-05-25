# ADR 0013 — Claude Code PreToolUse hook adapter (M6)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M6 design pass
**Threat:** T5 (agent-tool credential exfiltration; added to `docs/THREAT_MODEL.md` in the same commit)
**Extends:** `docs/ARCHITECTURE.md` §2 (`packages/hooks-claude` package boundary), §4 (cold-path)

---

## Context

M1-M5 built the at-rest detection surface: invisible Unicode, prompt
injection, MCP-config static analysis, and signature-based trust. All
four operate on bytes a developer wrote to disk *before* the agent
runs.

M6 closes the remaining gap. After all four detectors pass — or even
just don't run at all on the project the agent is operating in — the
agent itself can still be instructed to read a credential file, or
shell out to one, *at runtime*. The triggering instruction can come
from a context file Warden never saw (a fresh `~/.claude/CLAUDE.md`,
an MCP description fetched from a remote server, a user typing the
attack themselves), so we cannot solve this by adding more file-at-rest
rules.

The remaining choke point is the agent's own tool-call boundary.
Claude Code exposes a `PreToolUse` hook event (documented at
`https://docs.anthropic.com/en/docs/claude-code/hooks`, verified
2026-05-25) that fires after the agent has decided to call a tool but
before the tool actually runs. The hook receives a structured JSON
payload on stdin including `tool_name` and `tool_input`, and it can
short-circuit the call by exiting non-zero or by emitting a
`{"decision":"block","reason":"..."}` JSON document on stdout.

That contract is the M6 surface. The threat ID is **T5**.

---

## Decision

### 1. New package `packages/hooks-claude`, depends on `core` and `rules`

The hook adapter is its own package because:

- It has a CLI entry distinct from `warden scan` — the runtime hook is
  invoked by Claude Code, not by a human. Lifting it into `cli` would
  conflate two binaries.
- It depends on `packages/core` (path normalization, allowlist parser
  primitives) and `packages/rules` (the credential rule data) but
  nothing else. Same dependency posture as `packages/hooks-cursor`
  will have when its milestone lands.

The same package houses the **installer** (writes `~/.claude/settings.json`
and the wrapper script) and the **interceptor** (the runtime function
that classifies tool calls). They share the credential rule data and
allowlist format, so co-locating them keeps the test surface coherent.

### 2. Pure interceptor function — `evaluate(input, ruleSet, allowlist)`

The runtime hot path is a single pure function:

```ts
type Decision =
  | { kind: 'allow' }
  | { kind: 'deny'; ruleId: string; reason: string };

function evaluateToolCall(
  input: ClaudeToolUseInput,
  ruleSet: CredentialRuleSet,
  allowlist: Allowlist,
  home: string,        // for ~ expansion, injected for testability
  projectRoot: string, // for path normalization
): Decision;
```

The function does **no I/O**. The CLI shim reads stdin, parses JSON,
loads the allowlist from disk if present, and calls `evaluateToolCall`.
This is the same architectural pattern the M4 MCP analyzer uses
(`scanMcp(content: string) → McpFinding[]`) and for the same reason:
the test surface is a list of input → expected decision pairs and a
dishonest implementation cannot hide behind filesystem state.

### 3. JSON contract — Claude Code PreToolUse stdin shape

The hook receives (per Anthropic's docs, verified 2026-05-25):

```json
{
  "session_id": "...",
  "transcript_path": "...",
  "tool_name": "Read" | "Bash" | "Write" | ...,
  "tool_input": {
    "file_path": "/abs/or/~/path",
    "command": "shell string",
    ...
  }
}
```

Adapter behavior:

| `tool_name`        | What the adapter inspects        |
|--------------------|----------------------------------|
| `Read`             | `tool_input.file_path`           |
| `Edit`, `Write`    | `tool_input.file_path` (same blocklist — writing a credential file the agent didn't already see is just as suspicious) |
| `Bash`             | `tool_input.command` (full shell string, tokenized) |
| anything else      | allow (out of M6 scope)          |

Unknown / missing fields are treated as "allow" rather than "error":
the hook contract is cooperative, and a malformed payload almost
always means an agent version mismatch — failing the call would
strand the developer. The adapter logs the skip to stderr at a
low-prefix level (`warden hook: skipping …`) so reviewers can spot it.

### 4. Exit code policy

| Outcome    | Exit code | stdout                                | stderr                              |
|------------|-----------|---------------------------------------|-------------------------------------|
| allow      | 0         | (silent)                              | (silent)                            |
| deny       | 2         | (silent — Claude Code reads stderr)   | one-line `warden: blocked …` msg    |
| error      | 1         | (silent)                              | `warden: hook setup error: …`       |

Exit 2 is the Claude Code convention for "block and surface the
stderr message back to the agent" (per the hook docs); exit 1 is
treated as a tool error but not a block. We use 1 for adapter
configuration problems (malformed allowlist, etc.) so the developer
sees the error *and* the tool call goes through — the alternative
("block everything when our config is broken") would break the agent
session for the wrong reason.

**JSON output path (optional, mirrors Anthropic's spec):** when the
adapter is invoked with `--json-output`, it emits
`{"decision":"block","reason":"<rule>: <evidence>"}` on stdout
instead of relying on the exit-2 stderr convention. The installer
writes the hook configuration without `--json-output` by default,
preserving the stderr/exit-2 path (simpler to reason about); the JSON
path exists so future agent vendors that prefer the structured
contract can wire it in without a code change.

### 5. Credential rule data lives in `packages/rules/src/data/credentials.ts`

Three rule families, all citing T5:

- **`hooks.credential-file-read`** — high severity. Path-based block
  against the canonical credential paths: SSH private keys
  (`~/.ssh/id_*`, `~/.ssh/*_rsa`, `~/.ssh/*_ed25519`,
  `~/.ssh/*_ecdsa`, but **not** `~/.ssh/config`, `~/.ssh/known_hosts`,
  or `*.pub`), AWS credentials (`~/.aws/credentials`, `~/.aws/config`),
  GPG private keyring (`~/.gnupg/private-keys-v1.d/**`,
  `~/.gnupg/secring.gpg`), wallet files (`**/wallet.json`,
  `**/*.wallet`, `**/mnemonic*`), and project `.env` files (`**/.env`,
  `**/.env.*` excluding `*.example` and `*.sample`). Public-half files
  (`.pub`, `.example`, `.sample`) and SSH config files are explicit
  carve-outs — they are read all the time legitimately and blocking
  them would degrade the developer UX.
- **`hooks.credential-shell-read`** — high severity. Shell-pattern
  block on the same set of paths surfaced through `cat|less|more|head|
  tail|grep|od|hexdump|xxd|base64|openssl` and the egress family
  `curl|wget|scp|rsync|sftp`. Tokenization is whitespace + pipe-
  splitting; the rule is intentionally narrow (false negatives are
  acceptable because the file-path rule already covers `Read`).
- **`hooks.credential-pipe-network`** — high severity. Block on shell
  commands that read a credential path and pipe to a network command
  in the same string (e.g. `cat ~/.ssh/id_rsa | curl …`). This is the
  obvious-attack canary: a single tool call that combines both halves
  is unambiguous.

Each rule has a `citation` (OWASP LLM02:2025 + T1/T2 reports) and a
`verifiedDate`, same shape as MCP rules. Public-half carve-outs are
encoded as a separate `allowGlobs` array that takes precedence over
`denyGlobs` — the precedence is part of the rule semantics, not a
quirk of the evaluator.

### 6. Allowlist override — `.warden/hooks/allow.toml`

A project may legitimately need to read a credential path (an SDK
test that loads `~/.aws/credentials`, a deploy script invoking
`gpg --decrypt`). The override format mirrors ADR 0010's payload
markers: explicit, narrow, justified:

```toml
schema = "v1"

[[allow]]
rule = "hooks.credential-file-read"
path = "~/.aws/credentials"        # exact path or glob
reason = "ci-deploy.test.ts reads the real config to exercise STS handoff"

[[allow]]
rule = "hooks.credential-shell-read"
command-pattern = "openssl dec.*"   # regex matched against the full command
reason = "build/decrypt-stage.sh decrypts a release blob"
```

Rules:

- **`schema = "v1"` is required** as the first non-comment line, same
  pattern as `manifest.toml`. Unknown schemas → exit 1 (allowlist
  parse error) and the call goes through. Treating allowlist parse
  errors as "block" would strand the developer; we surface the error
  to stderr instead.
- **Both `rule` and at least one of `path` / `command-pattern` are
  required.** A blanket `allow.toml` with no fields would silently
  open the hook surface; we refuse such files at parse time.
- **`reason` is required and must be non-empty.** Same posture as
  `warden trust unlock --reason`: the allowlist exists so a reviewer
  can see *why* a specific path was excepted.
- **No nesting, no glob negation, no environment-variable
  interpolation.** Same minimalism the manifest parser keeps.

The allowlist lives under `.warden/hooks/` rather than `.warden/`
top-level so the trust-root governance (CODEOWNERS on
`.warden/trust/`) is unchanged. CODEOWNERS coverage of
`.warden/hooks/` is added in the same M6 commit for the same reason
trust-root edits require review.

### 7. Installer — `warden hooks install claude`

Idempotent. Inputs:

- The user's `~/.claude/settings.json` (created if missing).
- A target hook script path. By default we write to
  `~/.warden/hooks/claude-pre-tool-use.sh`, which `exec`s
  `bun /abs/path/to/warden hooks run claude` so the runtime is the
  same Warden binary the developer just used to install.

Outputs:

- A merged `~/.claude/settings.json` whose `hooks.PreToolUse` array
  contains an entry for the matcher `Read|Edit|Write|Bash` pointing at
  the wrapper script. If an entry with the same matcher *and the same
  command* already exists, the merge is a no-op (idempotent). If a
  different `warden` entry exists (e.g. from an older install), it is
  replaced.
- The wrapper script (`~/.warden/hooks/claude-pre-tool-use.sh`),
  executable, contents derived from a template embedded in the
  installer source — no runtime templating, no `npm exec`, no path
  guessing.

The installer never silently overwrites a non-Warden hook entry. If
the user has a competing PreToolUse hook for the same matcher, the
installer prints a diff and exits 1 with a hint pointing at
`--force`. We add `--force` only when a user files a real bug; not
landed in M6.

### 8. Settings.json merge — minimal-surface JSON edit

The settings file is JSON with comments tolerated by Claude Code's
parser, but the installer treats it as strict JSON for simplicity:

- Parse with `JSON.parse`. On error, exit 1 with the original line
  number — never attempt to repair.
- The merge preserves all unrelated keys. Only `hooks.PreToolUse` is
  touched.
- Output is written via `JSON.stringify(obj, null, 2)` to match
  Claude Code's own style. We accept that this strips comments — the
  installer logs a warning when the original file contained `//`
  comments so the user can decide whether to revert.

### 9. Testability

- The interceptor is pure. Tests pass tool-call JSON literals and
  assert on the returned `Decision`. No subprocesses, no settings.json.
- The allowlist parser is a string → `Allowlist` function. Tests cover
  the well-formed cases, the malformed-line case, the missing-reason
  case, and the unknown-schema case.
- The installer takes the settings.json path and the hook script path
  as parameters (not constants) so tests run against `mkdtempSync`
  fixtures. The idempotence test runs the installer twice and asserts
  the resulting JSON is byte-identical the second pass.
- A separate `CLI runtime` test invokes `bun run packages/hooks-claude/
  src/index.ts < fixture.json` and asserts on exit code + stderr, so
  the end-to-end stdin contract is exercised.

### 10. Non-goals (explicit)

- **Cursor / Cline / Aider adapters.** Separate milestones. The
  `packages/hooks-claude` interceptor is intentionally Claude-specific
  in its JSON shape; the credential rule pack in `packages/rules` is
  not, and other adapters will reuse it.
- **Network-egress blocking on socket APIs.** Out of scope (process
  isolation; see T5 §"Warden does NOT detect").
- **Hook signing / integrity.** The wrapper script is on the user's
  machine and the user trusts their own filesystem; signing the
  wrapper is futile if the attacker can already write `~/.claude/
  settings.json`. Trust boundary documented; not closing it.
- **Live secret detection in arbitrary file content.** This is a
  path-and-shell rule pack, not a secret scanner. Tools that scan
  *contents* (gitleaks, trufflehog) cover a different surface.

---

## Consequences

Positive:

- The runtime gap that file-at-rest detectors structurally cannot
  close is now covered for Claude Code, the dominant agent runtime.
- The package layout makes the next adapter (Cursor) a sibling
  package, not a fork — the credential rules in `packages/rules` and
  the allowlist format are shared.
- The pure-function interceptor preserves Warden's "no LLM, no
  network, deterministic" invariants from the scanner: the hook does
  not phone home, does not learn, and gives the same answer for the
  same input regardless of when it runs.

Negative:

- The hook is cooperative. An agent fork that strips PreToolUse, an
  MCP tool that opens its own socket, or a credential read via the
  agent's process memory all bypass the layer. T5 §"Warden does NOT
  detect" names this explicitly; M6 ships anyway because the covered
  surface (the agent's tool-call boundary) is still by far the
  dominant credential-read vector in published incident reports.
- `.warden/hooks/allow.toml` is a governance file with the same
  trust-of-committer property as `.warden/trust/allowed_signers`.
  CODEOWNERS coverage in M6 is the mitigation; a real CI-side
  enforcement (block PRs that grow the allowlist without two-party
  review) is post-1.0.

---

## Sources

- Anthropic Claude Code hooks documentation —
  `https://docs.anthropic.com/en/docs/claude-code/hooks` (verified
  2026-05-25). Source of the PreToolUse JSON shape and the exit-2
  block convention.
- OWASP LLM02:2025 Sensitive Information Disclosure —
  `https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/`
  (verified 2026-05-25). Primary citation for the T5 credential
  surface.
- TrapDoor (T1, May 2026, Socket) and GlassWorm (T2) reports already
  cited in `docs/THREAT_MODEL.md`. Both ended in credential-file
  exfiltration via agent tool calls — the M6 hook is the layer that
  catches the call even if the upstream context file slipped past
  M1/M2/M4.
