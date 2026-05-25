# ADR 0014 — Cursor hook adapter (M7)

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M7 design pass
**Threat:** T5 (agent-tool credential exfiltration; same as M6, see `docs/THREAT_MODEL.md`)
**Extends:** ADR 0013 (M6 Claude Code adapter — the rule pack and allowlist format are shared)
**Extends:** `docs/ARCHITECTURE.md` §2 (`packages/hooks-cursor` package boundary), §4 (cold-path)

---

## Context

M6 closed the runtime credential-read gap for Claude Code through the
`PreToolUse` hook event. M7 extends the same closure to **Cursor**, the
second-most-deployed AI coding agent.

The question every planning pass for M7 must answer first is: *what is
the Cursor-side enforcement surface, and is it equivalent to Claude's
`PreToolUse`?* The answer affects whether Warden can ship as a native
hook (preferred) or has to ride on a less-direct intermediary (rejected
in M6 for Claude — would have been rejected here too).

Cursor 1.7 (October 2025) introduced a native hook system that maps
closely to Claude Code's `PreToolUse`. The relevant events are
documented at `https://cursor.com/docs/hooks` (verified 2026-05-25):

| Cursor event              | Claude analogue        | M7 coverage                                  |
|---------------------------|------------------------|----------------------------------------------|
| `beforeReadFile`          | `PreToolUse` (Read)    | ✅ covered — same rule, same evidence shape  |
| `beforeShellExecution`    | `PreToolUse` (Bash)    | ✅ covered — same rule, same evidence shape  |
| `beforeMCPExecution`      | (no Claude equivalent) | ⬜ deferred — see §10                         |
| `afterFileEdit`           | (post-action only)     | ⬜ out of scope — fires *after* the edit      |
| `stop`                    | (post-session only)    | ⬜ out of scope — not a tool-call gate        |

Two facts shape every other decision in this ADR:

1. **Cursor 1.7+ has native pre-tool-use hooks.** The MCP-intermediary
   strategy (running a Warden MCP server in front of the agent that
   re-issues vetted calls) is NOT required and is rejected for the
   same reason it was rejected for M6 — see §6.
2. **Cursor has no `beforeFileEdit` / `beforeFileWrite` event.** The
   only file-write-side event is `afterFileEdit`, which is
   fire-and-forget and runs *after* the bytes are on disk. M7 therefore
   covers `Read` and `Bash` on Cursor but **cannot** block credential
   writes the way M6 does for Claude. This is a real coverage
   asymmetry and is named explicitly in §9 and surfaced in the
   threat-model update.

The threat ID is **T5** (same as M6). No new threat is introduced — M7
extends the existing T5 coverage to a second agent runtime.

---

## Decision

### 1. Populate `packages/hooks-cursor`, sibling of `packages/hooks-claude`

The empty `packages/hooks-cursor` skeleton (created at M0) becomes the
M7 home. Same package shape as `packages/hooks-claude`:

```
packages/hooks-cursor/
├── package.json                 (depends on @warden-sh/rules)
├── src/
│   ├── index.ts                 (public surface)
│   ├── interceptor.ts           (pure evaluateToolCall — input → Decision)
│   ├── allowlist.ts             (re-exports from @warden-sh/hooks-claude — see §7)
│   ├── install.ts               (writes ~/.cursor/hooks.json)
│   └── run.ts                   (CLI shim around interceptor)
└── tests/
    ├── interceptor.test.ts
    ├── install.test.ts
    └── run.test.ts
```

Rationale for a separate package rather than parameterizing
`hooks-claude` over an "agent vendor" abstraction:

- The JSON contract differs in three places (input shape, decision
  shape, installer target). A parameterized API would have to model
  all three as runtime data, making the type system describe what is
  more naturally described per package.
- The credential rule pack in `@warden-sh/rules` is already
  vendor-independent (it operates on the normalized `ToolCallView`),
  which is the shared abstraction. The adapter is intentionally thin
  on top.
- Future adapters (Cline, Aider, Windsurf) will repeat the same
  three-file structure. The repetition is a feature: each adapter is
  trivially auditable in isolation.

### 2. Pure interceptor function — `evaluateCursorToolCall(input, ctx)`

Same posture as M6's `evaluateToolCall`. The runtime hot path is a
single pure function over a parsed JSON input and an injected context
(home directory, cwd, allowlist). No I/O. The CLI shim reads stdin,
loads the allowlist, calls the pure function, writes the response.

```ts
type CursorEvent =
  | { kind: 'beforeReadFile';      file_path: string;                          ... }
  | { kind: 'beforeShellExecution'; command: string; cwd: string;              ... }
  | { kind: 'beforeMCPExecution';   tool_name: string; tool_input: string;     ... };  // skipped in M7 — see §10

type Decision =
  | { kind: 'allow' }
  | { kind: 'deny'; ruleId: string; reason: string }
  | { kind: 'skip'; why: string };

function evaluateCursorToolCall(
  input: CursorHookInput,
  ctx: { home: string; cwd: string; allowlist: Allowlist },
): Decision;
```

The function normalizes Cursor's per-event shape into the rule pack's
`ToolCallView`, then runs the same `CREDENTIAL_RULES` array that M6
uses. The rules see the same inputs they saw in M6; the matching is
byte-identical.

### 3. JSON contract — Cursor hook event shapes

Per Cursor's docs (verified 2026-05-25 at
`https://cursor.com/docs/hooks`), each event sends a JSON object on
stdin with a shape distinct from Claude Code's `PreToolUse`. The
relevant fields are:

**`beforeReadFile`:**
```json
{
  "file_path": "/abs/path",
  "content": "string (file contents — Warden ignores)",
  "attachments": [{ "type": "file" | "rule", "file_path": "..." }],
  "conversation_id": "...", "generation_id": "...",
  "model": "...", "hook_event_name": "beforeReadFile",
  "cursor_version": "...", "workspace_roots": ["..."],
  "user_email": "string | null", "transcript_path": "string | null"
}
```

**`beforeShellExecution`:**
```json
{
  "command": "shell string",
  "cwd": "/abs/path",
  "sandbox": false,
  "conversation_id": "...", "generation_id": "...",
  "model": "...", "hook_event_name": "beforeShellExecution",
  "cursor_version": "...", "workspace_roots": ["..."],
  "user_email": "string | null", "transcript_path": "string | null"
}
```

**`beforeMCPExecution`:** see §10 (deferred).

Differences from Claude's `PreToolUse` that the adapter must handle:

1. **Top-level fields, not nested `tool_input`.** Claude sends
   `{tool_name, tool_input: {file_path, command, ...}}`. Cursor sends
   the operation-specific fields at the top level alongside the
   metadata.
2. **Event name in `hook_event_name`, not `tool_name`.** The adapter
   dispatches on `hook_event_name`.
3. **`beforeReadFile` includes the file contents.** Warden ignores
   them — the rule pack is path-based, not content-based, and the
   content field is potentially large. We discard it without parsing.
4. **`workspace_roots` is an array, not a single value.** When
   resolving relative paths in `beforeShellExecution.command`, the
   adapter uses the `cwd` field (which is single-valued and matches
   shell semantics); `workspace_roots[0]` is a fallback only if `cwd`
   is missing.

Unknown / missing fields are treated as "skip" → "allow" rather than
"error", same posture as M6 (cooperative hook, schema mismatch ≠
strand the developer).

### 4. Decision contract — top-level `permission` field

This is the largest single delta from M6. Cursor expects the hook to
write a JSON object on stdout (not stderr) with a top-level
`permission` field:

```json
{ "permission": "allow" | "deny" | "ask", "agent_message": "...", "user_message": "..." }
```

Claude's `PreToolUse` uses `{"decision": "block", "reason": "..."}` or
the exit-2 stderr convention. The two contracts are mutually
incompatible. The M7 adapter therefore emits Cursor's format
unconditionally on the `warden hooks run cursor` path. There is no
"shared" emit function with M6.

Mapping:

| Internal `Decision`                  | Cursor stdout                                                                        | Exit code |
|--------------------------------------|--------------------------------------------------------------------------------------|-----------|
| `{ kind: 'allow' }`                  | `{"permission":"allow"}`                                                             | 0         |
| `{ kind: 'skip' }`                   | `{"permission":"allow"}` + one-line `warden hook: skipping …` on stderr              | 0         |
| `{ kind: 'deny', ruleId, reason }`   | `{"permission":"deny","agent_message":"<ruleId>: <reason>","user_message":"<short>"}`| 0         |
| (adapter config error)               | `{"permission":"allow"}` + `warden hook: setup error …` on stderr                    | 1         |

Notes on this matrix:

- **Exit 0 for deny** — Cursor reads the decision from stdout JSON,
  not from the exit code. Exiting non-zero on deny is what Claude
  expects but not what Cursor does; using Cursor's convention here
  keeps the contract clean.
- **`agent_message` carries the rule-cite evidence** — this is what
  the model sees and what Cursor surfaces in the UI when explaining
  the block. Equivalent to Claude's `reason`.
- **`user_message` is a short variant for the dev** — optional;
  defaults to a one-line "warden blocked … (see agent_message)".
- **Config errors return `permission: allow`, not deny** — same
  reason M6 uses exit 1 instead of exit 2 for config errors: the
  alternative (blocking everything when our config is broken) would
  strand the developer's session for a reason that is not the threat.
- **`failClosed` is independent of Warden** — `failClosed: true` in
  `hooks.json` only matters if the *hook process itself* crashes. As
  long as `warden hooks run cursor` exits 0 with valid JSON,
  `failClosed` is dormant. We **recommend** the installer set
  `failClosed: true` on the registered entry so that a crashed Warden
  binary is treated as a deny — but only for paths/commands that
  matched a rule; see §8.

### 5. Coverage matrix — Cursor events vs M6 rule pack

| Rule (from M6)                              | Cursor event that fires it | Status in M7 |
|---------------------------------------------|----------------------------|--------------|
| `hooks.credential-file-read` (Read)         | `beforeReadFile`           | ✅ covered    |
| `hooks.credential-file-read` (Edit / Write) | **no Cursor event**        | ❌ uncovered  |
| `hooks.credential-shell-read` (Bash)        | `beforeShellExecution`     | ✅ covered    |
| `hooks.credential-pipe-network` (Bash)      | `beforeShellExecution`     | ✅ covered    |

The Edit/Write uncovered cell is the single largest asymmetry between
M6 and M7. It is **not** a Warden bug — Cursor's hook event API does
not expose a `beforeFileEdit` or `beforeFileWrite` event today. The
only file-write-side event is `afterFileEdit`, which fires after the
file is on disk and is documented as fire-and-forget (no decision
field, no return shape).

Threat-model implications, named here so M7 ships honest:

- An agent on Cursor instructed to *write* a credential-shaped file
  (e.g., `echo $SOMETHING > ~/.ssh/id_rsa` — which would be caught
  by `beforeShellExecution`, but `Edit:~/.ssh/id_rsa` would not) is
  not blocked at the hook layer. The narrower form — writing a
  credential-bearing file the agent already chose — is uncovered on
  Cursor for as long as Cursor's hook API lacks the event.
- The credential-read attack vector (the one in T5 reports — TrapDoor,
  GlassWorm) is fully covered; both attacks read existing credentials
  rather than planting new ones.

We surface this as a new entry in `docs/THREAT_MODEL.md` T5 §"Warden
does NOT detect" and as a new `docs/ISSUES.md` entry (#007, severity
medium, resolution = monitor Cursor changelog + raise upstream feature
request).

### 6. Rejection of the MCP-intermediary strategy

A plausible alternative for Cursor would be to register Warden as an
MCP server that proxies file-read / shell-exec tool calls and applies
the credential rule pack before forwarding. This was rejected:

- **UX impact (decisive)** — an MCP-intermediary strategy would force
  every user to (a) install an MCP server, (b) reconfigure their
  Cursor MCP settings to route reads/shells through it, (c) disable
  Cursor's built-in Read / Bash tools so the proxy is the only path.
  That last step is structurally fragile: Cursor's built-in tools
  cannot be unregistered, only ignored — and an agent's "read this
  file" call resolved by the LLM is not addressable by us.
- **Coverage actually decreases** — Cursor's MCP server registry does
  not intercept the agent's built-in `Read` / `Bash` tools, so we
  would lose the very coverage we're trying to gain.
- **Trust-model regression** — turning Warden into an MCP server
  introduces a runtime network surface (MCP transport, even on stdio,
  is RPC) that the M6 architecture deliberately avoids.
- **Compounding fragility** — if Cursor changes its tool routing, the
  proxy silently stops being on the path. The native hook layer is
  the contract Cursor commits to.

The MCP intermediary is reconsidered **only** if Cursor removes its
hook API in a future major version, in which case it becomes a v1.0
discussion in its own ADR.

For pre-1.7 Cursor users: the M7 installer detects `cursor_version`
support is unavailable (the installer cannot probe Cursor itself, so
it falls back to a warning at install time if `~/.cursor/hooks.json`
write succeeds but no `cursor_version` field is observed in a
subsequent test run). Pre-1.7 users get a clear "your Cursor version
does not support hooks; please upgrade" message — they do not get a
working MCP-intermediary fallback in M7.

### 7. Allowlist — reuse `.warden/hooks/allow.toml` (no Cursor-specific file)

The allowlist file from M6 (`.warden/hooks/allow.toml`, schema "v1")
is **shared verbatim** between Claude and Cursor adapters. Reasons:

- The credential rule IDs are identical (`hooks.credential-file-read`,
  `hooks.credential-shell-read`, `hooks.credential-pipe-network`).
  Splitting the allowlist by agent vendor would force project owners
  to maintain two files with identical entries.
- The project's risk posture is per-credential-path, not per-agent. If
  `~/.aws/credentials` is legitimate for a Claude session, it is
  legitimate for a Cursor session running the same SDK test.
- The parser at `packages/hooks-claude/src/allowlist.ts` is already
  vendor-independent. `packages/hooks-cursor` imports it directly
  via `import { parseAllowlist } from '@warden-sh/hooks-claude'`
  rather than re-implementing it.

Open question on the package-boundary aesthetic: importing
`parseAllowlist` from `hooks-claude` introduces a cross-adapter
dependency. We accept this in M7 with a note that, if a third adapter
lands (Cline / Aider / Windsurf), the allowlist parser should be
lifted into `packages/rules` or a new `packages/hooks-common`. The
lift is mechanical — the parser has no Claude-specific behavior — and
deferring until two adapters use it avoids over-engineering on day
one.

CODEOWNERS coverage of `.warden/hooks/` (added in M6) is unchanged.

### 8. Installer — `warden hooks install cursor`

Idempotent. Inputs:

- Target hooks file: `~/.cursor/hooks.json` (user-level — same
  reasoning as M6 chose `~/.claude/settings.json` over project-level).
  If the user passes `--project`, the installer writes to
  `<cwd>/.cursor/hooks.json` instead. Not in M7 — same as M6's
  `--force`, deferred until a real user reports needing it.
- Wrapper script: `~/.warden/hooks/cursor-pre-tool-use.sh`,
  executable, contents derived from a template embedded in the
  installer source. Same shape as M6's
  `claude-pre-tool-use.sh`; the only difference is the subcommand
  (`hooks run cursor` instead of `hooks run claude`).

Outputs:

- A merged `~/.cursor/hooks.json` registering Warden for the three
  in-scope events:

  ```json
  {
    "hooks": {
      "beforeReadFile": [
        { "command": "~/.warden/hooks/cursor-pre-tool-use.sh", "failClosed": true }
      ],
      "beforeShellExecution": [
        { "command": "~/.warden/hooks/cursor-pre-tool-use.sh", "failClosed": true }
      ]
    }
  }
  ```

- `failClosed: true` is set on every Warden-registered entry. The
  rationale is asymmetric with the *deny semantics* in §4: when the
  hook process itself crashes, the safe default is to block (the
  developer will hear about it loudly). When the hook process runs
  successfully but our config is broken, allowing is safer (the
  developer's workflow isn't held hostage by our parser bug). The two
  signals are distinct.

Merge semantics (same posture as M6's `mergeSettings`):

- Parse with `JSON.parse`. On error, exit 1 with the original line
  number — never repair.
- Preserve all unrelated keys (Cursor's `hooks.json` may grow more
  event types over time).
- Recognize Warden-managed entries by a `command` substring match
  (`cursor-pre-tool-use.sh`); replace them in place.
- If a different (non-Warden) hook is registered for the same event,
  emit a diff to stderr and exit 1 with a hint to resolve manually.
  `--force` is reserved for the bug case; not landed in M7.

### 9. Non-goals (explicit)

- **No Cline / Aider / Windsurf adapters.** Each gets its own
  milestone if and when it lands.
- **No coverage of credential *writes* on Cursor.** Cursor's hook API
  does not expose a pre-write event; M7 documents the gap (§5,
  ISSUES #007) and ships without it. The honest framing is that
  Warden covers the *read* surface on Cursor and is silent on writes
  until Cursor adds the event.
- **No MCP-tool credential interception (`beforeMCPExecution`)** —
  deferred, see §10.
- **No Cursor `afterFileEdit` integration.** It is post-action and
  cannot block; integrating it would be a forensic logger, not an
  enforcement adapter. If users ask for an audit trail of post-edit
  events, that becomes its own (separate) feature.
- **No Cursor `stop`-event integration.** Stop hooks are for session
  cleanup, not tool-call gating.
- **No `--json-output` flag toggle.** Unlike M6 (which has both the
  stderr/exit-2 path and the optional `--json-output` JSON path),
  Cursor exposes only one decision protocol (top-level
  `permission`). M7 always emits Cursor's JSON shape.
- **No telemetry, no network calls.** Same invariants as M6.

### 10. Deferred: `beforeMCPExecution` (own milestone)

Cursor fires `beforeMCPExecution` for every MCP tool call the agent
makes. The shape includes `tool_name` (the MCP-server-declared tool
name) and `tool_input` (a JSON-encoded string — the per-tool argument
shape is server-dependent). A natural Warden extension would be to
inspect `tool_input` for credential-path-shaped arguments.

Reasons to defer rather than ship in M7:

- **Per-tool input schema is server-dependent.** The MCP spec says
  nothing about argument shapes; a `read_file(path=…)` MCP tool and
  a `fs.read({path: …, encoding: …})` tool have distinct argument
  trees. A useful rule would need either (a) a known-tool registry
  (which we lack), or (b) a generic recursive "does any string in
  `tool_input` match a credential glob" check (which is plausible
  but a new rule type, not a free rebuild of the existing pack).
- **M6 does not cover this either.** Claude's MCP tool calls flow
  through `PreToolUse` with `tool_name` set to the MCP tool's name,
  not `Read` / `Bash` / etc., so the M6 adapter currently routes
  them to the "other" branch and allows. Adding MCP coverage is a
  cross-adapter concern, not a Cursor-only one.
- **ADR 0011's MCP analyzer already covers the at-rest configuration
  surface.** A malicious MCP server declared in a config file is
  caught by M4. The runtime-MCP-call interception is the
  complementary surface but requires its own design pass.

Recommended next step (post-M7): a new milestone — call it M8 or
M-MCP-runtime — with its own ADR. The milestone would extend both
M6 and M7 (and any future adapters) with a shared MCP-call evaluator.

### 11. Testability

- Interceptor is pure. Tests pass per-event JSON literals and assert
  on the returned `Decision`. No subprocesses, no `hooks.json`.
- Installer takes `hooks.json` path and wrapper-script path as
  parameters (not constants) so tests run against `mkdtempSync`
  fixtures. Idempotence test runs the installer twice and asserts
  the resulting JSON is byte-identical the second pass.
- A `CLI runtime` test invokes
  `bun run packages/hooks-cursor/src/index.ts < fixture.json` and
  asserts on stdout JSON shape + exit code, exercising the full
  stdin/stdout contract.
- A **cross-vendor parity test** lives in the hooks-cursor test
  suite: for each malicious M6 fixture (Read/Bash credential
  payloads), there's a Cursor-shaped equivalent that produces the
  same `ruleId` from the same rule. The test asserts both adapters
  agree on the deny decision. If a rule fires on Claude but not on
  Cursor, the test fails — preventing the rule pack from drifting
  into vendor-specific behavior.

---

## Consequences

Positive:

- The runtime credential-read gap is now covered for both Claude Code
  and Cursor, the two dominant agent runtimes.
- The credential rule pack proves its vendor-independence: zero rule
  changes needed in `packages/rules`. The adapter is the only
  vendor-specific code.
- The allowlist file is shared, so project owners maintain one
  configuration regardless of which agents their developers run.
- The next adapter (Cline / Aider / Windsurf) has a working template
  to copy from — the same three-file shape, the same rule pack, the
  same allowlist.

Negative:

- **Edit/Write coverage asymmetry.** Cursor users do not get
  credential-write blocking until Cursor exposes a `beforeFileEdit`
  / `beforeFileWrite` event. This is documented (§5, §9, T5 update,
  ISSUES #007) but it is a real gap. Users on threat models that
  weigh credential-write attacks heavily should run Claude Code
  rather than Cursor until the event lands.
- **MCP runtime calls are uncovered on both adapters.** §10 names
  this; the resolution path is a future milestone.
- **The `parseAllowlist` import from `hooks-claude` creates a
  cross-adapter coupling.** Mitigated by the explicit lift-to-shared
  trigger condition (third adapter); accepted as the simplest M7
  decision.
- **Cursor's hook command-substring match for "is this a Warden
  entry" is the same heuristic M6 uses — fragile if a user has a
  non-Warden `cursor-pre-tool-use.sh` script of their own.** The
  fragility is identical to M6's; we accept it for the same reason
  (the conflict-detection path catches the false positive and asks
  the user to resolve manually).
- **Pre-1.7 Cursor users get no protection from M7.** The installer
  warns; no fallback is shipped. Resolution: upgrade Cursor.

---

## Sources

- Cursor hooks documentation —
  `https://cursor.com/docs/hooks` (verified 2026-05-25). Source of
  the per-event JSON shapes, the top-level `permission` decision
  field, the `failClosed` semantics, and the `hooks.json` file
  locations (project `.cursor/hooks.json`, user `~/.cursor/hooks.json`,
  enterprise paths).
- Cursor 1.7 release notes (October 2025) — introduced
  `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution`,
  `afterFileEdit`, `stop` events.
- Cursor community forum: "Bug: preToolUse / Agent hooks do not emit
  for built-in Web search in Cursor Agent" — confirms that not every
  agent action surfaces through hooks (Web search is one omission).
  Not a blocker for M7's credential coverage (Read and Bash are
  documented to fire), but recorded as ISSUES #008 to track parity.
- ADR 0013 (M6) — the credential rule pack design and allowlist
  format reused verbatim in M7.
- OWASP LLM02:2025 Sensitive Information Disclosure (already cited
  in `packages/rules/src/data/credentials.ts`) — primary T5
  citation.
