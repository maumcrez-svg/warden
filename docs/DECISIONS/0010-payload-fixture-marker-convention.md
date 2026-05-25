# ADR 0010 — Inline marker convention for "this file contains payloads by design"

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M3.1 design pass (review by project maintainer)
**Supersedes:** the `.wardenignore`-based exclusion strategy declared in
ADR 0008 §4 (M3, commit `13799fa`).

---

## Context

M3 (commit `13799fa`) shipped prompt-injection detection. To prevent the
detector from self-triggering on its own rule data and test inputs, M3
added three lines to `.wardenignore`:

```
tests/fixtures/                                                # inherited from M1
packages/rules/src/data/prompt-injection.ts                    # introduced in M3
packages/core/tests/scan-prompt-injection.test.ts              # introduced in M3
```

Review of M3 identified that this approach is structurally wrong for a
security tool:

1. **Exclusion is by whole file or whole directory.** An attacker who
   adds a new field to `packages/rules/src/data/prompt-injection.ts`
   (e.g. `notes: "<TrapDoor payload here>"`) gets the new field
   excluded for free — the entire file is out of scan scope.

2. **Glob exclusion silently covers new files.** A PR adding
   `tests/fixtures/innocuous/notes.md` with a real payload is invisible
   to `warden scan .`; the `tests/fixtures/` glob covers it.

3. **The exclusion list is in a separate file from the excluded
   content.** Reviewers diffing a PR that adds a fixture do not see, in
   that diff, any signal that the new file lands in an excluded zone.

4. **The reviewer-agent attack vector.** Any AI coding agent reading a
   PR (the reviewer's Claude Code / Cursor session, the agent that
   summarizes the diff, etc.) reads the new file *before* CI runs. The
   defence against this is that the file must be scanned at PR-open
   time by the contributor's own CI or by a pre-merge check — and an
   excluded file defeats that defence.

Warden ships a scanner. A scanner that excludes the directories where
payloads would land is the canonical anti-pattern for SAST tools. We
fix it before any other milestone.

---

## Decision

### 1. Inline header markers replace `.wardenignore` for "payload by design"

`.wardenignore` continues to exist, but its semantics narrow to
**"not agent context at all"** — opaque binaries (`bun.lock`), the
bootstrap-prompt verbatim record, build output. Files that *contain*
payloads but ARE agent context (rule data, detector tests, fixture
corpora) move to inline markers.

After M3.1, `.wardenignore` does not list any file under
`packages/rules/src/data/`, `packages/*/tests/`, or `tests/fixtures/`.

### 2. Marker grammar

One marker per file, in the file's **header zone** (defined in §5). The
grammar — strict ASCII:

```
warden: payload-fixture <family>[ <family>...] [scope:<scope>] -- <reason>
```

Where:

- `warden:` — fixed literal.
- `payload-fixture` — the only directive M3.1 ships. Future directives
  (e.g. `warden: trust-anchor`) get their own ADR.
- `<family>` — one or more space-separated family tokens from §3.
- `scope:<scope>` — optional. `scope:file` (default, can be omitted)
  or `scope:lines:N-M` for a closed line range.
- `-- <reason>` — mandatory free-text after a literal ASCII double
  hyphen-minus, with a single space on each side. Missing or empty
  reason is a hard parse error (§6). Em-dash (`—`) is **not**
  accepted: ASCII-only grammar avoids the irony of a security marker
  depending on a Unicode special character.

Examples:

```ts
// warden: payload-fixture rules-data -- regex literals in rule pack
// warden: payload-fixture detector-test prompt-injection-pattern -- scanner test feeds attack strings as inputs
```

```md
<!-- warden: payload-fixture trapdoor-unicode -- T1 TrapDoor tag-char payload -->
<!-- warden: payload-fixture trapdoor-unicode scope:lines:10-25 -- only the example block -->
```

### 3. Family tokens

Two categories of family.

**Narrow-scope families** — suppress findings *only* in the named
detector category. Cross-category poisoning still fires.

| Family                       | Suppresses category | Valid path scope                       |
|------------------------------|---------------------|----------------------------------------|
| `trapdoor-unicode`           | `unicode`           | anywhere                               |
| `prompt-injection-pattern`   | `prompt-injection`  | anywhere                               |

**Broad-scope role families** — suppress all current and future
detector categories. Path-restricted to canonical directories so they
cannot whitewash arbitrary files.

| Family          | Suppresses categories      | Path must match                         |
|-----------------|----------------------------|-----------------------------------------|
| `rules-data`    | all (forward-compatible)   | `packages/rules/src/data/**`            |
| `detector-test` | all (forward-compatible)   | `packages/*/tests/**`                   |

A broad-scope family from a non-matching path is a hard parse error
(§6). Path restriction is enforced before any suppression takes effect.

Multiple families may be listed when a file holds payloads of more
than one category. Suppressions union. Combining a broad-scope family
with a narrow one is permitted (the narrow is redundant but
descriptive); the combination is not flagged.

### 4. Cross-family poisoning is the key property

A fixture marked `trapdoor-unicode` declares "I expect unicode
findings; suppress them." If a malicious PR plants a prompt-injection
payload inside that same fixture, the prompt-injection finding still
fires because `prompt-injection` ∉ `{unicode}`.

This is the property the `.wardenignore` approach could not provide.
It is the M3.1 product.

For broad-scope families (`rules-data`, `detector-test`), this property
does **not** apply by design — those families suppress everything and
rely on path restriction plus code-review process as the defence.
Narrow-scope families are preferred wherever they fit; broad-scope
families are an explicit trust escalation, documented as such here and
in the per-file marker's `-- <reason>`.

### 5. Header zone — where the marker may appear

The marker must appear in the file's **header zone**, defined as:

- An optional shebang (`#!/...`) on line 1.
- Zero or more leading blank lines.
- A consecutive block of comment lines (`//` for TS/JS, `<!-- -->` for
  Markdown). Markdown comments may span multiple lines; the marker
  itself must be on its own single line inside a comment block.
- The header zone ends at the first non-blank, non-comment line.

The marker MUST be one line. Multi-line markers are a parse error
(prevents wall-of-text obfuscation).

If a parser encounters a `warden:` token *outside* the header zone, it
is a parse error — not silently ignored. This prevents an attacker
from burying a fake marker mid-file to disable scanning of surrounding
content.

### 6. Malformed marker semantics — fail closed (exit 2)

Any of the following conditions cause the scan to **fail with exit 2**
and a stderr error citing the file, line, and violation:

- Marker outside the header zone.
- Multiple markers in the same file.
- Unknown directive.
- Unknown family.
- Broad-scope family used outside its allowed path.
- Missing or empty reason after `-- `.
- Malformed `scope:lines:N-M` (non-integer, or violations of the
  bounds below).
- Range bound violation: `N < 1`, `N > M`, or `M >` file's total line
  count. A range pointing past EOF indicates a stale or malformed
  marker; we fail loud rather than silently clamp.
- Marker text spans multiple lines.

There is no "best-effort" mode. A malformed marker is a configuration
bug and must block the scan. Same principle as a malformed
`.wardenignore`: the scanner refuses to run with ambiguous config.

### 7. File-type coverage in M3.1

M3.1 ships marker parsing for the file types in the corpus today:

- TypeScript / JavaScript (`.ts`, `.tsx`, `.js`, `.mjs`, `.cjs`) —
  marker in `//` comment.
- Markdown (`.md`, `.mdc`, `.markdown`) — marker in `<!-- -->` comment.

**Deferred to M4, with operational rule attached:**

JSON / JSONC, YAML, and TOML marker syntax is not specified in M3.1
because no fixture of those types exists today.

**Operational rule:** if a contributor proposes a new fixture in a
file type M3.1 does not cover (JSON, YAML, TOML, etc.) **before** M4
lands, that contributor must open a new ADR specifying the marker
syntax for that file type — or extend ADR 0010 — and must not extend
`.wardenignore` to re-introduce the directory-glob exclusion this ADR
just removed. The point of M3.1 is that the easy bypass (add a line
to `.wardenignore`) is no longer the default; new file types are
adopted with deliberate design, not by silent regression.

### 8. Suppression reporting

Suppressed findings are not silent. The scanner counts them and emits
a summary line in the pretty reporter:

```
summary: 0 finding(s) — 0 high, 0 medium, 0 low
suppressed: 95 unicode + 8 prompt-injection in 5 file(s) by payload-fixture markers
```

`--verbose` (new flag, M3.1) lists each suppressed finding with the
marker that suppressed it. Makes it easy to audit at a glance what
would have fired without markers.

JSON `warden/scan/v2` (introduced in M3 by ADR 0009) absorbs the
following additive fields in M3.1:

- Top-level: `suppressedCount: number`,
  `suppressedByCategory: Record<FindingCategory, number>`.
- Per file: `marker: Marker | null`,
  `suppressedFindings: ReadonlyArray<UnicodeFinding>`,
  `suppressedPromptInjectionFindings: ReadonlyArray<PromptInjectionFinding>`.

These are additive within the v2 lifetime, not a v3 bump. Rationale:
v2 was introduced in M3 (commit `13799fa`) one day before M3.1; two
discriminator bumps in two days dilutes the value of the discriminator.
ADR 0009 gets a §3 footnote pointing here so the contract is traceable
from either ADR.

### 9. SARIF: suppressed findings get a `suppressions[]` entry

SARIF 2.1.0 defines `result.suppressions[]` for exactly this case
(§3.27.23). Suppressed Warden findings emit with
`suppressions: [{ kind: "external", justification: "<marker reason>" }]`
and continue to appear in `runs[].results[]`. This is the conformant
way to model "the tool found it but the user marked it as expected"
and avoids the worse alternative of dropping the result entirely.

### 10. Walker integration

The walker (`packages/core/src/walk.ts`) does **not** consult markers.
Markers do not change which files are visited. Markers are consulted
by `scanPath` after per-file content is read; suppression is applied
to the findings list before counts aggregate.

This separation matters: it keeps the walker's contract (`.gitignore`
+ `.wardenignore` only) intact, and ensures every scanned file is
*visible* in the report's `files[]` even when all its findings are
suppressed. A reviewer browsing the report sees the file's presence
and the marker that explains it.

### 11. Marker parse errors are first-class scan errors

`scanPath` aggregates marker parse errors per file into a
`markerErrors: ReadonlyArray<{ path: string; message: string }>` field
on `ScanReport`. `runScan` checks this list and:

- If non-empty: writes each error to stderr and exits with code 2
  (matching the existing "invocation error" exit-code class in ADR
  0007 §3).
- If empty: proceeds with the normal findings-based exit code.

This means a single broken marker in any scanned file fails the scan
loud, not silently.

---

## Threat model — what M3.1 closes and what stays open

**Closed by M3.1:**

- Whole-file exclusion of rule data and detector tests via
  `.wardenignore`. Files are scanned; cross-category payloads fire.
- Silent inheritance of glob exclusion by newly added files in
  `tests/fixtures/` or `packages/rules/src/data/`. New files without
  their own marker are scanned normally; new payload-bearing files
  must add a marker in the same PR, which is visible in the diff.
- Drift between `.wardenignore` and the files it excludes. The marker
  is in the file; rename moves the marker with the file.

**Open after M3.1 (documented limitations):**

- An attacker with write access to `packages/rules/src/data/` can add
  payload content under the broad-scope `rules-data` marker that
  already covers the file. Mitigation: PRs touching this path require
  maintainer review; the path is in `CLAUDE.md` §"What NOT to Touch
  Without Asking". A tighter tool-level defence (pattern-aware
  suppression: suppress only findings inside declared regex literals;
  everything else fires) is a future ADR — not M3.1.
- JSON / YAML / TOML fixtures cannot use markers yet. The operational
  rule in §7 prevents accidental regression to glob exclusion before
  M4 specifies the syntax.
- An attacker who can submit a PR adding a brand-new file with a
  legitimate-looking marker (`<!-- warden: payload-fixture
  trapdoor-unicode -- legit-looking reason -->`) can suppress the
  findings in that file. Same risk class as an attacker adding a
  malicious test that's "supposed" to be there — caught by code review
  of the marker line itself. The marker is designed to be glaring in
  the diff for exactly this reason.

---

## Migration plan (executed in the M3.1 implementation commit)

1. Implement marker parser in `packages/core` with the grammar above.
2. Implement suppression in `scanPath`; surface marker errors via
   `ScanReport.markerErrors` and `runScan` → exit 2.
3. Add markers to files:
   - `packages/rules/src/data/prompt-injection.ts` →
     `// warden: payload-fixture rules-data -- regex literals in rule pack`.
   - `packages/core/tests/scan-prompt-injection.test.ts` →
     `// warden: payload-fixture detector-test prompt-injection-pattern -- scanner test feeds attack strings as inputs`.
   - The four `malicious-*.md` files in `tests/fixtures/trapdoor/` →
     `<!-- warden: payload-fixture trapdoor-unicode -- ... -->`
     (regenerated through `tests/fixtures/_gen.ts` so the generator
     stays the source of truth).
   - The six positive fixtures in
     `tests/fixtures/prompt-injection/positive/` →
     `<!-- warden: payload-fixture prompt-injection-pattern -- ... -->`.
   - Benign fixtures get **no** marker (they pass clean naturally; the
     dogfood asserts this).
4. Remove from `.wardenignore`:
   - `tests/fixtures/`
   - `packages/rules/src/data/prompt-injection.ts`
   - `packages/core/tests/scan-prompt-injection.test.ts`
5. Remove the parallel `tests/fixtures/**` entry from the dogfood
   test's IGNORE list (it stops being needed once markers cover the
   files).
6. ADR 0008 §4: prepend a `**Superseded by ADR 0010 (M3.1, commit
   <SHA>).**` note. Do not rewrite the body — preserve the history.
7. ADR 0009: append a §3 footnote noting v2 absorbed
   `suppressedCount`, `suppressedByCategory`, `marker`, and
   `suppressedFindings*` in M3.1, with a pointer to §8 of this ADR.

---

## Consequences

**Positive:**

- The scanner's exclusion surface is per-file and visible in diffs.
- Cross-category poisoning is detected even in marked fixtures.
- The marker becomes a public convention: when M4 ships MCP-config
  scanning, real-world MCP fixtures in user repos use the same marker
  grammar (extended to JSON syntax in M4).
- ADR 0008 §4 stays in the repo as evidence that the project caught
  its own anti-pattern in review and corrected it. Public governance
  signal.

**Negative:**

- More files touched on each fixture addition (the contributor adds a
  marker, not just the file). Mitigated by the one-line marker length
  and a future linter that can suggest the family from path
  heuristics.
- Broad-scope families (`rules-data`, `detector-test`) are not fully
  defended at the tool level. We accept this for M3.1 with documented
  process mitigation; tightening is a future ADR.
- JSON / YAML / TOML fixtures stay outside marker coverage until M4.
  The operational rule in §7 prevents this from silently regressing.

---

## Revisit triggers

Reopen this ADR if any of:

- A real-world false negative is reported where a marker family
  suppressed a cross-category finding that should have fired.
- An attacker successfully ships a payload through `rules-data` or
  `detector-test` in production — promote pattern-aware suppression.
- A user community proposes a different marker grammar before the
  convention is widely adopted. The grammar is stable from M3.1
  onwards; breaking changes require a new ADR.
- The marker parser becomes a meaningful share of scan latency. (Not
  expected: marker is in the first ~10 lines of each file.)

Otherwise: leave the convention as written, extend file-type coverage
in M4.
