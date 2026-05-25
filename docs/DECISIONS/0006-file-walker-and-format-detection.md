# ADR 0006 — File walker semantics and format-detection scope

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M2 implementation review

---

## Context

M2 introduces a file walker and a format detector in `packages/core`,
feeding the `scanUnicode` engine landed in M1. Three implementation
choices needed to be pinned down before code shipped:

1. How `.gitignore` is honored.
2. Which paths are *always* ignored (regardless of `.gitignore`).
3. Whether the format detector covers only the named agent-context files
   from the ROADMAP scope or also generic Markdown.

This ADR records each choice and the constraints that drove it.

---

## Decision

### 1. Walker uses Bun's `Glob` + a small `.gitignore` parser

`Bun.Glob` (Bun 1.3.x) is the enumeration primitive; it does not parse
`.gitignore` syntax natively. Two alternatives were considered:

- **Add the `ignore` npm package** — battle-tested (Webpack, Prettier),
  zero runtime deps. Cost: one new dependency on `packages/core`'s
  budget of "< 10 deps" (CLAUDE.md §"Stack Constraints").
- **Hand-roll a minimal parser** — covers `#`-comments, blank lines,
  anchored (`/foo`) vs unanchored (`foo`) patterns, trailing-`/`
  directory-only markers, and the wildcards already understood by
  `Bun.Glob`.

We chose the hand-rolled parser (`packages/core/src/gitignore.ts`).
Reason: the warden repo's own `.gitignore` is simple, the M2 scope is
bounded, and adding `ignore` is reversible if a real-world `.gitignore`
exposes a gap. The parser is < 50 lines; the trade-offs are written
down here so a future maintainer can swap to `ignore` without rederiving
the design.

**Negation patterns (`!pattern`) are deliberately unsupported in M2.**
Correct negation requires preserving pattern order across the entire
file (and across nested `.gitignore`s); both add complexity that the
warden repo does not currently exercise. The parser records negation
lines under `unsupported` so the CLI can surface a warning. Tracked
for M3+ via the `unsupportedGitignorePatterns` field on `WalkResult`.

### 2. Always-ignored paths, regardless of `.gitignore`

The walker unconditionally skips:

```
**/.git/**
.git/**
**/node_modules/**
node_modules/**
```

Reason: `.git` contains commit blobs the scanner has no business
opening (and which would produce spurious findings for any commit that
touched a fixture); `node_modules` is third-party code outside the
project's authorship trust boundary. Even a project whose `.gitignore`
forgets `node_modules` (rare but possible) should never have third-party
content scanned as if it were first-party.

### 2a. `.wardenignore` for tool-specific exclusions

The walker also reads `.wardenignore` (same syntax as `.gitignore`).
Two problems make tool-specific ignores necessary alongside `.gitignore`:

- **Committed payloads.** A security tool's repository legitimately
  ships malicious fixtures under version control. Those fixtures
  belong in git (committers need to review them) but are noise during
  `warden scan .` on the same repository.
- **Non-context but committed files.** Bun's binary lockfile, vendored
  third-party docs, generated reports — committed for reproducibility,
  not authored as agent context.

A separate `.wardenignore` keeps the Warden carve-outs out of the
project's `.gitignore` (which is owned by git semantics) and avoids
abuse of `.gitignore` to influence tool behavior. This mirrors the
pattern established by ESLint, Prettier, Stylelint, and Biome (which
each ship `*ignore` files). Same parser as `.gitignore`; same M2
limitations apply (no negation, no nested files).

### 3. Generic-Markdown fallback (`kind: 'markdown'`)

The ROADMAP M2 scope lists named agent-context files (`CLAUDE.md`,
`AGENTS.md`, `.cursorrules`, etc.) plus "generic skill files". A literal
reading would scan only those named files. Two consequences forced a
wider net:

- **The M2 acceptance criterion** says `warden scan
  tests/fixtures/trapdoor/` must report N findings matching the M1
  count. The trapdoor fixtures are `*.md` files with non-canonical
  names (`malicious-tag-chars.md`, etc.) — they would all be skipped if
  only the named filenames were recognized.
- **The threat model itself.** TrapDoor (T1) and GlassWorm (T2) hide
  invisible Unicode in *any* Markdown an agent might read. Restricting
  the scanner to canonical filenames creates a trivial bypass: rename
  `CLAUDE.md` to `notes.md`, payload is invisible to Warden.

Therefore the detector returns `'markdown'` for any `*.md`, `*.mdc`, or
`*.markdown` file that does not match a more specific kind. The kind
distinction is preserved in the report (so users see at a glance whether
a finding hit a named context file or generic prose), but scanning
applies uniformly.

The false-positive surface is bounded by the walker (no `node_modules`,
no `.git`, plus `.gitignore`). The detector running over every
README/CHANGELOG/etc. is *intended* — those files are scanned by the
agent during onboarding sessions, and a Unicode payload in one is a
real threat surface.

### 4. Symlinks are not followed

`Bun.Glob.scanSync({ followSymlinks: false })` is the default and we
keep it. Following symlinks across the trust boundary of the scanned
root would let an attacker plant a `notes.md` that resolves to
`/etc/passwd` or a sibling repo. The walker treats the scanned root as
the trust boundary; symlinked content is outside it.

### 5. Deterministic ordering

The walker sorts its output lexicographically before returning. This is
the only guaranteed ordering across filesystems (APFS, ext4, NTFS each
expose different default orders). Reports must be diff-stable so
reviewers can compare two scans, and so CI snapshots remain meaningful.

---

## Consequences

**Positive:**
- Walker is < 100 lines, no new runtime dependency.
- Generic-markdown fallback closes the obvious rename-bypass.
- Deterministic output makes report diffs meaningful.
- Always-ignored paths protect against `.gitignore`-omission mistakes.

**Negative:**
- The hand-rolled `.gitignore` parser will miss negation and nested
  `.gitignore`s (the dominant unsupported case). The warden repo does
  not currently exercise these; outside repos will. Promotion to
  the `ignore` package is a clean swap when warranted.
- Generic-markdown scanning means a user with thousands of irrelevant
  `.md` files (e.g., a vendored documentation tree slipped past
  `.gitignore`) pays scan cost on them. The walker is fast (O(file
  count) + O(byte count)) but not free.

---

## Revisit triggers

Reopen this ADR if any of:

- A user reports `.gitignore` semantics diverging from `git
  check-ignore` on a real repo (promote to the `ignore` package).
- The generic-markdown fallback produces complaints about CHANGELOG /
  CONTRIBUTING / etc. being scanned (consider an exclusion list or a
  `--scope context-only` flag).
- A negation pattern is required by a first-class consumer (promote to
  the `ignore` package or implement negation support honestly).

Otherwise: leave the walker and detector as written.
