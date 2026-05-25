---
description: Execute a single milestone from docs/ROADMAP.md with full discipline.
argument-hint: <milestone-number>
---

# /milestone $ARGUMENTS

You are executing **milestone $ARGUMENTS** from `docs/ROADMAP.md`. Follow these rules strictly. No exceptions.

## Pre-flight (read before writing any code)

1. Open `docs/ROADMAP.md` and locate the section for milestone $ARGUMENTS. Read scope, in-scope, out-of-scope, acceptance criteria, demo command.
2. If this milestone adds or modifies a detection rule, open `docs/THREAT_MODEL.md` and identify the threat IDs covered (T1, T2, …). Every rule must cite at least one.
3. Open `CLAUDE.md` to refresh stack constraints, verification policy, and anti-patterns.

## Execution

- Implement **exactly** the scope listed under "In-scope" for milestone $ARGUMENTS. Nothing more.
- Reject anything that creeps into "Out-of-scope" — defer it to a new milestone via a new entry in `docs/ROADMAP.md`.

For each new detection rule:
- Cite the threat in a code comment, referencing the report URL or CVE.
- Add at least one **malicious** fixture and one **benign edge-case** fixture under `tests/fixtures/<threat-name>/`.
- Add a unit test exercising the rule against both fixture classes.

For each new package or surface-level architectural change:
- Add an ADR under `docs/DECISIONS/`. Number it as the next available integer.

For each new dependency:
- Pin with `--exact`.
- Justify in the commit message body.
- Confirm the dep does not violate the architectural constraints in `docs/ARCHITECTURE.md` §5 (no network on hot path, no spawn-to-introspect, etc.).

## Closing

1. Run `/verify` — must pass. Do not commit on failure.
2. Run `warden scan .` on the Warden repo itself (dogfood) — must report 0 high-severity findings.
3. Update `docs/ROADMAP.md`: flip milestone $ARGUMENTS status marker from 🟦 to ✅ and link the commit SHA when known.
4. Stage and commit with a Conventional Commit message in the form:
   `feat(<scope>): M$ARGUMENTS — <one-line summary>`
   The body cites threat IDs and notes any new deps.
5. Print a single-line CLI demo proving the milestone works, prefixed `M$ARGUMENTS demo: `.

## Anti-Patterns (Refuse)

- Do **not** chain into milestone $((ARGUMENTS + 1)) in the same session. Stop after closing this one. Open a fresh session for the next milestone.
- Do **not** commit if `/verify` reports any failure. Fix or defer; never bypass.
- Do **not** use `--no-verify`, `--no-gpg-sign`, or any hook-skip flag.
- Do **not** add dependencies without recording them in the commit message body.
- Do **not** invent a citation. If a threat report cannot be located, the rule does not ship.
