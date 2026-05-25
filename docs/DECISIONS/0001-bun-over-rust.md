# ADR 0001 — Bun over Rust for the MVP

**Status:** Accepted
**Date:** 2026-05-24
**Deciders:** Project bootstrap (initial maintainer)

---

## Context

The Warden CLI runs on developer laptops and CI runners. The hot path is byte-level Unicode scanning across collections of small-to-medium text files (typical agent context files: 1–50 KB; rule packs: 10–500 KB; MCP configs: < 5 KB). The product window is short — the TrapDoor news cycle (May 2026) is the wedge — and a competing OSS option could appear within months.

Three viable runtimes were considered:

1. **Rust** — single binary, fast cold start, no runtime to install, strong safety guarantees. Cost: months of build-out before a usable v0.1, smaller ecosystem for Markdown/JSON/MCP parsing helpers, higher contributor friction.
2. **Go** — single binary, decent cold start, large stdlib. Cost: ergonomically painful for the kind of string scanning we do; weaker TS/JS interop story for MCP and skill formats that originate in the JS ecosystem.
3. **TypeScript on Bun** — fastest time-to-first-finding, single-binary distribution via `bun build --compile`, native TS without a build step, JavaScript ecosystem for parsing the formats agents natively use. Cost: Bun is younger than Node/Deno; one company stewards it; pure-CPU performance ceiling lower than Rust.

---

## Decision

Build the MVP (M0–M6) in **TypeScript on Bun**.

Rationale:
- **Time-to-market dominates.** The wedge is the news cycle. A working `warden scan` shipped in weeks beats a slightly faster scanner shipped in months.
- **The formats we parse are JavaScript-native.** MCP configs, Cursor rules, Claude skills — all originated in the JS ecosystem. Reaching for their reference parsers is one `bun add` away in TS; it is an FFI/port project in Rust.
- **Single-binary distribution is solved.** `bun build --compile` produces a standalone binary for the curl-pipe install path. Users without Node/Bun installed get the binary; users with Node/Bun get a fast `bunx` path. Three distribution channels, one codebase.
- **Contributor accessibility.** TypeScript is the dominant language among the target user (AI-native indie devs). PR friction matters for an OSS tool.

---

## Consequences

**Positive:**
- M1 detector ships in days, not weeks.
- One codebase, three install paths (npm, bunx, curl-binary).
- Test runner, formatter (Biome), and types come for free.

**Negative:**
- Cold-start time is bounded by Bun startup (~30 ms on a modern Mac). Acceptable for a CLI invoked once per scan; problematic for a hot-loop daemon (not a use case we have).
- We carry Bun as a runtime dependency. If Bun's stewardship deteriorates, we have a migration cost.
- Pure-CPU performance ceiling is below Rust. If telemetry (post-MVP, opt-in) ever shows scan time as the user complaint, hot-path code becomes a candidate for Rust rewrite.

**Mitigations baked in:**
- Hot-path code lives in `packages/core` only and is pure functions, making a future Rust rewrite of `packages/core` (with TS bindings) a contained refactor, not a project re-architecture.
- The scanner does no I/O beyond filesystem reads, so a Rust rewrite would not require re-deriving network or shell-out behavior.

---

## Revisit triggers

Reopen this ADR if any of:
- Bun's release cadence stalls for > 6 months.
- A scan of a 100-file repo regularly exceeds 2 seconds on a 2024-class laptop.
- A meaningful share of users report "I can't install Bun" friction in install telemetry (post-MVP, opt-in only).

Otherwise: do not revisit. Cost of switching ports is high; the bar to flip is high.
