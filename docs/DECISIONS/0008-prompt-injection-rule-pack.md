# ADR 0008 — Prompt-injection rule pack design

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M3 implementation review

---

## Context

M3 ships rule-based prompt-injection detection in
`packages/rules/src/data/prompt-injection.ts`, exposed through
`scanPromptInjection(input: string): PromptInjectionFinding[]` in
`packages/core`. Threat coverage is T4 (CVE-2025-53773 family of indirect
prompt injection in agent-visible files) from `docs/THREAT_MODEL.md`.

Three things needed to be pinned down before code shipped:

1. The tier model (how a rule's "kind" maps to severity).
2. The pattern-design rule (how narrow each regex should be).
3. The citation policy (what counts as a primary source).

The acceptance criterion that drove all three: **zero false positives on
the M3 benign fixture set** (academic paper that describes attacks;
fictional dialogue containing "you are now"; security advisory quoting
CVE-2025-53773).

---

## Decision

### 1. Three-tier model with fixed tier → severity map

Each rule declares a `tier` and a `severity`. The map is fixed:

| Tier        | Severity | Meaning                                                                                     |
|-------------|----------|---------------------------------------------------------------------------------------------|
| verbatim    | high     | Exact known-payload string or near-canonical phrasing; zero legitimate use in agent prose.  |
| suspicious  | medium   | Narrowly-scoped attack phrasing; benign prose can be written to avoid it without contortion.|
| stylistic   | low      | Attack-adjacent shape with plausible benign use; advisory only.                             |

The map is enforced by a unit test
(`scan-prompt-injection.test.ts` → "rule data integrity"). A rule with
mismatched tier and severity fails CI.

Rationale: a single tier-to-severity table keeps the tier label honest
(authors cannot quietly downgrade a "verbatim" rule to medium when a
false-positive bites) and keeps reporter output predictable.

### 2. Pattern-design rule: narrow enough to survive the benign fixtures

Each rule's regex is scoped narrowly enough that the three M3 benign
fixtures pass with zero findings. Concretely:

- The override imperative requires verb + scope + target in the same
  span; the academic-paper fixture talks *about* override attacks without
  ever composing the full grammatical shape.
- The persona-shift rule requires `you are now` to be followed by a
  known jailbreak keyword (DAN, developer-mode, jailbroken, unrestricted,
  uncensored, free-from-restrictions, operating-without). Fictional
  dialogue ("you are now beyond the borderlands") fails the alternation.
- The CVE quote in the security advisory describes the vulnerability
  without reproducing a verbatim attack payload.

This is the "describe-without-reproducing" discipline applied to the
detector. The trade-off is acknowledged: a paraphrased novel attack
("disregard upstream context") may evade. Sequenced response — broader
detection (code-fence awareness, content-type gating, semantic
classification) is deferred to a future T5+ promotion with its own
fixtures and threshold derivation.

### 3. Citation policy: published primary sources only

Every rule cites at least one of:

- A peer-reviewed or arXiv-published paper (Perez & Ribeiro 2022,
  Greshake et al. 2023, Llama 2 paper).
- The OWASP LLM Top 10 standard (LLM01:2025 Prompt Injection).
- A vendor-published format specification (OpenAI ChatML).

CVE-2025-53773 itself is referenced as the threat ID (T4) but is **not**
cited as the rule's authoritative source while its NVD entry is unverified
(see `docs/THREAT_MODEL.md` §Citation Verification — Pending). When NVD
verification completes, the per-rule citations are updated to add the
NVD URL where applicable.

Every rule records `verifiedDate` (ISO date) on which a maintainer
confirmed the cited source resolved. The unit test asserts the field is
present and well-formed; it does not re-fetch the URL on every CI run
(out-of-band link-rot tracking belongs in a future maintenance loop).

### 4. Dogfood interaction

> **Superseded by ADR 0010 (M3.1, commit `461d468`).** The
> `.wardenignore`-based exclusion described below was the wrong shape
> for a security tool — review found that whole-file glob exclusion
> turns the exclusion list into an attacker entry point, since payload
> content in `packages/rules/src/data/prompt-injection.ts`,
> `packages/core/tests/scan-prompt-injection.test.ts`, or any file
> under `tests/fixtures/` would be invisible to `warden scan .`. M3.1
> replaces the .wardenignore entries with per-file inline
> `payload-fixture` markers that keep the files in scan scope and
> only suppress the declared finding categories (cross-category
> poisoning still fires). The section below is preserved as the
> historical record of the M3 decision and why it had to be revised
> one day later.

The dogfood scan (`warden scan .` and `tests/dogfood.test.ts`) runs the
prompt-injection scanner over Warden's own first-party files. Two files
necessarily contain attack strings as inputs and are excluded via
`.wardenignore` and a parallel `PROMPT_INJECTION_EXTRA_IGNORE` list in
the dogfood test:

- `packages/rules/src/data/prompt-injection.ts` — the rule data is
  authored attack patterns.
- `packages/core/tests/scan-prompt-injection.test.ts` — the scanner
  test feeds attack strings as inputs.

Authoritative spec text was rewritten to describe attack families
without reproducing the trigger phrasings, so `docs/ROADMAP.md` and
`docs/THREAT_MODEL.md` pass dogfood without an ignore entry. This is
intentional: docs that need an ignore are docs that have drifted from
the describe-without-reproducing discipline, and the absence of an
ignore is the forcing function.

---

## Consequences

**Positive:**
- The tier → severity table is auditable in one place and enforced.
- The pattern-design discipline produces a rule pack that survives its
  own documentation: an author cannot ship a rule whose patterns
  trigger on the M3 benign fixtures or on Warden's own docs.
- Citation policy aligns with the existing Unicode-rule citation policy
  (THREAT_MODEL §Citation Policy): primary source + verified date.

**Negative:**
- Narrow patterns miss paraphrased attacks. This is explicit; the
  alternative (broader patterns + post-hoc context gating) would have
  failed the M3 benign-fixture acceptance criterion.
- Two source files are .wardenignore'd. The set is small and named; if
  it grows beyond ~5 entries the convention should be reconsidered.

---

## Revisit triggers

Reopen this ADR if any of:

- A real-world prompt-injection variant is reported that the narrow
  patterns miss in a way that broader detection (code-fence awareness,
  content-type gating, semantic classification) would have caught.
- The CVE-2025-53773 NVD entry verification completes and the published
  payload diverges from the patterns we currently match.
- A new rule cannot be defended with a published primary source — at
  which point the rule does not ship, per project policy.
- The ignore list of dogfood-excluded files grows beyond a small, named
  set. The right response is probably an inline marker convention
  (`// warden-allow: prompt-injection-self-test`), not more ignores.

Otherwise: leave the tier model, pattern policy, and citation discipline
as written.
