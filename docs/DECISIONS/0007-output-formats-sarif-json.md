# ADR 0007 — Output formats: pretty, JSON, SARIF 2.1.0

**Status:** Accepted
**Date:** 2026-05-25
**Deciders:** M2 implementation review

---

## Context

M2 ships the `warden scan` CLI with three output modes: pretty
terminal (default), `--json`, and `--sarif`. Each mode has its own
stability promise and consumer. Three decisions needed to be pinned
down before code shipped:

1. The shape and stability of the `--json` payload.
2. The SARIF version (2.1.0) and the validator strategy.
3. The exit-code policy across all three modes.

---

## Decision

### 1. JSON format — `warden/scan/v1`

`--json` emits a single object with a leading `version` field equal to
`warden/scan/v1`. The fields in this version are frozen for the lifetime
of `v1`; additive fields require `v2`. The full shape:

```jsonc
{
  "version": "warden/scan/v1",
  "tool": { "name": "warden", "version": "<semver>" },
  "root": "<absolute>",
  "scannedAt": "<ISO 8601>",
  "fileCount": 4,
  "matchedCount": 4,
  "findingCount": 95,
  "highCount": 90,
  "mediumCount": 0,
  "lowCount": 5,
  "unsupportedGitignorePatterns": [],
  "files": [
    {
      "path": "tests/fixtures/trapdoor/malicious-tag-chars.md",
      "kind": "markdown",
      "findings": [
        {
          "ruleId": "unicode.tag-chars",
          "threatIds": ["T1", "T2"],
          "rangeName": "Tag chars",
          "codepoint": 917536,
          "byteOffset": 51,
          "severity": "high",
          "kind": "always-suspicious"
        }
      ]
    }
  ]
}
```

The version string is the contract. If we have to break it, we bump to
`warden/scan/v2`; downstream consumers can branch on the leading
discriminator without parsing the rest.

### 2. SARIF 2.1.0

`--sarif` emits a SARIF 2.1.0 document. Version chosen because it is the
current OASIS standard (TC document, March 2020) and is what GitHub Code
Scanning, Sonatype, and Snyk consume. The document references the schema
at `https://json.schemastore.org/sarif-2.1.0.json` via `$schema`.

We emit the minimum compliant document:

- `$schema`, `version`, `runs`.
- Per run: `tool.driver.name`, `tool.driver.version`,
  `tool.driver.informationUri`, `tool.driver.rules[]`, `results[]`.
- Per result: `ruleId`, `level`, `message.text`, `locations[]`.
- Per location: `physicalLocation.artifactLocation.uri` (relative to the
  scanned root) plus `region.byteOffset` and `region.byteLength`.

Severity mapping:

| Warden severity | SARIF level |
|-----------------|-------------|
| high            | error       |
| medium          | warning     |
| low             | note        |

**Validation strategy:** the test suite asserts the structural
invariants of SARIF 2.1.0 (required-field presence, level enum, version
string) on the emitted document. We do not bundle a JSON Schema runtime
into the CLI. Rationale:

- Shipping `ajv` + the SARIF schema would add ~250 KB to the CLI bundle
  for a feature already covered by a per-test structural assertion.
- The structural assertions cover every field we emit, and our emitter
  cannot produce fields we do not test.
- Users who want full JSON-Schema validation can pipe to any standard
  SARIF validator (`sarif-multitool validate`, GitHub's online tool,
  etc.). That is the same model the spec assumes.

If a real-world SARIF consumer reports a validation failure, the
remediation is to add the field to the emitter and to the structural
test. The promise we make is "valid SARIF 2.1.0 for the fields we
emit", not "every optional field is also valid".

### 3. Exit-code policy

| Condition                                  | Exit code |
|--------------------------------------------|-----------|
| Scan completed; zero high-severity findings| 0         |
| Scan completed; ≥ 1 high-severity finding  | 1         |
| Invocation error (bad path, etc.)          | 2         |

Why "high only" gates exit 1: medium and low findings are advisory and
do not interrupt a CI pipeline. high-severity Unicode findings (tag
chars, bidi overrides, density violations) correspond to the threats
the tool exists to surface — those are the gating signal.

`--quiet` does not change the exit code. It only suppresses per-finding
output in the pretty reporter; the summary line and exit code are
unchanged.

The README's promise ("exits non-zero on any high-severity hit") aligns
with this table.

---

## Consequences

**Positive:**
- Three reporters, one pipeline. The CLI is a thin shell over
  `scanPath` from `packages/core`.
- The `warden/scan/v1` discriminator lets us evolve JSON without
  breaking existing parsers.
- Exit code is predictable for CI integrators.

**Negative:**
- We promise SARIF validity only for the fields we emit. A SARIF
  consumer that requires a not-yet-emitted optional field will need an
  emitter change, not a config knob.
- Pretty output is opinionated about layout; a user who wants
  alternative ergonomics has to take JSON and pipe to `jq`.

---

## Revisit triggers

Reopen this ADR if any of:

- A SARIF consumer rejects our output against a published validator
  (add the field, write the test, leave the ADR in place).
- The exit-code policy is reported as too quiet (medium findings
  silently allowed through CI) or too noisy (high-but-acceptable
  findings blocking everything). The right response is a
  `--fail-on=<severity>` flag, not a policy reversal.
- A second tool wants to consume `warden`'s JSON and the `v1` contract
  needs to evolve — bump to `v2` and document the diff.

Otherwise: leave the formats and exit policy as written.
