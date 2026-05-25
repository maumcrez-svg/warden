# Trust fixture pack — M5 / ADR 0012

Each subdirectory is a scenario from ADR 0012 §3 (default-behavior matrix)
and §"Fixtures" (acceptance criteria). The directories carry the *static*
inputs (content files only); the dynamic trust state (signed manifest,
allowed_signers) is synthesized per-test in a temporary directory by
`packages/core/tests/scan-path-trust.test.ts`. This keeps the working tree
free of generated artifacts and avoids committing test-only key material.

| Fixture                  | Manifest         | Content on disk                 | Expected outcome                                     |
|--------------------------|------------------|---------------------------------|------------------------------------------------------|
| `signed-clean/`          | valid `[[trust]]`| matches manifest hash           | clean, exit 0                                        |
| `signature-mismatch/`    | valid `[[trust]]`| one byte changed after sign     | `trust.signature-mismatch` HIGH, exit 1              |
| `untrusted-signer/`      | valid `[[trust]]`| signed by key NOT in allowed_signers | `trust.untrusted-signer` HIGH, exit 1            |
| `unsigned-with-manifest/`| no entry for file| file unsigned                   | `trust.unsigned` MEDIUM (default), HIGH (strict)     |
| `unsigned-with-unlock/`  | `[[unlock]]` only| file unsigned                   | suppressed by unlock (default), HIGH (strict)        |
| `orphan-entry/`          | entry for absent file | absent on disk             | `trust.orphan-entry` LOW (default), MEDIUM (strict)  |
| `sentinel-no-manifest/`  | absent           | sentinel `trust-required` present | `trust.unsigned` HIGH for every file, exit 1      |

The broad-marker × trust interaction (ADR 0012 §7 row 3) is not represented
here as a directory — broad-scope marker families are path-restricted to
`packages/rules/src/data/**` and `packages/*/tests/**`, so a fixture
directory at `tests/fixtures/trust/...` could not carry a broad marker
without changing the marker parser's path restrictions. Coverage for that
interaction lives in `packages/core/tests/trust-scan.test.ts` ("broad-marker
+ unsigned → trust.unsigned elevated to HIGH").
