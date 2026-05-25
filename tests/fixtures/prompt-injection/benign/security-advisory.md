# Security Advisory — CVE-2025-53773

**Status:** Disclosed
**Component:** GitHub Copilot PR-description ingestion path
**Severity:** High

## Summary

A vulnerability was reported under the identifier CVE-2025-53773 in which
attacker-controlled text embedded in a pull-request description was
processed by the assistant as if it had been authored by the repository
owner. The class is generally referred to as indirect prompt injection.

## Impact

An attacker who could open a pull request against a repository could
cause an integrated assistant to follow embedded directives — for
example, surfacing private repository contents to the diff view or
suggesting changes that exfiltrate environment variables.

## Mitigation

Upgrade to the patched version of the affected component. Where an
upgrade is not yet available, configure the assistant to treat PR
descriptions as untrusted by default and require maintainer
acknowledgement before consuming them.

## References

- CVE-2025-53773 — NVD entry verification pending.
- Warden THREAT_MODEL §T4.
