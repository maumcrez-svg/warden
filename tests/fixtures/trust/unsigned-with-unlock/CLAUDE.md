# Unsigned with unlock

The manifest has an `[[unlock]]` block for this path. `trust.unsigned`
is suppressed in default mode; `--strict` ignores the unlock and re-emits
the finding at HIGH (ADR 0012 §3 matrix and §4.4).
