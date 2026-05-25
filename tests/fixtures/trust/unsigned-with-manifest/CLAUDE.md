# Unsigned with manifest

The manifest exists (signing a different file) but has no `[[trust]]`
entry for THIS file. `scanPath` emits `trust.unsigned` MEDIUM by default,
HIGH under `--strict`.
