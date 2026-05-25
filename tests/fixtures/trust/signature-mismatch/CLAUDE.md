# Signature mismatch

The test signs an earlier byte sequence, then writes this content. The
on-disk hash diverges from the manifest's recorded hash, so `scanPath`
emits `trust.signature-mismatch` HIGH.
