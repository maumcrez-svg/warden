# Untrusted signer

The test builds a manifest whose `[[trust]]` entry was signed by a key
whose fingerprint is NOT in the synthesized `allowed_signers`.
`scanPath` emits `trust.untrusted-signer` HIGH.
