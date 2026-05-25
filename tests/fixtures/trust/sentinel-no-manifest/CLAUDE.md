# Sentinel without manifest

The fixture commits the sentinel `.warden/trust-required` but no
manifest. `scanPath` treats every walked context file as
`trust.unsigned` HIGH and exits 1 (ADR 0012 §3 matrix row "scan,
sentinel present, manifest absent").
