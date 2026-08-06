# TRIAXIS v3.31 external-effect control-plane reference

v3.31 retains the cumulative state domains from v3.30 and adds two controls:

1. an operator-pinned availability policy requiring one fresh statement from
   every configured completion witness for `HIGH` and `CRITICAL` effects;
2. a separate content-addressed completion anchor using write-once `O_EXCL`
   objects, signed append-only events and a verifier-side monotonic checkpoint.

A missing, stale, invalid or equivocal completion witness is non-permissive.
This closes the v3.30 availability gap where a current blocking minority could
be omitted and treated as unavailable.

The filesystem anchor has no overwrite or delete API and rejects content-address
conflicts. The verifier checkpoint detects an older or forked signed anchor head
while that checkpoint remains current. This is an executable logical reference,
not physical WORM media, independent administration, KMS/HSM custody or
hardware-backed monotonic state.

No component grants action authority. A same-host deployment proves only
protocol interoperability and negative-test behavior. It does not establish
physical independence, immutable infrastructure or production exactly-once
execution.
