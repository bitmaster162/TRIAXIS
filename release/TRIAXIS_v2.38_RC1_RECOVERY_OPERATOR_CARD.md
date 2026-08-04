# TRIAXIS v2.38-RC1 Recovery — Operator Card

```text
1. Persist the complete v3 checkpoint receipt, not an ad hoc subset.
2. Genesis previous_envelope_sha256 is explicit null.
3. Successor previous_envelope_sha256 is the exact parent envelope digest.
4. Verify checkpoint_sha256 before trusting any receipt field.
5. Reject unknown, missing, mistyped or tampered receipt fields.
6. Do not confuse a self-digest with an external timestamp or signature.
7. Preserve receipt bytes alongside the execution/evidence manifest.
8. Keep durable-ledger and multi-writer guarantees outside current claims.
9. Analytical PASS does not imply external execution permission.
```
