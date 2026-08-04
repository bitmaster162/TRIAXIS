# TRIAXIS v2.39-RC1 Recovery — Operator Card

1. Persist the exact v3 checkpoint receipt and signed envelope together.
2. Persist `checkpoint_sha256` in a separate host-controlled latest-head anchor.
3. On restart call `ProvenanceTrustStateGuard.from_checkpoint(...)` with all three.
4. Never treat a receipt self-digest as proof of authorship or latest state.
5. Reject any receipt/envelope field mismatch.
6. Reject an older valid pair when the external anchor names a newer head.
7. Rotate the durable anchor only after the new checkpoint commit is accepted.
8. Keep external actions separately authorized; restore does not grant execution.
