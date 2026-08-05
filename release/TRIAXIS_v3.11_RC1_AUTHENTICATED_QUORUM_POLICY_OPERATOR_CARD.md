# TRIAXIS v3.11-RC1 Operator Card

1. Provision the quorum-policy root separately from anchor signing keys.
2. Install only root-signed sequential policy versions.
3. Never pass quorum threshold or anchor membership from an LLM or request payload.
4. Require every anchor witness to bind the exact current policy digest.
5. Reject signers, keys, anchor IDs or trust domains absent from current policy.
6. Reject policy rollback, version gaps, parent mismatch and forged root signatures.

Protect the entire policy-store database from rollback. v3.11 local monotonicity cannot detect restoration of the whole database by itself.
