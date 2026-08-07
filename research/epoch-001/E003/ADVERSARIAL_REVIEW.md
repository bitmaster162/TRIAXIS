# E003 — ADVERSARIAL REVIEW

## Auditor Attack Evaluation

1. **Attestation Replay**:
   - *Vector*: Replay an old, valid in-toto attestation for a superseded policy version.
   - *Finding*: Mitigated by exact Git tree binding (`HEAD:src`) and in-toto finishedOn / max clock skew validation (`ATTESTATION_EXPIRED`).

2. **Log Omission / False Statements**:
   - *Vector*: Generate valid signature off-log to avoid public auditability.
   - *Finding*: Mitigated by mandatory Rekor SET inclusion proof verification (`MISSING_INCLUSION_PROOF` -> `DENY`).

3. **Key Compromise Window**:
   - *Vector*: Key compromised after attestation generation.
   - *Finding*: Rekor integrated timestamp proves the signature was logged *before* key revocation, preventing backdated forgery.
