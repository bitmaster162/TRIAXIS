# TRIAXIS v3.7-RC1 Operator Card

Do not build the active operational trust registry directly from arbitrary key records.

Required path:

1. Pin the root public key out-of-band.
2. Verify and install sequence 1.
3. Install only exact parent-linked successors.
4. Load the operational `TrustKeyRegistry` from `SQLiteTrustRegistryStore`.
5. Reject rollback, fork, gap, root-signature failure or expired snapshot.

Back up the SQLite store, but do not treat backups as an anti-rollback mechanism. Use an external minimum accepted sequence before production deployment.
