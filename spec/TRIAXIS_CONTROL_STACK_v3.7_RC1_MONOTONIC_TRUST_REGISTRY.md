# TRIAXIS Control Stack v3.7-RC1 — Monotonic Trust Registry

## Status

Release Candidate. Not production-qualified. External execution permission is not implied.

## Defect closed

v3.6 authenticated individual contracts but accepted whichever `TrustKeyRegistry` object the caller supplied. Restoring an older registry snapshot could resurrect a key revoked in a newer snapshot.

## New registry state model

v3.7 introduces:

- root-signed registry snapshots;
- stable `registry_id`;
- monotonic integer `sequence`;
- exact `parent_snapshot_sha256` linkage;
- canonical sorted key records;
- SQLite WAL/FULL durable head;
- exact-idempotent reinstall;
- rejection of rollback, fork, parent substitution and sequence gaps;
- verification again after restart before a registry is loaded.

## Trust model

The root public key remains an out-of-band trust anchor. Snapshot signing uses the `TRUST_REGISTRY_SNAPSHOT` key purpose. Operational keys cannot sign registry state unless separately authorized for that purpose.

## Invariants

1. Sequence 1 has no parent.
2. A successor sequence equals current sequence + 1.
3. A successor parent equals the exact current snapshot digest.
4. A lower or conflicting sequence is rejected.
5. The signed snapshot and SQLite row must agree on sequence and digest.
6. Loading returns only keys from the verified current head.
7. Revocation in the current head cannot be bypassed by reinstalling an older snapshot into the same store.

## Explicit boundary

This release does not prevent whole-database rollback. If an attacker restores an older SQLite file together with its valid signed snapshot, local state alone cannot know a newer head existed. A hardware, remote or quorum monotonic anchor is still required.
