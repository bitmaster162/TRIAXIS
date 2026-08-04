# TRIAXIS v2.44-RC1 Recovery — Release Notes

## Closed defect

v2.43 prevented cross-namespace replay only inside one SQLite database. A
checkpoint copied to a fresh database had no signed namespace intent and could
be assigned to another namespace.

v2.44 introduces an Ed25519-signed checkpoint scope envelope bound to the exact
namespace digest, checkpoint receipt digest, trust-envelope digest, issuer and
validity interval. Verification occurs before state mutation, and the exact
scope row is persisted atomically with history/current state.

## Added

- `checkpoint_scope.py` verifier and schema projection.
- SQLite schema v3 with `checkpoint_scope`.
- `commit_scoped`, `load_guard_scoped`, and scope inspection.
- Legacy downgrade blocking after a lineage becomes scope-bound.
- Complete scope-history verification for scoped successors/restores.
- Frozen v3.8 closure and dedicated regression tests.

## Preserved

- v2.43 complete authenticated history.
- v2.42 same-database ownership.
- Exact retry, CAS and crash-atomic commit behavior.
- Legacy unscoped behavior for lineages that have never acquired scope rows.

## Compatibility

Schema v1 and v2 databases migrate transactionally to v3. Existing checkpoints
remain explicitly unscoped; migration does not invent authority scope.
