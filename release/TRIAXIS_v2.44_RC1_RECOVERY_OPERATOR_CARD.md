# TRIAXIS v2.44-RC1 Recovery — Operator Card

1. Use `commit_scoped` for any checkpoint intended to survive database transport.
2. Bind scope to the exact namespace, checkpoint and trust-envelope digests.
3. Supply a host-controlled evaluation tick; commit requires it to match the checkpoint tick.
4. Do not treat a database-local ownership row as cross-database authorization.
5. Do not mix unscoped history with scoped successors without an explicit signed migration.
6. After the first scoped checkpoint, legacy commit/restore is a downgrade and is blocked.
7. `checkpoint_scope_history_incomplete` requires evidence-led recovery, not automatic repair.
8. Scope verification does not replace external expected-head anchoring or whole-database anti-rollback.
