# TRIAXIS v2.42-RC1 Recovery — Release Notes

## Closed defect

The same authenticated checkpoint could previously be committed or copied into multiple logical namespaces in one SQLite database. v2.42 assigns each checkpoint and signed envelope identity one atomic database-wide namespace owner.

## Preserved

- Distinct authenticated checkpoint identities may occupy distinct namespaces.
- Exact retry in the owning namespace remains idempotent.
- Existing CAS, crash atomicity and lost-ack reconciliation behavior remains unchanged.

## Compatibility

Schema v1 is migrated transactionally to schema v2 only when ownership is unambiguous. Ambiguous legacy state is blocked.
