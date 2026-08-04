# TRIAXIS v2.40-RC1 Recovery — Release Notes

## Closed defect

Receipt, signed envelope and current head can now be committed and reopened as one
namespace-scoped local transactional state instead of three caller-managed writes.

## Added

- `SQLiteCheckpointStore` and `CheckpointStoreError`;
- canonical receipt/envelope BLOB storage;
- immutable ordered history;
- `BEGIN IMMEDIATE`, `synchronous=FULL`, WAL and CAS;
- state-neutral rollback on invalid pair or stale writer;
- clean reopen through authenticated v2.39 restore;
- frozen v3.3 durability closure.

## Non-claims

No whole-database anti-rollback, multi-host consensus or universal power-loss proof.
