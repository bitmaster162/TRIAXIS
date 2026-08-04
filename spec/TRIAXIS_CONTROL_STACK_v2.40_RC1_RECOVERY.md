# TRIAXIS Control Stack v2.40-RC1 Recovery — Local Durable Checkpoint Store

## Status

```text
SPECIFICATION STATUS: Release Candidate under same-lineage validation
IMPLEMENTATION STATUS: Partially implemented — one-host SQLite durability
PRODUCTION-QUALIFIED: NO
EXTERNAL EXECUTION PERMISSION: NOT IMPLIED
```

## Added control

`SQLiteCheckpointStore` stores one namespace-scoped current head and immutable
ordered history. Receipt and signed envelope bytes are canonical JSON. Genesis or
successor admission validates the exact pair before entering one `BEGIN IMMEDIATE`
transaction; current-head and history writes commit together or roll back together.

## Concurrency rule

Every successor requires `expected_previous_head` equal to the durable current
head. The check and update occur under the same SQLite write transaction. A stale
writer returns `checkpoint_store_cas_mismatch` and cannot append history or change
the current row.

## Restart rule

`load_guard(...)` still requires a host-controlled expected checkpoint digest and
reuses the v2.39 signed-envelope restore boundary. The database is storage, not an
authority source.

## Scope limits

This establishes deterministic one-host/cooperating-process semantics under the
SQLite contract. It does not establish power-loss behavior on every filesystem,
whole-file anti-rollback, multi-host consensus, hostile administrator resistance,
HSM custody, independent certification or Production qualification.
