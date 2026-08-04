# TRIAXIS Control Stack v2.42-RC1 Recovery — Durable Namespace Confinement

## New invariant

```text
within one SQLite checkpoint database:
one checkpoint_sha256 / envelope_sha256 identity
→ exactly one durable namespace owner
```

Namespace ownership is claimed in the same `BEGIN IMMEDIATE` transaction that appends immutable history and advances current state. A concurrent or later claim from another namespace is blocked as `checkpoint_store_namespace_replay`.

## Read and migration behavior

- `get_current()`, `history()`, restore, and idempotent reconciliation verify ownership.
- Missing owner state is corruption.
- A v1 database migrates only when every checkpoint/envelope identity has one unambiguous namespace.
- A vulnerable v1 database containing the same identity in multiple namespaces is rejected; migration does not choose a winner silently.

## Scope

The contract provides same-database namespace confinement for cooperating callers and corruption detection. It does not provide cryptographic namespace intent across independent database files, whole-database anti-rollback, hostile local-administrator resistance, multi-host consensus, or Production qualification.
