# TRIAXIS Authority Checkpoint Durability Trigger v3.3 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_CHECKPOINT_DURABILITY_TRIGGER_v3.3_RECOVERY
CANDIDATE_COMMIT: 3ae20af5e735128d3ea8e219e11d4d2c6e1893da
CANDIDATE_TREE: 04a5e2458e010a92301e318d35f854ab38983219
STATUS: Frozen post-product trigger
AUTHORED: after the v2.39 product commit and before any durable-store repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can one local host persist receipt, signed envelope and current head as one
transactional state, reopen it after process loss, reject stale writers and leave
the durable head unchanged on invalid input?

## Risk

v2.39 authenticates an exact restart pair, but durable coordination is delegated
to the caller. Separate writes can create split state:

```text
receipt written, head not written
head written, envelope not written
new process reads mixed generations
concurrent writers overwrite one another
```

## Required local-store contract

```text
SQLiteCheckpointStore(path, namespace)
.commit(..., expected_previous_head)
.load_guard(..., expected_checkpoint_sha256)
.get_current()
.history()
```

A commit must validate the exact receipt/envelope pair, enforce sequence, parent,
root continuity and compare-and-swap under one SQLite transaction. Invalid input
or stale CAS must not change the durable current row or append history.

## Cases

```text
4 positive controls for v2.39 restore behavior
6 durable transaction/reopen/CAS cases
10 total cases
```

## Non-claim

Passing a SQLite protocol does not prove power-loss behavior on every filesystem,
whole-database anti-rollback, multi-host consensus or Production qualification.
The host-controlled expected-head anchor remains required when loading state.
