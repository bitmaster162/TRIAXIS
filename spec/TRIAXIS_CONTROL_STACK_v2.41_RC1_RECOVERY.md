# TRIAXIS Control Stack v2.41-RC1 Recovery — Exact Commit Reconciliation

## New invariant

```text
current durable head == requested checkpoint head
AND current receipt/envelope bytes == requested pair
AND immutable history contains the exact current row
AND caller names the exact predecessor checkpoint head
=> return current head idempotently; append nothing
```

A different successor, a false predecessor claim, missing history or any pair
mismatch remains fail-closed. This supports retry after an unknown response outcome
without converting stale-writer rejection into permissive replay.

## Scope

The contract is local-store idempotency, not network exactly-once delivery,
distributed consensus, whole-database anti-rollback or Production qualification.
