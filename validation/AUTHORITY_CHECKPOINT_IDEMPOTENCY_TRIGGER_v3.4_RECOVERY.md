# TRIAXIS Authority Checkpoint Idempotency Trigger v3.4 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_CHECKPOINT_IDEMPOTENCY_TRIGGER_v3.4_RECOVERY
CANDIDATE_COMMIT: b16e203b8cf8280e09c5b897d5edf7dd87e760f1
CANDIDATE_TREE: 51749687a5e5b11e09e59d106277287134b35ba0
STATUS: Frozen post-product trigger
AUTHORED: after the v2.40 product commit and before any retry-reconciliation repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can the durable store reconcile a retry after an unknown commit outcome without
confusing it with a different stale writer?

## Risk

```text
SQLite COMMIT succeeds
→ process or response channel fails before caller receives the head
→ caller retries the exact request with the exact predecessor head
```

Rejecting the retry is safe from duplication but leaves the caller unable to
distinguish “already committed” from “not committed.” Blindly accepting every
stale request would be worse because it could hide a competing successor.

## Required invariant

```text
exact current receipt + exact current envelope
+ exact predecessor checkpoint head
=> idempotent success, no history append

same predecessor + different successor
=> checkpoint_store_cas_mismatch, no mutation

exact current pair + wrong predecessor claim
=> checkpoint_store_cas_mismatch
```

## Cases

```text
4 positive controls for v2.40 transactional behavior
6 idempotency/reconciliation cases
10 total cases
```
