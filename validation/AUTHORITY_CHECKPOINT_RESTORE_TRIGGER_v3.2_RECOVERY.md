# TRIAXIS Authority Checkpoint Restore Trigger v3.2 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_CHECKPOINT_RESTORE_TRIGGER_v3.2_RECOVERY
CANDIDATE_COMMIT: c6f31e1d0797b2c2d067f80241011d4808e067f4
CANDIDATE_TREE: 893cb92e8071d863a4b541f9c645c95e257798a3
STATUS: Frozen post-product trigger
AUTHORED: after the v2.38 product commit and before any restart-continuity repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can a fresh process restore an exact accepted trust checkpoint only from:

1. a valid v3 public checkpoint receipt;
2. the exact signed trust envelope represented by that receipt; and
3. a host-provided expected checkpoint digest stored outside the process?

## Risk

A self-digest makes a receipt tamper-evident but not authentic or current. Without
an authenticated envelope and an external expected-head anchor, restart may accept
an invented receipt, pair a receipt with the wrong envelope, or roll state back to
an older yet individually valid checkpoint.

## Required invariant

```text
restore_allowed
=> receipt validator PASS
AND signed envelope authentic under configured authority roots
AND every receipt identity/time/digest/parent field equals that envelope
AND expected_checkpoint_sha256 == receipt.checkpoint_sha256
```

After restore, ordinary monotonic rules remain active:

```text
replay restored head     -> BLOCK
exact successor          -> PASS
older receipt + newer external head anchor -> BLOCK
```

## Cases

```text
4 positive controls for existing in-process behavior
6 restart/authentication/rollback cases
10 total cases
```
