# TRIAXIS Authority Checkpoint History Integrity Trigger v3.7 Recovery

## Candidate

- Version: `TRIAXIS v2.42-RC1 Recovery`
- Commit: `a85bd5cfd9268922f0cf1f9ef3bebff51dc490a4`
- Tree: `796704b37cc4c6bf5b448146701eb4c055bdc4a9`

## Question

Can current checkpoint state be restored while its supposedly immutable history is truncated, gapped, replaced, or ahead of current?

## Required invariant

```text
for each non-empty namespace:
history sequences == 1..current.sequence
AND history tip == current exact pair
AND every successor parent == previous envelope
AND every history row has exact namespace ownership
```

## Canonical blocks

```text
checkpoint_store_history_incomplete
checkpoint_store_history_chain_mismatch
checkpoint_store_current_not_history_tip
```

## Scope

This protocol checks internal history completeness and continuity in one SQLite database. It does not prove whole-database anti-rollback against replacement of the entire database and external expected-head anchor together.
