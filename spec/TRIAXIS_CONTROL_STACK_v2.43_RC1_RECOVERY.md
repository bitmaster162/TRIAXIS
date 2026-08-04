# TRIAXIS Control Stack v2.43-RC1 Recovery — Complete Durable History

## New invariant

```text
non-empty namespace
→ immutable history sequences are exactly 1..current.sequence
→ history tip is byte-exact current state
→ every successor names the previous envelope
→ time and authority-root identity remain monotonic
→ every history receipt/envelope authenticates
```

`get_current()`, `history()`, `load_guard()` and `commit()` validate the complete namespace history before exposing or advancing state.

## Canonical failures

```text
checkpoint_store_history_incomplete
checkpoint_store_history_chain_mismatch
checkpoint_store_current_not_history_tip
checkpoint_store_corrupt_state
```

## Security effect

The store no longer accepts a genuine current checkpoint while presenting a truncated, gapped, foreign-parent or ahead-of-current audit trail.

## Scope

This is internal database-history integrity. It does not prevent replacement of the entire database together with a stale external expected-head anchor, and it does not provide distributed consensus or hostile-administrator resistance.
