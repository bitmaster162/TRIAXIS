# TRIAXIS Authority Checkpoint Receipt Trigger v3.1 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_CHECKPOINT_RECEIPT_TRIGGER_v3.1_RECOVERY
CANDIDATE_COMMIT: 1bbc5b7d5861856eee030544c44ee3ba2cf9fe78
CANDIDATE_TREE: dc1fb2ca3b5ed81cf3937df819dc676e19a4db9c
STATUS: Frozen post-product trigger
AUTHORED: after v2.37 product commit and before receipt repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Does the public checkpoint receipt preserve exact chain parentage and carry a
self-verifiable canonical digest?

## Required receipt

```text
contract_id
sequence
envelope_sha256
snapshot_sha256
previous_envelope_sha256
issued_at
evaluation_tick
authority_id
key_id
authority_root_sha256
checkpoint_sha256
```

The receipt validator must accept the untouched receipt and reject any mutation
under the unchanged digest.

## Bank

```text
4 positive controls
5 receipt completeness/integrity negatives
9 total cases
```
