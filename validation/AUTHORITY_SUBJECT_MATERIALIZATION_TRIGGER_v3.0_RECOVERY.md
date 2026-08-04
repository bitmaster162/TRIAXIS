# TRIAXIS Authority Subject Materialization Trigger v3.0 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_SUBJECT_MATERIALIZATION_TRIGGER_v3.0_RECOVERY
CANDIDATE_COMMIT: 10d0db544692431e2cfd152922eaac2f27c3f0f3
CANDIDATE_TREE: 0ffafd760e8424c2f639961208f015ee23492d3f
STATUS: Frozen post-product trigger
AUTHORED: after v2.36 product commit and before materialization repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can a malformed nested Analysis Bundle value reach snapshot subject hashing and
raise an exception instead of producing a state-neutral contract block?

## Required terminal

Every non-canonical JSON bundle must return:

```text
status: BLOCK
primary_reason: BLOCKED_BY_ANALYSIS_CONTRACT
error.code: invalid_analysis_bundle_materialization
checkpoint: unchanged
```

## Bank

```text
4 positive controls
5 malformed nested-value negatives
9 total cases
```
