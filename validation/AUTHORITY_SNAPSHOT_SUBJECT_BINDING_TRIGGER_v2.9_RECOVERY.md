# TRIAXIS Authority Snapshot Subject Binding Trigger v2.9 — Recovery

```text
PROTOCOL_ID: TRIAXIS_AUTHORITY_SNAPSHOT_SUBJECT_BINDING_TRIGGER_v2.9_RECOVERY
CANDIDATE_COMMIT: ca779fdd9a91808470a3a338e9e7f0ab5a0bb361
CANDIDATE_TREE: 4c5c60a9fd8aa5a84b0c532a7257060876fbcd21
STATUS: Frozen post-product trigger
AUTHORED: after v2.35 product commit and before any subject-binding repair
INDEPENDENCE: same implementation lineage; not independent certification
```

## Question

Can an authenticated, current-time Trust Snapshot authorize an Analysis Bundle
other than the exact bundle and provenance registry from which the snapshot was
constructed?

## Required invariants

```text
snapshot.source_bundle_sha256 == analysis_bundle.bundle_sha256
snapshot.trust_records_sha256 == SHA256(analysis_bundle.provenance_registry)
```

A bundle mismatch must block state-neutrally as:

```text
BLOCKED_BY_TRUST_SNAPSHOT_STATE
trust_snapshot_bundle_binding_mismatch
```

A provenance-registry mismatch must block state-neutrally as:

```text
BLOCKED_BY_TRUST_SNAPSHOT_STATE
trust_snapshot_provenance_binding_mismatch
```

## Bank

```text
4 positive controls
5 subject/provenance replay negatives
9 total cases
```
