# TRIAXIS CONTROL STACK v2.36-RC1 Recovery — Snapshot Subject Binding Delta

## Status

```text
SPECIFICATION_STATUS: Release Candidate
IMPLEMENTATION_STATUS: Partially implemented — recovered deterministic authority path
BASELINE_EVIDENCE_COMMIT: c6f8dc7ce5f467e37861f078e0d93f0b3c1011d5
PRODUCTION_QUALIFIED: NO
EXTERNAL_ACTION_PERMISSION: NOT IMPLIED
```

## Trigger

The committed v2.35 product passed 61/61 historical tests but failed frozen
post-product protocol v2.9:

```text
4 / 9 PASS
5 / 9 FAIL
positive controls: 4 / 4 PASS
```

A fresh authenticated snapshot could be replayed across a different Analysis
Bundle or provenance registry.

## Normative subject binding

Authority acceptance requires all existing authenticity and time checks plus:

```text
snapshot.source_bundle_sha256 == frozen_bundle.bundle_sha256
snapshot.trust_records_sha256 == SHA256(frozen_bundle.provenance_registry)
```

Mismatch terminals:

```text
trust_snapshot_bundle_binding_mismatch
trust_snapshot_provenance_binding_mismatch
```

Both map to `BLOCKED_BY_TRUST_SNAPSHOT_STATE` and preserve the exact previous
checkpoint.

## Two-phase enforcement

1. `AuthorityAnalysisSession` computes both expected digests from one exact
   materialized bundle before analytical preparation.
2. `ProvenanceTrustStateGuard.accept()` requires and rechecks both digests under
   the mutation lock.

Low-level checkpoint acceptance without expected subject digests fails closed as
`trust_snapshot_subject_binding_required`.

## Contract lineage

```text
v1-v4: preserved identifiers
active: TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v5
```

## Non-claims

No recovery of unavailable historical Git objects, independent certification,
durable distributed state, production keys, trusted external clock or live
external execution.
