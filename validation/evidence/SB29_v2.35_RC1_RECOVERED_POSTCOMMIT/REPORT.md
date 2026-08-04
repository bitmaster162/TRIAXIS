# TRIAXIS v2.35-RC1 Recovered — Post-Commit Snapshot Subject Binding Trigger

```text
EXECUTED_PRODUCT_TAG:    TRIAXIS-v2.35-RC1-RECOVERED
EXECUTED_PRODUCT_COMMIT: ca779fdd9a91808470a3a338e9e7f0ab5a0bb361
EXECUTED_PRODUCT_TREE:   4c5c60a9fd8aa5a84b0c532a7257060876fbcd21
PROTOCOL:                TRIAXIS_AUTHORITY_SNAPSHOT_SUBJECT_BINDING_TRIGGER_v2.9_RECOVERY
RESULT:                  FAIL
CASES:                   4 / 9 PASS
FAILURES:                5 / 9
POSITIVE CONTROLS:       4 / 4 PASS
EXACT PRODUCT TESTS:     61 / 61 PASS
BYTE REPRODUCTION:       PASS across two isolated process invocations
RESULTS SHA-256:         9ad897bd35f87c1d891a28903928413265c00f6745f900087d6b6a919b742034
SUMMARY SHA-256:         0549af8ab292e1223042b22a5f066a91c5352c31146236247abf95d28899887a
```

## Triggered defect

v2.35 authenticates snapshot bytes and binds their observation time, but does
not prove that the snapshot was constructed for the exact Analysis Bundle and
provenance registry being evaluated. A valid current-time signature can
therefore be replayed across another run, a resealed semantic mutation, an
arbitrary source digest, a successor bundle or another provenance registry.

## Required repair

Before analytical preparation and again before checkpoint mutation, require:

```text
snapshot.source_bundle_sha256 == bundle.bundle_sha256
snapshot.trust_records_sha256 == SHA256(bundle.provenance_registry)
```

Every mismatch must be state-neutral.
