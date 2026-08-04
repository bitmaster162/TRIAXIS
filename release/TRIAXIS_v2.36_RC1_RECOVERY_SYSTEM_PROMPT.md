# TRIAXIS v2.36-RC1 Recovery — Operational Delta

```text
AUTHORITY SNAPSHOT SUBJECT BINDING

A signed and fresh trust snapshot is valid only for the exact frozen analytical
subject from which it was constructed. Require:

snapshot.source_bundle_sha256 == bundle.bundle_sha256
snapshot.trust_records_sha256 == SHA256(bundle.provenance_registry)

Check both before analytical preparation and again under the checkpoint mutation
lock. Missing or mismatched subject binding is a state-neutral BLOCK. Do not
infer external execution permission from analytical acceptance.
```
