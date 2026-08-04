# TRIAXIS v2.36-RC1 Recovery — Operator Card

```text
1. Authenticate snapshot bytes and authority root.
2. Bind bundle, host and snapshot to one evaluation tick.
3. Bind snapshot.source_bundle_sha256 to the exact frozen bundle digest.
4. Bind snapshot.trust_records_sha256 to the exact frozen registry digest.
5. Reject semantic replay even when IDs, time and signature remain valid.
6. Repeat subject checks under the checkpoint mutation lock.
7. Never allow low-level acceptance without explicit subject bindings.
8. Preserve the exact prior checkpoint on every mismatch.
9. Validation keys are non-secret test infrastructure only.
10. Analytical PASS does not imply live external-action permission.
```
