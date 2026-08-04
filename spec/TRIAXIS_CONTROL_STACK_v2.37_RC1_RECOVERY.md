# TRIAXIS CONTROL STACK v2.37-RC1 Recovery — Canonical Ingress Delta

## Status

```text
SPECIFICATION_STATUS: Release Candidate
IMPLEMENTATION_STATUS: Partially implemented — recovered deterministic authority path
BASELINE_EVIDENCE_COMMIT: df1c93cd8ca4477e0a4a8fb86d1b874aeb48bfd9
PRODUCTION_QUALIFIED: NO
EXTERNAL_ACTION_PERMISSION: NOT IMPLIED
```

## Trigger

The exact v2.36 product passed 66/66 historical tests but failed five malformed
nested-input cases in frozen protocol v3.0. Non-canonical provenance values
escaped as Python exceptions before the low-level validator ran.

## Normative ingress invariant

Before authority classification, time comparison, subject hashing or analytical
validation, the complete Analysis Bundle must be materialized once into a
detached canonical JSON value.

Rejected values include:

```text
sets
bytes
NaN or infinity
non-string mapping keys
cycles
hostile or unstable nested mappings
unsupported objects
```

All failures return:

```text
status: BLOCK
primary_reason: BLOCKED_BY_ANALYSIS_CONTRACT
error.code: invalid_analysis_bundle_materialization
checkpoint: unchanged
```

The trust envelope is likewise canonicalized once before authentication.

## Contract lineage

```text
v1-v5: preserved identifiers
active: TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v6
```

## Non-claims

No independent certification, durable/distributed state, production key custody,
trusted external time, live tool safety or external-action permission.
