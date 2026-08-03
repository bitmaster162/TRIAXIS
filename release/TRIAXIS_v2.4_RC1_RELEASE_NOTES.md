# TRIAXIS v2.4-RC1 — Release Notes

## Evidence trigger

Commit-sealed H1 against frozen v2.3-RC1 produced 11 PASS / 13 FAIL. The patch is limited to those observed failures.

## Changes

1. Added Policy Integrity with version/digest binding and explicit conflict state.
2. Added Authority Composition, quorum and bounded delegation validation.
3. Added Toolchain Integrity and capability-evidence trust.
4. Added Reliance Gate for material downstream human action at X0.
5. Added inherited data classification, lineage and control-trace secrecy.
6. Added atomic budget reservation and compare-and-commit requirements.
7. Bound idempotency keys to payload, target, destination, principal and policy.
8. Added checkpoint and tamper-evident ledger integrity requirements.
9. Added exact blocker vocabulary for the new gates.

## Status

```text
SPECIFICATION_STATUS: RELEASE_CANDIDATE
IMPLEMENTATION_STATUS: PARTIALLY_IMPLEMENTED — DETERMINISTIC GATES ONLY
VALIDATION_STATUS: H1 REGRESSION PASS 24/24; FRESH H2 REQUIRED
EXTERNAL_EXECUTION: NOT AUTHORIZED BY THIS RELEASE
```

## H1 regression receipt

```text
CASE_SHA256: a97044760755316801d0c6dcd9de839c9f00e1947386108953ea3aeb6d6cba8b
RESULT_SHA256: 0d878762e1d50f4ce05e3ee74acadced659ef20aaa6da8dafdda75b4a6210340
PASS: 24
FAIL: 0
```
