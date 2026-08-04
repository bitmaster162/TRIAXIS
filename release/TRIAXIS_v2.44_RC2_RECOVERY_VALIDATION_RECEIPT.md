# TRIAXIS v2.44-RC2 Recovery — Validation Receipt

## Accepted evidence

- Exact RC1 detached validation: 103/103 tests and 75/75 frozen cases.
- New post-product v3.9 trigger: 9/9 cases, 4/4 positive controls.
- v3.9 repeated byte-identically against the exact RC1 tag.
- Scope/history/current crash boundaries remained atomic before and after COMMIT.

## Promotion rule

```text
logic change after RC1: forbidden
src tree at RC2: must equal d941c4032c8e00ca71816f0f1f56cafa043d329a
new material defect in v3.9: none found
promotion: validation-only RC2
```

## Status

```text
SPECIFICATION STATUS: Release Candidate
IMPLEMENTATION STATUS: Partially implemented
ANALYSIS STATUS: PASS WITH CONDITIONS
PRODUCTION-QUALIFIED: NO
EXTERNAL EXECUTION PERMISSION: NOT IMPLIED
```
