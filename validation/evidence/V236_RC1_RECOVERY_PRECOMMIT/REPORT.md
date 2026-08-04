# TRIAXIS v2.36-RC1 Recovery — Pre-Commit Validation

```text
BASELINE EVIDENCE COMMIT: c6f8dc7ce5f467e37861f078e0d93f0b3c1011d5
RESULT:                   PASS WITH CONDITIONS
UNIT/HISTORICAL TESTS:    66 / 66 PASS
FROZEN V2.9 CLOSURE:       9 / 9 PASS
POSITIVE CONTROLS:         4 / 4 PASS
TRIGGER REPRODUCIBILITY:  byte-identical across two process invocations
SB29 RESULTS SHA-256:     07c70f2193c7a600e541efcf9f58ef9d1a921e69d2eac13e059c1a0ceb62a902
SB29 SUMMARY SHA-256:     fb216d7b8c13e954e5485d566fd8c716a83bcee12efe285a1ff191a5c763bc96
COMPILEALL:               PASS
DIFF CHECK:               PASS
SECRET MARKER SCAN:       PASS
```

## Closed trigger

The v2.35 product accepted five current-time subject/provenance replay cases.
The v2.36 candidate blocks all five without checkpoint mutation while retaining
all four positive controls.

## Historical-oracle compatibility

The recovered v2.7 atomicity fixture now seals each snapshot over the exact
invalid bundle being tested. This preserves the original analytical rejection
oracle (`invalid_rationale_role` / `invalid_type`) instead of allowing the new
subject-binding gate to mask it with an unrelated mismatch.

## Scope

Same-lineage deterministic recovery validation only; not independent
certification or production qualification.
