# TRIAXIS v2.37-RC1 Recovery — Pre-Commit Validation

```text
BASELINE EVIDENCE COMMIT: df1c93cd8ca4477e0a4a8fb86d1b874aeb48bfd9
RESULT:                   PASS WITH CONDITIONS
UNIT/HISTORICAL TESTS:    70 / 70 PASS
FROZEN V3.0 CLOSURE:       9 / 9 PASS
POSITIVE CONTROLS:         4 / 4 PASS
TRIGGER REPRODUCIBILITY:  byte-identical across two process invocations
SM30 RESULTS SHA-256:     7d587cdf098b051bc4edb7d90e9c55e77ca39f8720651c25c4cd29016d539106
SM30 SUMMARY SHA-256:     3d7901bce23a53e266cc6899725098889c80cb7fdf25b11f9f3eda09fe57d0fa
COMPILEALL:               PASS
DIFF CHECK:               PASS
SECRET MARKER SCAN:       PASS
```

## Closed trigger

Five non-canonical nested values that escaped v2.36 as Python exceptions now
return one state-neutral `invalid_analysis_bundle_materialization` block. All
four positive controls remain intact.

## Scope

Same-lineage deterministic recovery validation only; not independent
certification or production qualification.
