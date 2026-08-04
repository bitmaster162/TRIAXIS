# TRIAXIS v2.35-RC1 Recovery — Pre-Commit Validation

```text
BASELINE EVIDENCE COMMIT: 964469b1b5d9be81da01d550ca89896cac7351dd
TARGET:                   uncommitted v2.35-RC1 Recovery candidate
RESULT:                   PASS WITH CONDITIONS
UNIT/HISTORICAL TESTS:    61 / 61 PASS
FROZEN V2.8 CLOSURE:       9 / 9 PASS
POSITIVE CONTROLS:         4 / 4 PASS
TRIGGER REPRODUCIBILITY:  byte-identical across two process invocations
SF28 RESULTS SHA-256:     39e5c7bb9ba6810caba9eab4171920efdc63bc7d6b3279566ad5b681d960117a
SF28 SUMMARY SHA-256:     9e231df375b7875990c23bf9dfda0e240dd268a472e6b6cd3d56c308a6c2037d
COMPILEALL:               PASS
DIFF CHECK:               PASS
SECRET MARKER SCAN:       PASS
```

## Closed trigger

The exact recovered v2.34 product accepted five stale snapshot scenarios. The
v2.35 candidate blocks all five before checkpoint mutation while preserving all
four positive controls.

## Scope

This is same-lineage deterministic validation against a recovered product
lineage. It is not independent certification and does not establish durable
state, production key custody, trusted external time or live execution safety.
