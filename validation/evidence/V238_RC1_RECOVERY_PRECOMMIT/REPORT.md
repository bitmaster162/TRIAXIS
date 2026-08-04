# TRIAXIS v2.38-RC1 Recovery — Pre-Commit Validation

```text
BASELINE EVIDENCE COMMIT: d5d5c805591cb18d8f378e5341a461f99b0e2039
RESULT:                   PASS WITH CONDITIONS
UNIT/HISTORICAL TESTS:    74 / 74 PASS
FROZEN V3.1 CLOSURE:       9 / 9 PASS
POSITIVE CONTROLS:         4 / 4 PASS
TRIGGER REPRODUCIBILITY:  byte-identical across two process invocations
CR31 RESULTS SHA-256:     c0acdcdcd64f405364e6f8d24b88d02f817360fd3d95a183cc977e1b8f16ab00
CR31 SUMMARY SHA-256:     7e5461e7f6634f3855bcecdfcbc3824817d826bdea35574ace30a38c9efc7c1a
UNIT LOG SHA-256:         2f8a9ffdbdf3aa3e26d53c3d1056ca9d69896873ffe9ad82a6871e2a4cb78b3b
COMPILEALL:               PASS
DIFF CHECK:               PASS
SECRET MARKER SCAN:       PASS
```

## Closed trigger

The public trust checkpoint receipt now preserves the exact parent-envelope
identity, carries a canonical self-digest and is accepted only by an exported
strict validator. Two checkpoints that differ only by parent no longer serialize
identically; any covered-field mutation invalidates the receipt digest.

## Scope

The receipt digest is tamper-evidence, not an authenticity proof and not a durable
latest-head anchor. Restart continuity, rollback resistance and host storage remain
outside this version and require a fresh post-product protocol.

Same-lineage deterministic recovery validation only; not independent certification,
production qualification or external execution authority.
