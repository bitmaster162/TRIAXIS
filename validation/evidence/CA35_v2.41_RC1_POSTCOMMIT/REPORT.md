# TRIAXIS v2.41-RC1 Recovery — Post-Commit Crash Atomicity Validation

```text
EXACT PRODUCT COMMIT:       9ef3a3850278a45eddfc15361f0e9955cb746d70
EXACT PRODUCT TREE:         f487f5bec1185077f447e092be389a6d7ea93a59
PROTOCOL:                   TRIAXIS_AUTHORITY_CHECKPOINT_CRASH_ATOMICITY_TRIGGER_v3.5_RECOVERY
RESULT:                     PASS
CASES:                       9 / 9 PASS
POSITIVE CONTROLS:           4 / 4 PASS
HISTORICAL TESTS:           88 / 88 PASS
REPRODUCIBILITY:            byte-identical across two detached process invocations
RESULTS SHA-256:            b9a8844cb6b8110fce6987aabdff6b50ac81c4ec8d0fbe38ca0b524f88fcea44
SUMMARY SHA-256:            4fb6dac3a586c08333167ddb1d5651cf975d85e9ae5c4bf87c9c6ee38e647013
PROTOCOL ROWS SHA-256:      4860d8345c638c9291f027e11153ccc47b08268a1cda744a69dc42dacfa043e6
```

## Observed behavior

- process death after genesis history insertion recovers an empty store;
- process death after successor history insertion recovers exact genesis;
- process death after successor current-row update but before COMMIT recovers exact genesis;
- process death immediately after COMMIT recovers exact successor and two-row history;
- exact retry after the post-COMMIT unknown outcome reconciles without history growth.

No mixed current/history state was observed in this runtime and test matrix.

## Scope limit

This is same-lineage executable evidence on the current SQLite/WAL runtime. It is
not a universal proof for all filesystems, controller caches, torn-sector faults,
hostile database rollback, multi-host consensus, independent certification,
Production qualification or external execution authority.
