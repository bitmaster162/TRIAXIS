# TRIAXIS v2.38-RC1 Recovery — Post-Commit Restore Trigger

```text
EXACT PRODUCT COMMIT:       c6f31e1d0797b2c2d067f80241011d4808e067f4
EXACT PRODUCT TREE:         893cb92e8071d863a4b541f9c645c95e257798a3
PROTOCOL:                   TRIAXIS_AUTHORITY_CHECKPOINT_RESTORE_TRIGGER_v3.2_RECOVERY
RESULT:                     FAIL AS TRIGGERED
CASES:                       4 / 10 PASS
FAILURES:                    6 / 10
POSITIVE CONTROLS:           4 / 4 PASS
HISTORICAL TESTS:           74 / 74 PASS
REPRODUCIBILITY:            byte-identical across two detached process invocations
RESULTS SHA-256:            0b8913266838bd50a771aacf03d936520fd869630823e5533f83349f7687139f
SUMMARY SHA-256:            808b7ff1654c5b483ebf59d6a447b959f18493ad0bbeb2c5e7b68ce0923da816
PROTOCOL ROWS SHA-256:      38352020d0a6b6784d8953282cf6fdbf22e3195d81c47dc201273b11f935a1bb
```

## Triggered defect

v2.38 produces a complete, self-verifying checkpoint receipt but exposes no
restart restoration API. A fresh process therefore cannot prove all three of:

1. the receipt is structurally and canonically valid;
2. the receipt describes the exact signed trust envelope authenticated under
   the configured authority roots; and
3. the receipt equals a host-controlled expected-head digest stored outside
   the process.

All six new restart cases return `checkpoint_restore_api_missing`. Existing
in-process genesis, successor, receipt verification and replay protection remain
valid, so the bank does not pass by indiscriminate blocking.

## Required correction

Add an authenticated `ProvenanceTrustStateGuard.from_checkpoint(...)` restore
boundary that validates the receipt, authenticates and exactly matches the signed
envelope, requires an external expected-head digest, and sets in-memory state only
after every check passes.

Same-lineage trigger evidence only; not independent certification, durable storage
proof, production qualification or permission for external action.
