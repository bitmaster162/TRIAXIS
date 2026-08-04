# TRIAXIS v2.37-RC1 Recovered — Post-Commit Checkpoint Receipt Trigger

```text
EXECUTED_PRODUCT_TAG:    TRIAXIS-v2.37-RC1-RECOVERED
EXECUTED_PRODUCT_COMMIT: 1bbc5b7d5861856eee030544c44ee3ba2cf9fe78
EXECUTED_PRODUCT_TREE:   dc1fb2ca3b5ed81cf3937df819dc676e19a4db9c
PROTOCOL:                TRIAXIS_AUTHORITY_CHECKPOINT_RECEIPT_TRIGGER_v3.1_RECOVERY
RESULT:                  FAIL
CASES:                   4 / 9 PASS
FAILURES:                5 / 9
POSITIVE CONTROLS:       4 / 4 PASS
EXACT PRODUCT TESTS:     70 / 70 PASS
BYTE REPRODUCTION:       PASS across two isolated process invocations
RESULTS SHA-256:         3bc7408d04af07a2c994b1debc14423cef2cdd07e838b667f490b18cf1f92c1c
SUMMARY SHA-256:         fc3e6b683f9729a639f300c3ad7ae486103a576181e942f2a3eba4fd44eb029b
```

## Triggered defect

The in-memory checkpoint contains `previous_envelope_sha256`, but `as_dict()`
omits it. The public receipt also lacks a canonical `checkpoint_sha256` and an
exported verifier. Consequently:

- genesis null parent is not explicit;
- successor parentage cannot be reconstructed from the receipt alone;
- two internal checkpoints differing only by parent can serialize identically;
- receipt tampering cannot be detected without unrelated internal state.

## Required repair

Bump the checkpoint receipt contract without erasing v2, include the exact parent
and a canonical self-digest, and expose a fail-closed receipt validator.
