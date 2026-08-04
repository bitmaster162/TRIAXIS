# TRIAXIS v2.40-RC1 Recovery — Post-Commit Idempotency Trigger

```text
EXACT PRODUCT COMMIT:       b16e203b8cf8280e09c5b897d5edf7dd87e760f1
EXACT PRODUCT TREE:         51749687a5e5b11e09e59d106277287134b35ba0
PROTOCOL:                   TRIAXIS_AUTHORITY_CHECKPOINT_IDEMPOTENCY_TRIGGER_v3.4_RECOVERY
RESULT:                     FAIL AS TRIGGERED
CASES:                       6 / 10 PASS
FAILURES:                    4 / 10
POSITIVE CONTROLS:           4 / 4 PASS
HISTORICAL TESTS:           85 / 85 PASS
REPRODUCIBILITY:            byte-identical across two detached process invocations
RESULTS SHA-256:            e4e66992600dc808d4464e347867a88ca79c66602fbc8a30fbfd87e8b521a9e4
SUMMARY SHA-256:            e75a38957e650ee3eca80fd0a4b4ad5908f9c771261f2db65ce95dfca781e173
PROTOCOL ROWS SHA-256:      9a1077bf5c07f541cefd9d808b3c46a21b7523f29bdf14db96e3b20bf59abf53
```

## Triggered defect

After a successful SQLite COMMIT whose response is lost, retrying the exact
genesis or successor request returns `checkpoint_store_cas_mismatch`. Safety is
preserved and no duplicate history row is written, but the caller cannot reconcile
“already committed” from “not committed.” The same failure persists after clean
reopen and through a second store handle.

## Preserved controls

A genuinely different successor from the same predecessor and an exact current
pair accompanied by a false predecessor claim remain blocked state-neutrally.

## Required correction

Inside the write transaction, recognize an exact current receipt/envelope pair as
idempotently committed only when the claimed predecessor equals the actual prior
history head (or null for genesis). Return the current head without appending or
updating anything. All non-exact stale writers remain CAS failures.

Same-lineage evidence only; not distributed idempotency, network protocol proof,
production qualification or external action authority.
