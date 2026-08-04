# TRIAXIS v2.34-RC1 Recovered — Post-Commit Snapshot Freshness Trigger

```text
EXECUTED_PRODUCT_TAG:    TRIAXIS-v2.34-RC1-RECOVERED
EXECUTED_PRODUCT_COMMIT: e78857d74afd6edd8725609b4891d12aee186c21
EXECUTED_PRODUCT_TREE:   e348e844742fbdf14fa99ceb39496db4861250c4
PROTOCOL:                TRIAXIS_AUTHORITY_SNAPSHOT_FRESHNESS_TRIGGER_v2.8_RECOVERY
RESULT:                  FAIL
CASES:                   4 / 9 PASS
FAILURES:                5 / 9
POSITIVE CONTROLS:       4 / 4 PASS
BYTE REPRODUCTION:       PASS across two isolated process invocations
RESULTS SHA-256:         c3d9e887f79d115a5cc0863354797669e6799223ff07c7aa2bea5d971aca20ae
SUMMARY SHA-256:         3474f29c85d7f8d7fa9fe45be00723c370daea47de0563c2728b4b707599a69d
```

## Triggered defect

The recovered v2.34 authority session accepts an authenticated snapshot whose
`snapshot.evaluation_tick` is older than the host-controlled and Analysis
Bundle evaluation tick.  Re-signing old state or keeping an old envelope valid
therefore permits trust-state staleness.

All five negative cases expected:

```text
BLOCKED_BY_TRUST_SNAPSHOT_STATE
stale_trust_snapshot_state
```

but instead reached `PASS` and advanced state.  Four positive controls behaved
as expected, so this is not a trivially blocking harness.

## Identity boundary

The imported frozen trigger embeds the unavailable historical v2.34 identity:

```text
fc364c61a8d7f8483b29fbb5bb82be3b80be7b29
303a85faae969cf48fbd1b4f1c45c537fb1e59b7
```

Those fields are preserved as protocol metadata.  The actual executable target
for this report is the recovered product commit/tree shown above.  This report
does not claim byte identity with the unavailable historical product.

## Required repair

A successful authority analysis must require:

```text
bundle.frame.evaluation_tick
== trusted_evaluation_tick
== authenticated_snapshot.evaluation_tick
```

Stale or future snapshot state must block before any checkpoint mutation.
