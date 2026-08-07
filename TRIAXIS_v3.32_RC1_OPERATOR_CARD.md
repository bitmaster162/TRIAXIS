# TRIAXIS v3.32-RC1 Operator Card

## Mandatory order

1. Run the complete v3.31 guard in-process.
2. Query the provider-native idempotency namespace with a fresh single-use
   challenge.
3. Accept only `ABSENT` or authoritative `NO_EFFECT`.
4. Read the current signed immutable completion-anchor head.
5. Query the pinned completion-transparency authorities with one verifier epoch
   and challenge.
6. Require threshold agreement with the local head and honor any valid
   newer-head or same-sequence-fork veto.
7. Re-check the separate authorization token immediately before execution.
8. Persist execution and completion receipts.

## Immediate BLOCK conditions

- missing v3.31 PASS;
- provider-native status missing, stale or blocking;
- payload mismatch under `effect_id`;
- transparency quorum absent or config-substituted;
- newer minority head or same-sequence fork;
- challenge replay;
- ambiguous state;
- unavailable required authorization;
- any request to infer physical independence from local reference processes.

## Non-authority statement

Provider-native and transparency objects are evidence. They never authorize an
action. `can_trade=false`, `capital_permission=DENY`, `deploy_permission=DENY`.
