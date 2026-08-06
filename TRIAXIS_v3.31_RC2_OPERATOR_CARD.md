# TRIAXIS v3.31-RC2 Operator Card

## Safe interpretation

`PASS` means the exact v3.31-RC1 executable reference satisfies its frozen
logical closure:

- every configured completion witness supplied one fresh exact statement for
  `HIGH` or `CRITICAL` retry evaluation;
- a missing, stale, substituted or contradictory witness blocks instead of
  degrading to the inherited 2-of-3 threshold;
- only `ABSENT` and authoritative `NO_EFFECT` can be treated as permissive;
- signed provider outcomes are stored as content-addressed write-once objects
  with a separately signed event chain, head and effect status;
- verifier checkpoint memory rejects a lower anchor sequence or a different
  same-sequence head/state root while that checkpoint remains current;
- provider, completion availability, logical completion anchor and immutable
  anchor must all permit;
- all evidence remains non-authorizing.

`PASS_WITH_CONDITIONS` applies because the post-RC1 probe confirmed that a
coordinated rollback of every completion-evidence domain and the verifier
checkpoint can recreate a complete permissive old view for the same stable
`effect_id`.

## Required execution order

1. Verify separate action authority and exact intent/target/payload/state.
2. Establish the current `IN_FLIGHT` execution-ledger head through its pinned
   quorum.
3. Query provider state under a fresh challenge.
4. Query every configured completion witness under one shared fresh challenge.
5. Verify the exact v3.31 availability policy and full configured-set semantic
   agreement.
6. Query the logical completion anchor under a separate fresh challenge.
7. Query the immutable anchor and compare its signed head/state root with
   verifier checkpoint state.
8. Continue only if all outcome domains report `ABSENT` or proven `NO_EFFECT`.
9. Reserve completion memory before provider mutation.
10. Recheck separate action authority immediately before submission.
11. Submit stable `effect_id` as provider idempotency key.
12. Persist the signed provider outcome in every completion witness, both
    anchors and the execution ledger.
13. Advance checkpoints and acknowledge the queue only after durable evidence
    exists.

## Do

- pin availability policy and both quorum configurations outside the agent;
- require the exact full configured completion-witness set for high-risk
  effects;
- keep witness identities and trust domains distinct;
- restrict permissive states to `ABSENT` and `NO_EFFECT`;
- treat missing response, timeout and stale evidence as `BLOCK`;
- retain content-addressed objects, signed object receipts and full event-chain
  evidence;
- protect verifier checkpoint state in a separate administrative domain where
  possible;
- treat `UNKNOWN` and `COMPLETED` as non-retryable;
- require signed authoritative `NO_EFFECT` before another generation;
- record rollback, fork, unavailability and equivocation as incidents.

## Do not

- fall back from all-configured to 2-of-3 after a witness disappears;
- let a caller widen the permissive completion-state set;
- call local `O_EXCL` files physical WORM, independent storage or hardware
  monotonic state;
- reset witnesses, anchors or checkpoints to recover availability;
- infer permission from omitted evidence;
- retry after timeout or ambiguous provider result;
- treat any evidence object as action authorization;
- co-locate all state, backups, keys, checkpoints and administrators and call
  the result immutable or independent;
- claim production exactly-once without provider-native durable idempotency and
  externally non-rollbackable completion evidence.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `production_qualified=false`
- `physical_independence=false`
- `administrative_independence=false`
- `physical_worm_established=false`
- `hardware_monotonicity=false`
- `independent_certification=false`
- `real_provider_adapter=false`
