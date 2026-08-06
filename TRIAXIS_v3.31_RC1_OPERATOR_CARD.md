# TRIAXIS v3.31-RC1 Operator Card

## Safe interpretation

`PASS` means the exact executable reference satisfies this frozen logical
closure:

- every configured completion witness supplied one fresh exact statement;
- missing or stale minority evidence blocks rather than silently degrading to a
  threshold;
- provider outcomes are content-addressed and appended to a separately signed
  immutable-anchor event chain;
- the signed immutable-anchor head is not below or forked from verifier memory;
- provider, full completion availability, logical anchor and immutable anchor
  all permit;
- all evidence remains non-authorizing.

`PASS` does not mean physical WORM, independently administered storage,
hardware-backed anti-rollback, protected verifier state or production exactly-once.

## Required execution order

1. Verify separate action authority and exact intent/target/payload/state.
2. Establish current `IN_FLIGHT` execution-ledger head through its pinned quorum.
3. Query provider state.
4. Query every configured completion witness under one fresh challenge.
5. Verify exact v3.31 availability policy and full-set semantic agreement.
6. Query the logical completion anchor.
7. Query the immutable anchor and compare its signed head with verifier
   checkpoint state.
8. Continue only if all outcome domains report `ABSENT` or proven `NO_EFFECT`.
9. Reserve completion memory and recheck separate action authority.
10. Submit stable `effect_id` as provider idempotency key.
11. Persist the provider receipt in every required completion evidence domain.
12. Advance checkpoints and acknowledge the queue only after final evidence.

## Do

- pin the availability policy and quorum configuration outside the agent;
- require all configured witnesses for `HIGH` and `CRITICAL` effects;
- keep witness identities and trust domains distinct;
- treat missing response, timeout and stale evidence as `BLOCK`;
- retain content-addressed object receipts and signed event-chain evidence;
- keep verifier checkpoint state in a separately protected administrative
  domain where possible;
- treat `UNKNOWN` and `COMPLETED` as non-retryable;
- keep the verifier's permissive state set restricted to `ABSENT` and
  `NO_EFFECT`; caller-supplied widening is invalid;
- require signed authoritative `NO_EFFECT` before another generation;
- record rollback, fork, unavailability and equivocation as incidents.

## Do not

- fall back from all-configured to 2-of-3 after a witness disappears;
- call local `O_EXCL` files physical WORM or independent storage;
- reset witnesses, anchors or checkpoints to recover availability;
- let the requesting agent alter membership, policy or risk class;
- infer permission from omitted evidence;
- retry after timeout or ambiguous provider result;
- treat any evidence object as action authorization;
- co-locate all files, backups, keys, checkpoints and administrators and call it
  immutable or independent;
- claim production exactly-once without external protected storage and
  provider-native idempotency evidence.

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
