# TRIAXIS v3.29-RC2 Operator Card

## Safe interpretation

`PASS` means the exact v3.29-RC1 executable reference satisfies its frozen
closure under the tested logical-state assumptions:

- a pinned threshold of distinct execution-head authorities must agree on one
  fresh challenge-bound ledger-head statement;
- the local execution ledger must exactly match that statement;
- a separately persisted completion witness remembers provider reservation and
  signed provider outcome by stable `effect_id`;
- provider and completion-witness state must both permit before retry;
- all receipts, heads, statuses and quorum witnesses remain evidence only.

`PASS` does not mean physical independence, real-provider conformance, or
safety after rollback or compromise of a quorum threshold together with the
completion witness and provider state.

## Required execution order

1. Verify the local pre-reservation ledger head against a fresh pinned quorum.
2. Reserve and move the stable effect to `IN_FLIGHT` in the execution ledger.
3. Deliver every new signed ledger event to the head authorities.
4. Verify the exact `IN_FLIGHT` head against another fresh quorum.
5. Query provider and completion-witness status for the exact `effect_id` and
   payload digest.
6. Reserve the effect in the external completion witness.
7. Recheck separate action authority, target, payload, state, policy and expiry.
8. Submit the stable `effect_id` as the provider idempotency key.
9. Persist provider outcome and issue the signed provider outcome receipt.
10. Ingest that receipt into the completion witness and re-anchor the final
    execution-ledger outcome before acknowledging the queue.

## Do

- pin quorum membership and configuration digest outside the executing agent;
- keep authority IDs, service IDs, signer IDs, keys and trust domains distinct;
- preserve sequence and parent continuity for every head and completion event;
- validate signed aggregate quorum witnesses against the exact pinned config;
- compare completion-witness sequence, head-event digest and state root;
- treat `RESERVED`, `UNKNOWN` and `COMPLETED` as non-retryable;
- require signed authoritative `NO_EFFECT` before another generation;
- treat a minority fork rejection as an incident even when a rolled-back
  majority can still form threshold.

## Do not

- reset an authority or witness to recover availability;
- let the requesting agent choose or weaken quorum membership;
- count duplicate identities, keys or trust domains as independent votes;
- retry after timeout or ambiguous provider outcome;
- treat a quorum witness, completion receipt or status as action authorization;
- deploy quorum members, completion witness, provider state, keys, backups and
  administrators in one rollback domain and call that independent;
- claim protection against threshold compromise or coordinated rollback;
- claim production exactly-once without provider-native immutable evidence.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `production_qualified=false`
- `physical_independence=false`
- `administrative_independence=false`
- `independent_certification=false`
- `real_provider_adapter=false`
