# TRIAXIS v3.28-RC2 Operator Card

## Safe interpretation

`PASS` means the exact v3.28-RC1 reference implementation satisfies its frozen
closure under the tested state-domain assumptions:

- a current external head detects execution-ledger rollback or fork;
- a current provider idempotency record blocks replay even after rollback of the
  queue, ledger, and head authority;
- exact provider transport retries do not repeat the modeled effect;
- uncertain outcomes remain blocking until authoritative reconciliation.

`PASS` does not mean that a real external provider, physical deployment, or
coordinated rollback of all state domains is safe.

## Required execution order

1. Verify the pre-reservation local ledger head against a fresh external-head
   challenge.
2. Reserve and start the exact stable effect in the execution ledger.
3. Deliver every new signed ledger event to the head authority.
4. Verify the exact `IN_FLIGHT` local head against another fresh external-head
   challenge.
5. Query provider status for the exact `effect_id` and payload digest.
6. Recheck separate action authority and all target, payload, state, policy, and
   expiry bindings.
7. Submit the stable `effect_id` as the provider idempotency key.
8. Persist provider and ledger outcome before acknowledging the local queue.

## Do

- keep queue, ledger, head authority, and provider idempotency state in distinct
  rollback and administration domains;
- preserve event-chain continuity and deliver missing events before their signed
  envelopes expire;
- treat a synchronization gap as a blocking incident;
- treat `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` provider states as non-retryable;
- require exact provider payload binding;
- require authoritative `NO_EFFECT` evidence before creating another generation;
- monitor sequence, head-event digest, state root, signer, trust domain,
  challenge freshness, and provider status.

## Do not

- reset, replace, or reinitialize the external head to recover availability;
- delete or rewrite a provider idempotency record;
- retry after timeout or ambiguous transport failure;
- treat a signed head, provider status, ledger receipt, or reconciliation record
  as action authorization;
- deploy all state, keys, backups, and administrators in one failure domain and
  describe it as independent;
- claim exactly-once behavior for a real provider without adapter-specific
  conformance evidence;
- claim protection against coordinated rollback of every state domain.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `production_qualified=false`
- `independent_certification=false`
- `real_provider_adapter=false`
