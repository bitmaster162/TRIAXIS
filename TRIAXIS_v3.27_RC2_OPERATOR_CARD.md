# TRIAXIS v3.27-RC2 Operator Card

## Safe interpretation

`PASS` means the exact RC1 external-execution-ledger reference satisfies its frozen tests and blocks replay caused by rollback of the local dispatch queue while the external ledger remains current.

## Do

- derive one stable `effect_id` from the persisted queue item, exact action envelope, and canonical target;
- reserve the effect in the external ledger before invoking a mutating provider;
- use the same stable `effect_id` as the provider-side idempotency key where the provider supports it;
- treat `RESERVED`, `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` as blocking states;
- require authoritative `NO_EFFECT` evidence before allowing a new generation;
- verify the exact ledger identity, signed event receipt, signed head, sequence, previous-event digest, and state root;
- keep the ledger in a rollback and administration domain separate from the local dispatch queue.

## Do not

- derive external-effect identity from `claim_id`, `dispatch_id`, `attempt_id`, provider request ID, or lease identity;
- create a new effect identity merely by rotating or substituting an authorization token;
- retry a mutating operation after timeout or transport uncertainty without authoritative reconciliation;
- treat a signed ledger receipt as action authorization;
- restore an old ledger database and assume its head is current;
- claim production exactly-once execution from this reference.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
- `production_qualified=false`
- `independent_certification=false`
