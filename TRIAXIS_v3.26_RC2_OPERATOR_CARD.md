# TRIAXIS v3.26-RC2 Operator Card

## Safe interpretation

`PASS` means the local queue state machine satisfies its frozen tests and exact-tag validation.

## Do

- persist input and attachment snapshots before dispatch;
- dispatch only after durable claim creation;
- use the exact dispatch id as the idempotency key;
- move uncertain post-dispatch operations to `UNKNOWN`;
- reconcile `UNKNOWN` against an authoritative external system;
- keep provider request IDs for tracing only.

## Do not

- auto-retry a mutating operation after timeout;
- treat a provider request ID as authorization;
- restore an old queue database and assume its state is current;
- claim production exactly-once semantics from this local reference.

## Runtime flags

- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
