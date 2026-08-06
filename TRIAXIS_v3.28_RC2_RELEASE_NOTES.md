# TRIAXIS v3.28-RC2 Release Notes

v3.28 adds an external monotonic execution-ledger head and a provider-side
idempotency/reconciliation reference to the v3.27 stable-effect ledger.

The head authority persists the highest accepted signed ledger sequence,
head-event digest, and deterministic state root outside the execution-ledger
database. It accepts only contiguous signed event advances from the previously
remembered head and rejects rollback, same-sequence fork, sequence gap, parent
mismatch, authority rebinding, and untrusted signatures. A fresh signed response
is bound to a single-use verifier challenge and does not grant action authority.

The provider reference persists one record per stable `effect_id` and exact
payload digest. `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` block another external
effect. Exact transport replay is idempotent, payload substitution fails closed,
and only authoritative `NO_EFFECT` reconciliation permits another generation.
The included provider is a state-machine reference, not a real vendor adapter.

RC2 makes no product-source changes. It records the post-RC1 coordinated
rollback boundary:

1. with ledger, external head, and provider state current, a completed effect is
   blocked;
2. after rollback of the local queue, execution ledger, and head authority, the
   still-current provider record continues to block the effect;
3. after coordinated rollback of the provider idempotency store as well, the
   same stable effect becomes executable again.

Therefore v3.28 does not claim production exactly-once execution under
coordinated rollback or compromise of every effect-state domain. The next
material layer requires independently administered head quorum, real
provider-native immutable idempotency/reconciliation, append-only external
receipts, or hardware/KMS-backed monotonic anti-rollback state.
