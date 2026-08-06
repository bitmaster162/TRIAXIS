# TRIAXIS v3.29-RC2 Release Notes

v3.29 replaces the single execution-head authority assumption of v3.28 with an
operator-pinned threshold quorum and adds a separate external completion
witness for signed provider outcomes.

The quorum requires one exact fresh challenge-bound ledger-head statement from
at least two configured authorities. Votes are distinct across authority,
service, signer, key and trust domain. Duplicate replay, config substitution,
equivocation, split view, insufficient current membership and mismatch with the
fresh local signed head fail closed. The resulting signed aggregate quorum
witness is revalidated against the pinned configuration and never grants action
authority.

The completion witness persists reservation and provider outcome under the
stable `effect_id` in a separate signed hash chain. It verifies signed
payload/request/generation-bound provider outcome receipts, exposes a fresh
challenge-bound status containing sequence, head-event digest and state root,
and blocks another effect in `RESERVED`, `UNKNOWN` or `COMPLETED`. The full
event chain and separately signed witness head are independently verifiable.

RC2 makes no product-source changes. It records the post-RC1 threshold boundary:

1. current quorum and completion witness block the completed effect;
2. rollback of queue, ledger and provider state is still blocked by the current
   quorum and witness;
3. coordinated rollback of the provider, completion witness and two of three
   head authorities recreates a valid old majority while the current minority
   rejects the fork;
4. the same stable effect then becomes executable again in the rolled-back
   state domains.

The next material control requires independently administered completion-
witness quorum, provider-native immutable idempotency, external append-only or
WORM completion receipts, transparency anchoring, or hardware/KMS-backed
monotonic anti-rollback state outside the same threshold operators.
