# TRIAXIS v3.30-RC2 Release Notes

v3.30 replaces the single completion-witness assumption of v3.29 with an
operator-pinned threshold quorum and adds a separate signed logical append-only
completion anchor.

The completion quorum requires one exact fresh challenge-bound effect statement
from at least two configured witnesses. Votes are distinct across witness,
authority, service, signer, key and trust domain. Duplicate replay, config
substitution, equivocation, semantic disagreement, insufficient current
membership and stale evidence fail closed. A valid configured witness reporting
`RESERVED`, `UNKNOWN` or `COMPLETED` vetoes retry even when two other witnesses
report a permissive state.

The logical completion anchor consumes signed provider outcome receipts and
stores a separately signed event chain, head, state root and fresh
challenge-bound status. Exact receipt replay is idempotent. Payload, request,
generation, parent-chain or identity substitution fails closed. `UNKNOWN` can
be reconciled only by later signed outcome evidence; only `NO_EFFECT` can open a
new generation.

RC2 makes no product-source changes. It records the exact-RC1 validation and the
mandatory coordinated rollback boundary:

1. current provider state, completion quorum and anchor block the completed
   effect;
2. rollback of provider plus a completion-witness threshold is still blocked by
   the current anchor;
3. rollback of the anchor is still blocked when the current `COMPLETED`
   completion minority is included;
4. coordinated rollback of provider, both quorum thresholds and the anchor,
   combined with omission of the current completion minority, recreates a
   permissive old view for the same stable effect.

The included SQLite anchor is therefore a logical append-only reference, not
physical WORM storage. A received blocking minority is protective; an omitted
minority is not.

Frozen results:

- historical and new unit tests: `474 / 474 PASS`;
- v3.30 closure: `26 / 26 PASS`;
- closure rows SHA-256:
  `32ebaf6247db3310329eee05c5727878c13102aac70d5df89c2c750fe120a0ec`;
- four-process service smoke: `5 / 5 PASS`;
- service-smoke rows SHA-256:
  `eeb61fdd4918271972b6e3fb6629cd2339279922d914d93dce0e1f54e36a7e13`;
- rollback-boundary rows SHA-256:
  `4e5276e61d58126d27ba5a6c911795a494c75889ddd4b6e130e06be7c6734800`;
- boundary status: `BOUNDARY_CONFIRMED`.

The next material control requires availability-closed witness policy for
high-risk effects, independently administered completion-anchor quorum or
transparency checkpoint, provider-native immutable idempotency, and physical
append-only/WORM or hardware-backed anti-rollback evidence outside the quorum
operators.
