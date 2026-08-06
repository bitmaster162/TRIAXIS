# TRIAXIS v3.30-RC1 Release Notes

v3.30 replaces the single completion-witness assumption of v3.29 with an
operator-pinned threshold quorum and adds a separate signed logical append-only
completion anchor.

The completion quorum requires one exact fresh challenge-bound effect statement
from at least two configured witnesses. Votes are distinct across witness,
authority, service, signer, key and trust domain. Duplicate replay, config
substitution, equivocation, semantic disagreement, insufficient current
membership and stale evidence fail closed. A valid configured witness reporting
`RESERVED`, `UNKNOWN` or `COMPLETED` vetoes retry even when two other witnesses
report a permissive state. An omitted or unavailable witness cannot veto and
remains part of the claim boundary.

The logical completion anchor consumes signed provider outcome receipts and
stores a separately signed event chain, head, state root and fresh
challenge-bound status. Exact receipt replay is idempotent. Payload, request,
generation, parent-chain or identity substitution fails closed. `UNKNOWN` can
be reconciled only by later signed outcome evidence; only `NO_EFFECT` can open a
new generation.

The included SQLite anchor is not physical WORM storage. It demonstrates the
contract and rollback boundary only while its database remains current.

Frozen pre-RC1 results:

- historical and new unit tests: `474 / 474 PASS`;
- v3.30 closure: `26 / 26 PASS`;
- closure rows SHA-256:
  `32ebaf6247db3310329eee05c5727878c13102aac70d5df89c2c750fe120a0ec`;
- four-process service smoke: `5 / 5 PASS`;
- service-smoke rows SHA-256:
  `eeb61fdd4918271972b6e3fb6629cd2339279922d914d93dce0e1f54e36a7e13`.

RC1 still requires the mandatory post-commit coordinated rollback probe before
an RC2 validation classification.
