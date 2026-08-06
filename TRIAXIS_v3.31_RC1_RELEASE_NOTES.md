# TRIAXIS v3.31-RC1 Release Notes

v3.31 closes the availability gap left by the v3.30 completion threshold and
adds a separate content-addressed immutable-anchor reference.

For `HIGH` and `CRITICAL` effects, the new policy requires a fresh statement
from every configured completion witness. Missing, stale, substituted,
equivocal or semantically disagreeing evidence blocks even if the old 2-of-3
threshold could otherwise pass. `ABSENT` and `NO_EFFECT` remain distinct, and
any valid `RESERVED`, `UNKNOWN` or `COMPLETED` member vetoes retry.

The immutable-anchor reference stores exact signed provider-outcome envelopes
under their canonical content digest using write-once `O_EXCL` creation. A
signed object receipt binds retention and legal-hold assertions. A separate
signed event chain, head and challenge-bound effect status remain independently
verifiable. A verifier-side SQLite checkpoint rejects a lower sequence or a
different same-sequence head/state root while checkpoint state remains current.

The implementation is not physical WORM storage. The filesystem and checkpoint
can still be rolled back by their administrator. The post-product coordinated
rollback probe remains mandatory before RC2 classification.

Frozen pre-RC1 validation:

- full regression suite: **506/506 PASS**;
- v3.31 closure: **32/32 PASS**;
- closure rows SHA-256:
  `f0c57ad5b6a5fd6dc14e1c8f3624828e6e171cb36c2fa466382a881aff5cf2d9`;
- service process smoke: **5/5 PASS**;
- service-smoke rows SHA-256:
  `743c32b2b0f64498e64b0ca30dcfefe9f33317a5cbb0f4c0ee14aa9453faf692`.

The final static audit also closed an API-level policy-widening path:
`allowed_states` is now constrained to a non-empty unique subset of exactly
`ABSENT` and `NO_EFFECT`. A caller cannot relabel `UNKNOWN` or `COMPLETED` as
permissive.
