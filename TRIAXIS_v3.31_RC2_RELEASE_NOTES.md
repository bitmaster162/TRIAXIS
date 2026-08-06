# TRIAXIS v3.31-RC2 Release Notes

v3.31 closes the witness-availability gap left by the v3.30 threshold policy and
adds a separate content-addressed immutable-anchor reference.

For `HIGH` and `CRITICAL` effects, every configured completion witness must
produce one fresh, exact, identity-pinned statement. Missing, stale,
substituted, equivocal or semantically disagreeing evidence blocks even when an
inherited 2-of-3 threshold could otherwise pass. `ABSENT` and `NO_EFFECT` remain
distinct, and `RESERVED`, `UNKNOWN` or `COMPLETED` cannot be relabelled as
permissive through the verifier API.

The immutable-anchor reference stores the exact signed provider-outcome
envelope under its canonical digest using `O_CREAT|O_EXCL`. A signed object
receipt binds the stable effect, provider request, content identity, retention
window and legal-hold assertions. A separate signed event chain, head, state
root and challenge-bound effect status remain independently verifiable. A
verifier-side checkpoint rejects a lower sequence or a different same-sequence
head/state root while checkpoint state remains current.

RC2 makes no product-source changes. It records exact-RC1 validation and the
mandatory coordinated rollback boundary:

1. current provider state, full completion availability and both completion
   anchors block the completed effect;
2. rollback of provider and two completion witnesses allows the inherited
   threshold to report `ABSENT`, but v3.31 blocks because one configured witness
   is missing, while the current immutable anchor still reports `COMPLETED`;
3. rollback of the immutable-anchor filesystem is rejected by the retained
   verifier checkpoint;
4. coordinated rollback of provider, all completion witnesses, the logical
   anchor, the immutable-anchor filesystem and its verifier checkpoint
   recreates a complete permissive old view for the same stable effect;
5. the inherited execution-head threshold can also recreate the old execution
   view while one current execution-head minority rejects the fork.

The filesystem anchor is therefore a logical immutable-object reference, not
physical WORM storage. Availability-closed membership prevents omission of one
current witness; it cannot survive rollback of every configured witness and its
external checkpoint memory.

Frozen results:

- historical and new tests: `506 / 506 PASS`;
- v3.31 closure: `32 / 32 PASS`;
- closure rows SHA-256:
  `f0c57ad5b6a5fd6dc14e1c8f3624828e6e171cb36c2fa466382a881aff5cf2d9`;
- four-process service smoke: `5 / 5 PASS`;
- service-smoke rows SHA-256:
  `743c32b2b0f64498e64b0ca30dcfefe9f33317a5cbb0f4c0ee14aa9453faf692`;
- rollback-boundary rows SHA-256:
  `a7c3ccfe4527f6ac704976098d3c529673b32aa8e983bace5eb6e055be1b88fc`;
- boundary status: `BOUNDARY_CONFIRMED`.

The next material control requires provider-native durable idempotency keyed by
stable `effect_id`, an independently administered physical WORM or append-only
completion anchor, a transparency/checkpoint quorum outside completion-evidence
administrators, hardware-backed monotonic anti-rollback state, and real
multi-host/multi-administrator evidence.
