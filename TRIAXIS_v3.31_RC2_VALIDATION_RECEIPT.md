# TRIAXIS v3.31-RC2 Validation Receipt

## Subject

- RC1 product commit: `71d0e48bcce3436b498ca675bf5afa15398d7b39`
- RC1 product tree: `3189b4e0aff6ff57075c6865007816ddf8a6b004`
- RC1 source tree: `2ee7824026cd4f304314234fc92d9d75eb7b948f`
- RC1 annotated-tag object: `85a4c2648960ae3e1a496ed0bd10991b4006bef6`
- post-product evidence commit: `7f67b17bfc4248226e6787005825467194817d8b`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `506 / 506 PASS`
- v3.31 closure: `32 / 32 PASS`
- closure rows SHA-256:
  `f0c57ad5b6a5fd6dc14e1c8f3624828e6e171cb36c2fa466382a881aff5cf2d9`
- real-process service smoke: `5 / 5 PASS`
- service-smoke rows SHA-256:
  `743c32b2b0f64498e64b0ca30dcfefe9f33317a5cbb0f4c0ee14aa9453faf692`
- exact-tag worktree after validation: clean

The frozen closure verifies full configured-set completion availability,
identity and trust-domain pinning, stale and missing response handling,
blocking-state veto, policy substitution rejection, permissive-state-set
widening rejection, signed availability-witness handoff, content-addressed
write-once provider-outcome objects, signed object receipts, exact replay
idempotency, materialized-object and receipt corruption detection, signed
append-only event continuity, state-root binding, checkpoint rollback/fork
detection, fresh single-use status, cumulative fail-closed preflight,
authenticated service boundaries, secret minimization and Draft 2020-12 schema
conformance.

## Post-product boundary

The exact-RC1 coordinated rollback probe demonstrated:

1. current provider state, full completion availability, logical completion
   anchor and immutable anchor block a completed stable effect;
2. after rollback of provider state and two completion witnesses, the inherited
   pair can form a permissive 2-of-3 statement, but the v3.31 all-configured
   policy blocks the missing current witness;
3. the current immutable anchor independently continues to report `COMPLETED`;
4. after rollback of the immutable-anchor filesystem, the retained checkpoint
   rejects its lower signed head with `immutable_anchor_checkpoint_rollback`;
5. after coordinated rollback of provider, all completion witnesses, the
   logical anchor, immutable-anchor filesystem and checkpoint, all completion
   evidence reports `ABSENT` for the same stable effect;
6. rollback of two execution-head authorities permits the inherited threshold
   to recreate the old execution view while the current third authority rejects
   the fork;
7. the same stable `effect_id` receives a new dispatch and becomes executable
   again in the local reference;
8. rollback-boundary rows SHA-256:
   `a7c3ccfe4527f6ac704976098d3c529673b32aa8e983bace5eb6e055be1b88fc`.

Boundary status: `BOUNDARY_CONFIRMED`.

Therefore v3.31 prevents silent omission of one configured completion witness
and detects immutable-anchor rollback while verifier checkpoint memory remains
current. It does not establish production exactly-once execution under
coordinated rollback of every completion-evidence domain and the checkpoint.

## Source immutability

The post-product evidence commit does not change `src/`.

- RC1 source tree: `2ee7824026cd4f304314234fc92d9d75eb7b948f`
- post-evidence source tree: `2ee7824026cd4f304314234fc92d9d75eb7b948f`

## RC2 classification

RC2 is validation-only. It records exact-tag validation and the observed
coordinated rollback boundary without changing RC1 product source.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- physical independence: `false`
- administrative independence: `false`
- physical WORM established: `false`
- hardware monotonicity: `false`
- independent certification: `false`
- real provider adapter: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
