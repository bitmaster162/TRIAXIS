# TRIAXIS v3.28-RC2 Validation Receipt

## Subject

- RC1 product commit: `7d7e488185410d0cdadc2476c147ead062be0706`
- RC1 product tree: `1b1984981cc6d6a9e84822c3a0984c3258597470`
- RC1 source tree: `cdb23a7dafb450e0a0b8f0a56380cc7c206edc3e`
- RC1 annotated-tag object: `bc4d8b70ad28256c2e2d13865ded0d88cf6a8d9f`
- post-product evidence commit: `70ac891699a2be0cfbedd6a1d0f1352d46ef2544`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `415 / 415 PASS`
- v3.28 execution-head/provider closure: `22 / 22 PASS`
- closure rows SHA-256: `905260b95aeb77a8d3cafdd00a087178ee8239927b884444af13d2725dc50222`
- head-authority runner startup/shutdown smoke: `PASS`
- provider runner startup/shutdown smoke: `PASS`
- exact-tag worktree status: clean

The frozen closure verifies contiguous signed head advance, idempotent head
replay, stale-head and same-sequence-fork rejection, rollback/fork detection,
fresh single-use challenge binding, guarded reservation, exact `IN_FLIGHT` head
anchoring, restart persistence, HTTP authentication and secret minimization,
provider payload binding, transport idempotency, `UNKNOWN` blocking and
reconciliation, signed provider status, provider restart persistence, and schema
conformance.

## Post-product boundary

The frozen coordinated rollback probe demonstrated:

1. current ledger and provider state block the completed effect;
2. rollback of the queue, execution ledger, and external head authority revives
   the local reservation path, but the still-current provider `COMPLETED` record
   blocks another external effect;
3. restoring the provider idempotency store to its pre-effect snapshot as well
   causes the same stable `effect_id` and exact payload to be accepted again;
4. the rollback-boundary rows SHA-256 is
   `a5e8313d1dd0189b9e90275abd1e6146b7618ce18896f83c3c6d5259fa25e61a`.

Therefore v3.28 materially extends rollback protection but does not establish
exactly-once execution under coordinated rollback or compromise of every
relevant state domain.

## Source immutability

The post-product evidence commit does not change `src/`.

- RC1 source tree: `cdb23a7dafb450e0a0b8f0a56380cc7c206edc3e`
- post-evidence source tree: `cdb23a7dafb450e0a0b8f0a56380cc7c206edc3e`

## RC2 classification

RC2 is validation-only. It adds release documentation and records the observed
boundary without modifying the RC1 product source.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- independent certification: `false`
- real provider adapter: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
