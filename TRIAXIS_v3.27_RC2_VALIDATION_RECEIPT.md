# TRIAXIS v3.27-RC2 Validation Receipt

## Subject

- RC1 product commit: `06c2e2930a4ef8d922c170df28e4b2b0e0e85050`
- RC1 product tree: `d00ff37efc2f0318ff1606c004576f8592293b92`
- RC1 source tree: `6c3faff1f661246e9b99a39c165e5a823f5e84a8`
- post-commit evidence commit: `a999870445c92379ff7c899e784a641ff8ccd31e`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `393 / 393 PASS`
- v3.27 external-execution-ledger closure: `14 / 14 PASS`
- closure rows SHA-256: `1a7cc1b20738f7ba7137551d568d6edc4041bcad5d5ce396c13db7a3d5dcf2ab`
- exact-tag worktree status: clean

The frozen closure verifies stable effect identity, signed receipts and heads, exact transport idempotency, conflict rejection, queue-rollback protection, token-rotation resistance, fail-closed intent substitution, `UNKNOWN` reconciliation, restart persistence, concurrent reservation exclusion, HTTP authentication, and schema conformance.

## Post-product boundary

The frozen whole-ledger rollback probe demonstrated:

1. with the current external ledger, a completed effect remains blocked;
2. restoring both the queue database and execution-ledger database to their pre-dispatch snapshots erases the completed state;
3. the revived local request retains the same stable `effect_id`, receives a new `dispatch_id`, and is accepted by the rolled-back ledger;
4. the rollback boundary rows SHA-256 is `8110672490cf21a6d4ddbf65d78267259b0b1f40753924d90863daadf3485a84`.

Therefore separate persistence from the queue is necessary but insufficient. The next material control is an independently persisted monotonic ledger-head verifier or quorum, provider-side idempotency keyed by stable `effect_id`, or authoritative provider-side reconciliation before retry.

## RC2 classification

RC2 is validation-only. No product source change follows RC1.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- independent certification: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
