# TRIAXIS v3.26-RC2 Validation Receipt

## Subject

- RC1 product commit: `f147b480e6e292fc418ad412e29e06131f745edf`
- RC1 product tree: `b22dce4974bf9d04d4938f977804a22ee104ae92`
- RC1 source tree: `c4b5472257a6c43b624436aa455d4676d5d01aa6`
- post-commit evidence commit: `3ed91875cf7f06818398ab9978bc73b98d238e9e`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `379 / 379 PASS`
- v3.26 durable-dispatch closure: `10 / 10 PASS`
- worktree status: clean

## Post-product boundary

The frozen rollback probe demonstrated:

1. without rollback, a delivered mutating input cannot be claimed again;
2. restoring the entire SQLite queue file to a pre-dispatch snapshot revives the old queued input;
3. the revived input can receive a new claim and therefore can produce a duplicate external effect.

This is a local monotonic-freshness boundary. It is not repaired by another table in the same database.

Required external controls include a separately administered execution ledger, external monotonic dispatch head, or authoritative idempotency/reconciliation at the external tool boundary.

## RC2 classification

RC2 is validation-only. No product source change follows RC1.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- independent certification: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
