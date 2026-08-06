# TRIAXIS v3.30-RC2 Validation Receipt

## Subject

- RC1 product commit: `9e98ede98bf561a050eddcd578dbf814ab7324ac`
- RC1 product tree: `311a66e0beda000d9fa6739bd38ee17aa20bc4cf`
- RC1 source tree: `57816a3be34f83d65dfd177143359ab49671ad7c`
- RC1 annotated-tag object: `02c99863f07bd47f7abc3fee8e7f6fa84e2c19ad`
- post-product evidence commit: `fe0d2c9275453553d66c4003a263c266b51b374b`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `474 / 474 PASS`
- v3.30 closure: `26 / 26 PASS`
- closure rows SHA-256:
  `32ebaf6247db3310329eee05c5727878c13102aac70d5df89c2c750fe120a0ec`
- real-process service smoke: `5 / 5 PASS`
- service-smoke rows SHA-256:
  `eeb61fdd4918271972b6e3fb6629cd2339279922d914d93dce0e1f54e36a7e13`
- exact-tag worktree after validation: clean

The frozen closure verifies pinned completion-witness quorum configuration,
2-of-3 exact agreement, identity and trust-domain distinctness, stale response
handling, duplicate response rejection, signer equivocation, semantic-state
agreement, blocking-minority veto, signed aggregate witness handoff, signed
provider outcome ingestion, exact replay idempotency, payload substitution
rejection, reconciliation and generation rules, full anchor chain and head,
state-root binding, fresh single-use status, composed preflight, authenticated
process boundaries, secret minimization and schema conformance.

## Post-product boundary

The exact-RC1 coordinated rollback probe demonstrated:

1. current provider state, completion quorum and anchor block a completed stable
   effect;
2. after rollback of provider state and two completion witnesses, the old pair
   can form a permissive 2-of-3 statement when the current minority is omitted,
   but the current anchor still reports `COMPLETED` and blocks;
3. after rollback of the anchor, inclusion of the current completion minority
   triggers the blocking-minority veto;
4. after coordinated rollback of queue, ledger, provider, two execution-head
   authorities, two completion witnesses and the anchor, the rolled-back
   thresholds form valid old statements;
5. the current execution-head minority rejects the fork and the current
   completion minority would veto if queried, but omission of that completion
   minority allows the same stable `effect_id` to become executable again;
6. rollback-boundary rows SHA-256:
   `4e5276e61d58126d27ba5a6c911795a494c75889ddd4b6e130e06be7c6734800`.

Boundary status: `BOUNDARY_CONFIRMED`.

Therefore v3.30 materially extends rollback resistance beyond a single
completion witness. It does not establish production exactly-once execution
under coordinated rollback of both quorum thresholds and the logical anchor,
or when a current blocking witness is omitted.

## Source immutability

The post-product evidence commit does not change `src/`.

- RC1 source tree: `57816a3be34f83d65dfd177143359ab49671ad7c`
- post-evidence source tree: `57816a3be34f83d65dfd177143359ab49671ad7c`

## RC2 classification

RC2 is validation-only. It records exact-tag validation and the observed
coordinated rollback/omission boundary without changing RC1 product source.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- physical independence: `false`
- administrative independence: `false`
- physical WORM established: `false`
- independent certification: `false`
- real provider adapter: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
