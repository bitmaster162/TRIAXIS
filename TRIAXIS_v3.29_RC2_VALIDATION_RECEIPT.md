# TRIAXIS v3.29-RC2 Validation Receipt

## Subject

- RC1 product commit: `0b727ebe5e18adc553b6c08954061d5925314086`
- RC1 product tree: `a267bbd74c6f4a207d9317b459275f9fc4096dab`
- RC1 source tree: `d946ef6f60fac4dfe2f7e4bc546a4c2a0d990de0`
- RC1 annotated-tag object: `834e6cf765fffe1320fbc07a29fc54cba3fe26d1`
- post-product evidence commit: `1f01c81b88f629a556a0afcf4235276f31a6db6a`

## Exact product validation

The annotated RC1 tag was checked out into an independent detached worktree.

- unit and historical tests: `448 / 448 PASS`
- v3.29 quorum/completion-witness closure: `33 / 33 PASS`
- closure rows SHA-256: `dcf3e947a6a85b5f2fab5e6c7e4064a2d5473953da8bf9b85c78277424463528`
- real-process service smoke: `3 / 3 PASS`
- service-smoke rows SHA-256: `511b5abf507085188c4fcdd8170f1b6e9c22fcc43f4dcfe1c9d7deb66aa4acdb`
- exact-tag worktree before the adversarial probe: clean

The frozen closure verifies operator-pinned quorum configuration, 2-of-3 exact
head agreement, stale/unavailable/split-view handling, duplicate identity and
key rejection, signer equivocation, local-ledger rollback detection, signed
aggregate quorum-witness handoff revalidated against the pinned configuration,
provider outcome receipts, completion-witness reservation, full signed witness
chain and head verification, status state-root binding, reconciliation,
provider rollback resistance, composed preflight, authenticated process
boundaries, secret minimization, and schema conformance.

## Post-product boundary

The exact-RC1 coordinated rollback probe demonstrated:

1. with queue, execution ledger, all three head authorities, provider state and
   completion witness current, the completed effect is blocked;
2. after rollback of queue, execution ledger and provider state, the current
   2-of-3 head quorum detects the local rollback and the current completion
   witness still reports `COMPLETED`;
3. after coordinated rollback of the provider, completion witness and two of
   the three head authorities, the rolled-back majority forms a valid old
   2-of-3 statement while the one current minority rejects the fork;
4. the same stable `effect_id` becomes executable again in the rolled-back
   provider and completion-witness state;
5. the rollback-boundary rows SHA-256 is
   `7484baaef7e444d0d144738d062fb342d08cd64b7e26673c27425fedf1c15e08`.

Boundary status: `BOUNDARY_CONFIRMED`.

Therefore v3.29 materially extends rollback resistance beyond a single head or
provider database, but it does not establish production exactly-once execution
under compromise or coordinated rollback of a quorum threshold together with
the completion-memory domain.

## Source immutability

The post-product evidence commit does not change `src/`.

- RC1 source tree: `d946ef6f60fac4dfe2f7e4bc546a4c2a0d990de0`
- post-evidence source tree: `d946ef6f60fac4dfe2f7e4bc546a4c2a0d990de0`

## RC2 classification

RC2 is validation-only. It records the exact-tag validation and observed
threshold boundary without changing the RC1 product source.

- analysis: `PASS_WITH_CONDITIONS`
- production-qualified: `false`
- physical independence: `false`
- administrative independence: `false`
- independent certification: `false`
- real provider adapter: `false`
- external execution permission: `NOT_IMPLIED`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`
