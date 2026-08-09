# Decision Closure-24 v0.1.1 Release

Status: `FROZEN_BEFORE_SOLVER_EXPOSURE`

## Shape

- 24 blind cases
- 12 paired closure states
- 12 `ENOUGH`
- 12 `NOT_ENOUGH`
- two-chat A/B execution: Ordinary U0 vs Decision Closure U1
- no LLM judge required for primary metrics

## Deterministic dimensions

- sufficiency accuracy
- action-field accuracy
- minimal-witness accuracy
- flip accuracy on `ENOUGH`
- discriminator accuracy on `NOT_ENOUGH`
- stop accuracy
- pair closure joint accuracy

## Leakage controls

- action labels: A1/A2/A3/A4 = 3/3/3/3
- flip labels: F1/F2/F3/F4 = 3/3/3/3
- discriminator labels: T1/T2/T3/T4 = 3/3/3/3
- witness lengths: 2..5 observations
- family labels hidden
- pair IDs hidden
- preflight: PASS
- scorer perfect fixture: 100% on all metrics
- scorer bad fixture: 0% sufficiency, witness, stop, and pair closure joint

## Frozen package hashes

Subject kit SHA-256:
`81696767cd36a82a836de58143d51e2f82a3fe8c73afe824b87a0136a58bab46`

Private evaluator SHA-256:
`8b293e4a7d00af4c013fa011f0cb1372747f7ba6f2d0e917d75d4ab509a38099`

The private oracle/evaluator is intentionally not committed to this research branch to preserve blind evaluation integrity.

## Broad-lift rule

A broad Decision Closure lift requires improvement of at least two primary closure dimensions by >=10 percentage points each with no >=3 percentage-point action-field harm.

If the gain is isolated, narrow the claim:
- witness only -> Decision Trace / Auditability
- flip only -> Decision Boundary
- discriminator only -> Decision Discriminator
- stop only -> Decision Frontier / Cost Control
