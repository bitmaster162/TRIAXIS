# Decision Integrity-24 v0.1 — Release Receipt

Status: `FROZEN_BEFORE_SOLVER_EXPOSURE`

## Shape

- 24 blind cases
- 8 hidden triplets
- each triplet contains:
  - `BASE`
  - `MATERIAL UPDATE`
  - `IRRELEVANT UPDATE`
- public family metadata: hidden
- public triplet metadata: hidden
- witness length: 2–4 observations

## What the triplets test

For every triplet:

- the material update crosses the decision boundary and must change the bounded action;
- the irrelevant/rhetorical update must preserve the bounded action;
- the solver must bind the commitment to a sufficient witness and a reopen boundary.

## Primary metrics

- action accuracy
- closure accuracy
- witness accuracy
- reopen-boundary accuracy
- material reopen sensitivity
- irrelevant-update invariance

Secondary:

- triplet integrity rate
- overreaction rate
- underreaction rate

## Closure distribution

- `INVESTIGATIVE_CLOSED`: 14
- `PROVISIONAL_CLOSED`: 7
- `TERMINAL_CLOSED`: 3

`TERMINAL_CLOSED` means terminal within the current frozen scope, not metaphysically irreversible.

## Preflight

- all triplets material-flip / irrelevant-preserve: PASS
- witness sets within contract: PASS
- family hidden: PASS
- triplet IDs hidden: PASS
- scorer perfect fixture: PASS
- scorer bad fixture discrimination: PASS

## Frozen artifacts

Subject kit SHA-256:
`0f09916a2bbf12bb0f23cf47717b1180384e48f313f2e13a658b3f3c57be9923`

Private evaluator SHA-256:
`6055ae71d201a4b118368f9dd5bd90bf78628584353e588d883125deeab2833f`

Private oracle is intentionally not committed.

## Arms

- `U1`: Bounded Revisable Closure
- `U2`: Trialectic Decision Integrity (`REALITY → ANGEL → DEVIL → COMMITMENT → REOPEN`)

## Frozen narrowing rule

Trialectic incremental value requires improvement on at least one primary dimension by >=12.5 pp (one of eight triplets) without >=4.2 pp action harm. Otherwise no incremental Trialectic value is demonstrated on DI24.

Broad Decision Integrity lift requires improvement on at least two primary dimensions while preserving action accuracy.
