# Dual-State Integrity-16 release receipt

Status: `FROZEN_BEFORE_SOLVER_EXPOSURE`

## Corpus

- 16 blind cases / 8 paired scenarios
- epistemic state:
  - `UNRESOLVED`: 6
  - `RESOLVED`: 10
- operational closure:
  - `INVESTIGATIVE_CLOSED`: 7
  - `PROVISIONAL_CLOSED`: 7
  - `TERMINAL_CLOSED`: 2
- explicit stress cases:
  - `UNRESOLVED + operationally closed`: 6
  - `RESOLVED + INVESTIGATIVE_CLOSED`: 1
- family metadata hidden
- pair metadata hidden
- preflight: PASS
- scorer validation: PASS

## Metrics

- epistemic accuracy
- closure accuracy
- action accuracy
- witness accuracy
- reopen-boundary accuracy
- unresolved-closure accuracy
- semantic-conflation rate
- pair-integrity rate

## Public subject kit

SHA-256:

`c77caa116bcb22a592be7ca5be4ba65e673dbf4fd10b65f98e249d3c066ef997`

## Private evaluator

SHA-256:

`c01978d9083e47dc36a0c38da89922ed927f730d37a8ba9d55fdc9a192ce8d2f`

Private oracle is not committed.

## Run

Two fresh contexts only:

1. U1 Dual-State Decision Integrity + DS16
2. U2 Trialectic Dual-State Decision Integrity + same DS16

No cross-arm context.
