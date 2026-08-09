# Decision Integrity-24 — GPT-5.6 Sol Self-Test Adjudication

Date: 2026-08-09

Classification: `AUTHOR_CONTAMINATED_CONFORMANCE_ONLY`

This is **not blind evidence** and is not valid for external method-lift claims because the benchmark family was created in the same conversation/research process.

## Modes

- U0 — Ordinary
- U1 — Bounded Revisable Closure
- U2 — Trialectic Decision Integrity

## Result

All three modes reached the scorer ceiling on the conformance run:

- action accuracy: 100%
- closure accuracy: 100%
- witness accuracy: 100%
- reopen-boundary accuracy: 100%
- material reopen sensitivity: 100%
- irrelevant-update invariance: 100%
- overreaction rate: 0%
- underreaction rate: 0%
- triplet integrity rate: 100%

## Interpretation

- U1 vs U0 action lift: 0 pp
- U2 vs U1 incremental lift: 0 pp in this contaminated conformance run
- no claim of Trialectic superiority is justified from this self-test
- the run does show that the Decision Integrity record is executable without forcing generic OPEN/HOLD states

## Semantic audit

The only required clarification is closure terminology:

`TERMINAL_CLOSED` means **terminal within the current frozen scope**. It does not mean that genuinely new contradictory evidence can never start a new decision episode.

Operational distinction retained:

- `TERMINAL_CLOSED`: no unresolved in-scope discriminator is required now
- `PROVISIONAL_CLOSED`: a named material update can reopen/change the commitment
- `INVESTIGATIVE_CLOSED`: the correct bounded action now is a specific test/verification
- `OPEN`: no justified bounded next action can be identified

## Research status

`DECISION_INTEGRITY=ACTIVE_HYPOTHESIS`

`TRIALECTIC_INCREMENTAL_VALUE=NOT_DEMONSTRATED`

`TRIALECTIC_KILLED=NO`

Independent or externally isolated runs are required for method comparison.
