# TRIAXIS v3.32-RC2 Release Notes

v3.32 is the terminal same-host/local-reference release in this control-stack
line. RC2 adds validation evidence only; product source is byte-identical to RC1.

## Material result

- Stable provider-native `effect_id` contract with write-once transition chain.
- Current pinned provider policy is validated at the evaluation tick; a matching
  historical digest is insufficient.
- `IN_FLIGHT`, `UNKNOWN`, and `COMPLETED` remain retry-blocking.
- Completion transparency uses an operator-pinned threshold over the current
  immutable-anchor head.
- A valid newer minority or same-sequence fork vetoes an old majority.
- Transparency inner freshness windows must exactly match the signed envelope.
- Evidence services grant no execution authority.

## Validation

- Full suite: 533/533 PASS.
- v3.32 closure: 27/27 PASS.
- Service process smoke: 5/5 PASS.
- Coordinated local rollback boundary: BOUNDARY_CONFIRMED.

## Terminal claim boundary

A coordinated rollback of all local provider/completion/transparency evidence
state can restore an old permissive view. Exactly-once execution is not
established. Any stronger claim requires external evidence under
`TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`.
