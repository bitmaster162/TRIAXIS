# Decision Integrity Primitive v0.1

Decision Integrity is the ability to make a bounded commitment that is simultaneously:

1. **supported** — reconstructable from a minimal sufficient evidence witness;
2. **fragility-aware** — paired with the smallest material condition that would change it;
3. **revisable** — reopened on material evidence rather than rhetorical pressure;
4. **stable** — invariant to irrelevant updates;
5. **auditable** — externally replayable from the frozen decision record.

## Core record

```json
{
  "closure_class": "TERMINAL_CLOSED | PROVISIONAL_CLOSED | INVESTIGATIVE_CLOSED | OPEN",
  "action": "bounded commitment now",
  "minimal_witness": ["O2", "O7"],
  "reopen_condition": "smallest material evidence condition"
}
```

## Trialectic implementation

`REALITY → ANGEL ↔ DEVIL → COMMITMENT → REOPEN RULE`

- **REALITY**: bind decision scope and admissible evidence.
- **ANGEL**: construct the strongest minimal sufficient support for a bounded action now.
- **DEVIL**: identify one materially plausible countermodel that would force a different bounded action.
- **COMMITMENT**: act now; do not wait for metaphysical certainty.
- **REOPEN RULE**: state exactly what future evidence changes the commitment.

The third pole is therefore not a synthesizer persona. It is **revisable commitment**.

## Operational invariants

- Material update that crosses the decision boundary must change the commitment.
- Irrelevant/rhetorical update must not change the commitment.
- Epistemic uncertainty does not automatically imply operational non-closure.
- A verification/test can itself be the closed bounded action (`INVESTIGATIVE_CLOSED`).
- `TERMINAL_CLOSED` means terminal within the current frozen scope, not immutable forever.

## Candidate metrics

- action accuracy
- closure-class accuracy
- minimal-witness sufficiency
- reopen-boundary accuracy
- material reopen sensitivity
- irrelevant-update invariance
- overreaction rate
- underreaction rate
- triplet integrity rate

## Failure modes

- PREMATURE_COMMITMENT
- PERMANENT_HESITATION
- WITNESS_GAP
- COUNTERMODEL_BLINDNESS
- REOPEN_OVERREACTION
- REOPEN_UNDERREACTION
- PROVENANCE_OVERCLAIM
- INSTRUMENT_OVERCLAIM
- ZERO_VOI_CONTINUATION

## Current claim discipline

Decision Integrity is a research hypothesis, not a validated product claim.

TRIAXIS/Trialectic Closure is one candidate implementation. The benchmark remains method-neutral and the method is not the oracle.
