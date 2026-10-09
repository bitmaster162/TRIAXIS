# Trialectic Closure v0.1

Trialectic Closure is a conditional closure operator, not default persona debate:

`REALITY → ANGEL → DEVIL → CLOSURE`

## REALITY
Bind one decision and admissible evidence. Establish provenance, currentness, scope, authority and measurement validity only where decision-relevant.

## ANGEL — constructive sufficiency
Construct the smallest valid witness supporting the leading bounded action. ANGEL may return `NO_CLOSED_CASE` when no action has a sufficient witness.

## DEVIL — counterfactual fragility
Attack only the ANGEL closure. Name at most one materially plausible alternative state that implies a different action. Generic doubt, rhetoric, already-falsified alternatives, and counterexamples that cannot change the action are forbidden.

DEVIL returns either `NO_SURVIVING_COUNTERCASE` or one surviving countermodel plus the observation that discriminates it.

## CLOSURE
If ANGEL has a sufficient witness and DEVIL has no surviving action-changing countercase:

- `status=ENOUGH`
- emit action + minimal witness
- emit smallest material flip condition
- `stop=true`

If DEVIL has a surviving action-changing countercase:

- `status=NOT_ENOUGH`
- do not force a final action
- choose one bounded discriminator
- `stop=false`

## Bypass rules

- Direct evidence may make ANGEL one line.
- DEVIL must name a distinct action-changing model or return `NO_SURVIVING_COUNTERCASE`.
- One DEVIL countermodel maximum per evidence state.
- No majority vote.
- No repeated debate rounds.
- Stop at the decision frontier.

## Research status

Decision Closure remains the minimal core. Trialectic Closure survives only if the ANGEL/DEVIL asymmetry improves false-closure resistance, witness quality, flip-boundary precision, or discriminator selection over simpler Decision Closure at acceptable cost.