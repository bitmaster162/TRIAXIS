# Trialectic Closure v0.1

## Core

Trialectic Closure is **not** three personas debating by default.

It is a conditional closure operator:

`REALITY → ANGEL → DEVIL → CLOSURE`

### REALITY
Bind one decision and admissible evidence. Establish provenance, currentness, scope, authority, and measurement validity only where decision-relevant.

### ANGEL — strongest sufficient positive case
Construct the smallest valid witness supporting the leading bounded action.

ANGEL may return `NO_CLOSED_CASE` when no action has a sufficient witness.

### DEVIL — strongest action-changing countercase
Attack only the ANGEL closure. Identify at most one materially plausible alternative state that implies a different action. Generic doubt, rhetoric, already-falsified alternatives, and counterexamples that cannot change the action are forbidden.

DEVIL returns either:

- `NO_SURVIVING_COUNTERCASE`, or
- one surviving countermodel plus the observation that discriminates it.

### CLOSURE
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

## Why retain ANGEL and DEVIL

ANGEL tests **constructive sufficiency**.

DEVIL tests **counterfactual fragility**.

Their useful asymmetry is:

> Can I prove closure?

versus

> Can one plausible material fact still change the action?

## Bypass rules

- Direct evidence may make ANGEL one line.
- DEVIL must name a distinct surviving action-changing model or return `NO_SURVIVING_COUNTERCASE`.
- One DEVIL countermodel maximum per evidence state.
- No majority vote.
- No repeated debate rounds.
- Stop at the decision frontier.

## Relation to Decision Closure

Decision Closure is the minimal operational core.

Trialectic Closure is a conditional adversarial implementation of the sufficiency and flip-boundary checks. It survives only if it improves closure, witness, flip, or discriminator quality over the simpler Decision Closure protocol at acceptable cost.