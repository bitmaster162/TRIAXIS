# Dual-State Decision Integrity v0.1

## Core correction

Decision systems must track two states separately:

1. **Epistemic state** — whether the decision-relevant proposition/world state is resolved.
2. **Operational closure** — whether a justified bounded action exists now.

This avoids the FC16 failure where `NOT_ENOUGH` was forced to mean both epistemic uncertainty and absence of action closure.

## Canonical record

```json
{
  "epistemic_state": "RESOLVED | UNRESOLVED",
  "closure_class": "TERMINAL_CLOSED | PROVISIONAL_CLOSED | INVESTIGATIVE_CLOSED | OPEN",
  "action": "bounded commitment now",
  "minimal_witness": ["O1", "O4"],
  "reopen_condition": "smallest material future evidence condition"
}
```

## Closure classes

### TERMINAL_CLOSED
Within the current frozen scope, no unresolved in-scope discriminator is required for the current bounded action/claim.

### PROVISIONAL_CLOSED
The action is justified now, but a named material future observation would change or reopen it.

### INVESTIGATIVE_CLOSED
The underlying proposition may be unresolved, but the correct bounded action now is a specific verification/test.

### OPEN
No justified bounded next action can be identified from current admissible evidence and action surface.

## Important state combinations

### UNRESOLVED + INVESTIGATIVE_CLOSED
The world state is unknown, but the next action is already determined.

Example: mutation effect unknown; do not retry; query the authoritative idempotency scope.

### RESOLVED + INVESTIGATIVE_CLOSED
The current state is known, but the correct next action is still a verification/approval step.

Example: exact digest D7 is known to lack semantic-owner approval; obtain review of D7 before promotion.

### RESOLVED + TERMINAL_CLOSED
The bounded claim is established/rejected within current scope and no in-scope discriminator remains necessary.

## Trialectic mapping

`REALITY -> ANGEL <-> DEVIL -> COMMITMENT -> REOPEN`

- REALITY owns epistemic state.
- ANGEL owns constructive action support.
- DEVIL owns action-changing countermodels.
- COMMITMENT owns bounded action now.
- REOPEN owns future material revision conditions.

## Prior-art boundary

This is **not** a claim to invent belief-state/action separation, belief revision, value of information, or provenance. Those are established adjacent areas.

The research question is narrower: whether a model-agnostic decision record and benchmark that jointly scores epistemic state, bounded commitment, minimal sufficient witness, counterfactual/reopen boundary, and audit trace exposes useful capabilities or failure modes not captured by final-answer accuracy alone.

## Research hypothesis

The useful primitive may be neither generic debate nor generic belief revision. It may be **synchronization between epistemic state and bounded commitment state**, with externally auditable evidence and explicit reopen boundaries.
