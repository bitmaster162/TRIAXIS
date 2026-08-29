# Semantic Contract Split v0.1

## Problem

A single status variable such as `ENOUGH / NOT_ENOUGH` can silently overload two different state spaces:

- **epistemic state** — whether the underlying proposition/world state is resolved;
- **operational closure** — whether a bounded action is justified now.

Competent solvers may then produce different but internally coherent outputs from the same public case.

Example:

- underlying provenance lineage may be unresolved in some details;
- yet a directly established reasoning-input dependency is already sufficient to reject an independence claim now.

A solver can therefore say `epistemically unresolved` while also saying `operationally closed: reject`.

## Failure class

`SEMANTIC_CONTRACT_SPLIT`

Definition:

> Two competent solvers map the same ambiguous contract vocabulary to different latent state variables, producing divergent outputs even when the underlying reasoning is coherent.

## Required fix

Never overload the two dimensions.

Canonical record:

```json
{
  "epistemic_state": "RESOLVED | UNRESOLVED",
  "closure_class": "TERMINAL_CLOSED | PROVISIONAL_CLOSED | INVESTIGATIVE_CLOSED | OPEN",
  "action": "bounded action now",
  "minimal_witness": ["O2", "O7"],
  "reopen_condition": "smallest material evidence condition"
}
```

Critical valid states include:

- `UNRESOLVED + INVESTIGATIVE_CLOSED`
- `UNRESOLVED + PROVISIONAL_CLOSED`
- `RESOLVED + INVESTIGATIVE_CLOSED`

Therefore:

`UNRESOLVED != OPEN`

and

`RESOLVED != TERMINAL_CLOSED`.

## Relation to Trialectic Decision Integrity

- REALITY tracks epistemic state.
- ANGEL constructs support for a bounded action.
- DEVIL identifies an action-changing countermodel.
- COMMITMENT selects the bounded action now.
- REOPEN defines the material condition that changes the commitment.

The semantic split is therefore not a formatting issue. It is a first-class decision-integrity failure mode.
