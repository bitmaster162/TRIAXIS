# Prior-art position — 2026-08-10

This note is a research positioning memo, not a novelty claim.

## Adjacent established components

### Belief-state policies / POMDPs
Partially observable decision models explicitly separate uncertain belief state from action policy and can value information-gathering actions.

### Value of Information / optimal stopping
Sequential decision theory studies whether another observation is worth its cost and when an information-acquisition process should stop.

### Belief/intention revision
BDI and belief-revision work separates beliefs from commitments/intentions and studies how new facts should trigger revision.

### Preregistered belief-revision triggers
Recent work on Preregistered Belief Revision Contracts (PBRC) fixes admissible evidence triggers and witness sets for auditable epistemic change.

### Agent provenance / auditability
Recent agent research treats evidence tracing, provenance, replayability, and process-level accountability as distinct from final-answer correctness.

## Current candidate wedge

Do **not** claim invention of belief revision, value of information, provenance, or action under uncertainty.

The narrower candidate is a unified, model-agnostic decision record and benchmark for synchronizing:

1. epistemic state;
2. bounded operational commitment;
3. minimal sufficient evidence witness;
4. one action-changing countermodel;
5. explicit reopen trigger;
6. evidence provenance / audit replay;
7. stop/continue behavior under decision value.

The key semantic distinction is:

`UNRESOLVED != OPEN`

A system may be uncertain about the world and still have a fully justified bounded action now.

## Falsification

Collapse or narrow this research direction if a simpler existing formalism or baseline reproduces the same measurable benefits at lower cost.

TRIAXIS remains a contestant/implementation hypothesis, not the oracle.
