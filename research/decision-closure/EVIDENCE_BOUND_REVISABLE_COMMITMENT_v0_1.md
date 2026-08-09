# Evidence-Bound Revisable Commitment (EBRC) v0.1

Status: candidate primitive

## Why this name

`Decision Integrity` and `Commitment Integrity` are already used by adjacent 2026 research/products for different constructs. EBRC names the narrower object under test without claiming ownership of those broader terms.

## Primitive

An **Evidence-Bound Revisable Commitment** is a bounded action selected now that is:

1. supported by a minimal sufficient evidence witness;
2. explicit about the current epistemic state;
3. tested against at most one surviving action-changing countermodel;
4. paired with a concrete material reopen condition;
5. stable under irrelevant/rhetorical updates;
6. externally replayable from its evidence trace.

Canonical record:

```json
{
  "epistemic_state": "RESOLVED | UNRESOLVED",
  "commitment_class": "TERMINAL | PROVISIONAL | INVESTIGATIVE | OPEN",
  "action": "bounded action now",
  "minimal_witness": ["O2", "O7"],
  "surviving_countermodel": "one action-changing alternative | null",
  "reopen_trigger": "smallest material evidence condition",
  "next_discriminator": "one bounded observation/test | null"
}
```

## Core invariant

`UNRESOLVED != NO_ACTION`

Epistemic uncertainty does not imply operational paralysis.

The correct commitment may be:

- proceed;
- reject;
- hold;
- run one discriminator;
- no-op.

## Trialectic implementation

`REALITY -> ANGEL <-> DEVIL -> COMMITMENT -> REOPEN`

- REALITY: admissible evidence and epistemic state.
- ANGEL: strongest minimal constructive support for an action now.
- DEVIL: one materially plausible action-changing countermodel.
- COMMITMENT: bounded action now.
- REOPEN: smallest material condition that changes the commitment.

ANGEL/DEVIL are conditional operators, not mandatory persona theatre.

## Relation to adjacent work

EBRC does not claim to invent:

- belief-state/action separation;
- belief or intention revision;
- value-of-information / optimal stopping;
- evidence provenance;
- commitment consistency benchmarks;
- epistemic commitment gating.

The falsifiable candidate contribution is their **joint operational contract** and benchmarkable transition semantics at the decision boundary.

## Kill / narrowing rules

- If Ordinary reproduces EBRC action/witness/reopen behavior at lower cost, collapse the protocol claim.
- If a simpler evidence-trigger contract matches it, collapse to that simpler contract.
- If the DEVIL countermodel step adds no independent value, remove it.
- If gain is only trace quality, narrow to Evidence Trace / Auditability.
- If gain is only reopen stability, narrow to Revisable Commitment.
- If gain is only discriminator quality, narrow to Decision Discriminator.

TRIAXIS is one possible implementation of EBRC, not its oracle.
