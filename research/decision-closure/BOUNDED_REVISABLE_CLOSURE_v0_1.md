# Bounded Revisable Closure v0.1

## Core correction

A decision does not need to be immutable to be closed.

**Bounded Revisable Closure** means:

> Current evidence is sufficient to choose the correct bounded action now, while explicitly recording the material condition under which that commitment must be reopened.

This separates two questions that FC16 accidentally conflated:

1. **Epistemic resolution** — do we know the underlying world state?
2. **Operational closure** — do we know what bounded action to take now?

Examples:

- We may not know whether a timed-out mutation succeeded, but we can still close the immediate action: **do not retry; query the authoritative scope**.
- We may not know the current serving revision, but we can close: **do not assert a revision; obtain one fresh post-route readback**.
- We may know enough to reject a bounded claim even though a positive proof is absent: if Run B consumed Run A's reasoning, the specific independence claim is falsified for the current frozen scope.

## Canonical decision record

```json
{
  "epistemic_status": "RESOLVED | UNRESOLVED",
  "closure_status": "CLOSED | OPEN",
  "commitment_class": "PROCEED | REJECT | HOLD | TEST | NOOP",
  "action": "bounded action now",
  "minimal_witness": ["O1", "O4"],
  "surviving_countermodel": "one action-changing alternative | null",
  "reopen_trigger": "smallest future fact that requires reconsideration | null",
  "next_discriminator": "one bounded test | null",
  "stop_current_cycle": true
}
```

## Trialectic interpretation

REALITY establishes the admissible evidence.

ANGEL asks: **What bounded action is constructively supported now?**

DEVIL asks: **What one materially plausible state would force a different action?**

The third pole is not a synthesizer persona. It is **COMMITMENT**:

**Given current evidence, counterfactual fragility, and reversibility, what do we do now — and exactly when must we reopen?**

```text
                REALITY
                   |
          +--------+--------+
          |                 |
       ANGEL              DEVIL
   sufficient case    flip/countermodel
          |                 |
          +--------+--------+
                   |
              COMMITMENT
                   |
          action + reopen rule
```

## Closure classes

### TERMINAL_CLOSED
Within the **current frozen scope**, the bounded action/claim is closed and no unresolved in-scope discriminator is required. This does **not** mean metaphysical or permanent irreversibility: genuinely new contradictory evidence or a later scope change can start a new decision episode.

### PROVISIONAL_CLOSED
The immediate action is justified now, but a named material observation is expected or plausible and would reopen/change the decision.

### INVESTIGATIVE_CLOSED
The correct immediate action is a specific test/observation. The underlying world state is unresolved, but the next operational decision is closed.

### OPEN
The system cannot even identify a justified bounded next action from the admissible action surface and current evidence. This should be rare and must not be used as a generic uncertainty bucket.

## Why this may be the stronger primitive

It avoids both failure modes:

- **premature certainty**: acting as though revisable evidence were final;
- **permanent hesitation**: refusing to act whenever some uncertainty remains.

The target is neither certainty nor skepticism.

The target is **revisable commitment with a precise evidence boundary**.
