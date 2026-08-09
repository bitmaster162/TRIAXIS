# Decision Closure Protocol v0.1

## Purpose

Decision Closure is a compact decision-quality primitive for determining:

1. whether current evidence is sufficient to act;
2. which minimal evidence set actually supports the action;
3. what material fact would flip the decision;
4. which unresolved observation has the highest decision value;
5. when additional analysis should stop.

It is not a persona/debate framework and does not assume that more reasoning is better.

## Canonical state

```json
{
  "status": "ENOUGH | NOT_ENOUGH",
  "action": "bounded action | null",
  "minimal_witness": ["O2", "O7"],
  "flip_condition": "specific material fact that would change the action",
  "next_discriminator": "single bounded observation/test | null",
  "stop": true
}
```

## Algorithm

### 1. Bind one decision
Define one bounded decision and admissible actions. Do not expand scope.

### 2. Bind evidence
For decision-relevant observations, bind provenance, currentness, authority/scope, and instrument validity where needed. Labels, filenames, PASS markers and provider names do not prove stronger properties by themselves.

### 3. Sufficiency gate
`ENOUGH` when at least one minimal sufficient witness set establishes a bounded action under the decision rule.

`NOT_ENOUGH` when two or more materially plausible states remain that imply different actions.

Do not use model confidence as the sufficiency test.

### 4. Minimal witness
Return the smallest evidence set sufficient to reconstruct the action. A witness is invalid if it omits a dependency whose absence breaks the inference or if it relies on rhetoric, stale context, unbound provenance, or invalid instrumentation.

### 5. Flip condition
State the smallest material fact or evidence condition that would change the selected action. It must be observable/falsifiable in principle, decision-relevant, and action-changing rather than merely confidence-changing.

### 6. Discriminator
If `NOT_ENOUGH`, choose one feasible observation/test that best separates the remaining action-relevant models. Prefer direct observation, independent measurement, single-variable intervention, and lower cost when discriminating power is equivalent.

### 7. Stop
`stop=true` when the action is closed and remaining feasible evidence cannot change it, or no feasible observation has positive decision value within scope.

`stop=false` only when a concrete unresolved discriminator can still change the action.

## Falsification

Collapse or narrow the protocol if Ordinary or a simpler direct-test baseline matches it at lower cost, if it creates unnecessary HOLD states, if flip conditions are generic rationalizations, or if discriminator selection fails to beat simpler baselines.