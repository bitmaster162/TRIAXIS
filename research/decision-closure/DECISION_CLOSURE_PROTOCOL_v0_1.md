# Decision Closure Protocol v0.1

Status: Research candidate
Date: 2026-08-09

## Purpose

Decision Closure is a compact decision-quality primitive for determining:

1. whether the current evidence is sufficient to act;
2. which minimal evidence set actually supports the action;
3. what concrete fact would flip the decision;
4. which unresolved observation has the highest decision value;
5. when additional analysis should stop.

It is not a persona/debate framework and does not assume that more reasoning is better.

## Canonical output

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

### 1. Bind the decision
Define one bounded decision and its admissible actions. Do not expand scope.

### 2. Bind evidence
For every relevant observation record:
- origin/provenance;
- timestamp/currentness;
- authority/scope;
- measurement/instrument validity where relevant.

Labels, filenames, PASS strings, summaries, and provider names are not evidence of stronger properties unless they are bound to those properties.

### 3. Sufficiency gate
Classify the state:

`ENOUGH` when at least one minimal sufficient witness set establishes a bounded action under the current decision rule.

`NOT_ENOUGH` when two or more materially plausible states remain that imply different actions.

Do not use model confidence as the sufficiency test.

### 4. Minimal witness
Return the smallest available evidence set sufficient to reconstruct the action.

A witness is invalid if:
- removing an omitted dependency changes whether the action follows;
- it relies on irrelevant framing or authority-free labels;
- it assumes provenance, currentness, measurement validity, or scope that is not established.

### 5. Flip condition
State the smallest material fact or evidence condition that would change the selected action.

A valid flip condition must:
- be decision-relevant;
- be falsifiable/observable in principle;
- change the action rather than merely increase confidence;
- not restate the current conclusion.

### 6. Discriminator
If `NOT_ENOUGH`, identify one feasible observation/test that best separates the remaining action-relevant models.

Prefer:
1. direct observation over narrative inference;
2. independent measurement over correlated repetition;
3. single-variable intervention over compound change;
4. lower cost when discriminating power is equivalent.

### 7. Stop rule
Set `stop=true` when either:
- the action is closed and remaining feasible evidence cannot change it; or
- no feasible additional observation has positive decision value within scope.

Set `stop=false` only when a concrete unresolved discriminator can still change the action.

## Non-goals

Decision Closure does not require:
- ANGEL/DEVIL personas;
- majority vote;
- debate theatre;
- multi-pass reasoning by default;
- proprietary identity/security infrastructure.

## Falsification conditions

The protocol should be collapsed or narrowed if:
- ordinary reasoning matches it on closure accuracy and evidence discipline at lower cost;
- a simpler direct-test protocol achieves the same results;
- it increases HOLD/verification behavior without improving downstream correctness;
- flip conditions are generic rationalizations rather than predictive boundaries;
- discriminator selection does not beat cheaper baselines.
