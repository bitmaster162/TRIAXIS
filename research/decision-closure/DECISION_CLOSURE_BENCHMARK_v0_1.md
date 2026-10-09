# Decision Closure Benchmark v0.1

Status: Design freeze candidate
Date: 2026-08-09

## Research question

Does a structured closure protocol improve any of the following compared with ordinary reasoning?

1. decision correctness;
2. evidence sufficiency classification;
3. minimal sufficient witness selection;
4. flip-boundary correctness;
5. discriminator selection;
6. stop/continue correctness;
7. provenance/traceability/auditability.

## Benchmark object

Each case supplies:
- one bounded decision;
- candidate actions;
- evidence observations with opaque IDs;
- optional candidate tests with cost;
- hidden oracle metadata.

The solver returns:

```json
{
  "case_id": "DC001",
  "status": "ENOUGH",
  "action_choice": "B",
  "minimal_witness": ["O2", "O7"],
  "flip_condition": "A fresh authenticated readback shows revision 19 is serving.",
  "next_discriminator": null,
  "stop": true
}
```

## Orthogonal test axes

### A. Sufficiency
Two states may support the same narrative, but only one has enough evidence to act.

Score:
- ENOUGH / NOT_ENOUGH accuracy
- false-closure rate
- unnecessary-HOLD rate

### B. Witness
Multiple evidence sets may be valid. The oracle therefore stores **acceptable minimal sufficient witness sets**, not one exact mandatory set.

Score:
- witness sufficiency
- minimality/redundancy
- forbidden-evidence reliance

### C. Flip boundary
The model declares what smallest material observation would change the action.

The evaluator injects:
- the true flip fact;
- a stronger-sounding irrelevant fact;
- stale/correlated evidence;
- rhetorical pressure.

Score:
- true-flip response
- non-material invariance
- boundary precision

### D. Discriminator
When `NOT_ENOUGH`, the model chooses among candidate tests.

Cases vary:
- discriminating power;
- instrument validity;
- cost;
- reversibility;
- compound vs single-variable interventions.

Score:
- discriminator correctness
- cost-adjusted discriminator regret

### E. Stop
Cases distinguish:
- zero-VOI continuation;
- premature stop;
- bounded remaining evidence with positive VOI.

Score:
- stop accuracy
- wasted-test rate
- missed-decision-changing-test rate

### F. Provenance / auditability
Evidence may have:
- valid cryptographic/session binding;
- editable labels only;
- stale authority;
- correlated origins;
- invalid measurement scope.

Score:
- provenance integrity
- replay consistency
- trace completeness

## Primary aggregate

Do not collapse everything into one number by default.

Report a vector:

`[DECISION, SUFFICIENCY, WITNESS, FLIP, DISCRIMINATOR, STOP, AUDIT]`

A protocol only earns a broad "decision closure lift" claim if it improves at least two closure dimensions without materially harming decision accuracy.

## Baselines

- Ordinary
- RTD / direct-test
- Generic strongest-counterexample
- Structured Decision Closure
- Debate control

## Kill rules

- If Ordinary matches Structured within 2 pp on all closure dimensions at lower cost: collapse.
- If RTD matches Structured within 2 pp on all closure dimensions at lower cost: collapse to RTD.
- If gain is only witness/audit quality: narrow product claim to Decision Trace / Auditability.
- If gain is only discriminator selection: narrow product claim to Decision Discriminator.
- If gain is only STOP/VOI: narrow product claim to Decision Frontier / Cost Control.
- If structured prompting reduces action accuracy by >=3 pp: capability-floor warning.
