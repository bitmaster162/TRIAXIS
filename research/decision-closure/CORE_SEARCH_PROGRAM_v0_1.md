# Core Search Program v0.1

## Objective

Find the **smallest mechanism set** that reproduces any external lift.

Do not rank historical versions by complexity.
Run cumulative ablations and localize the first useful mutation.

## Arms

### K0 DIRECT
No special scaffold.

### K1 EVIDENCE
Add:
- separate supplied facts from assumptions;
- no invented missing facts;
- minimal load-bearing evidence.

Historical source: v2.3.

### K2 ORIGIN
K1 plus:
- common-upstream / correlated-evidence check;
- independence is a property of evidence origin, not count.

Historical source: v2.5.

### K3 CONTEXT
K2 plus:
- exact input contract;
- controlling instruction vs quoted/external data;
- provenance of material fields;
- stable dependency/context scope.

Historical source: v2.8-v2.10.

### K4 COMMITMENT
K3 plus:
- separate epistemic state from operational closure;
- choose bounded action now;
- explicit reopen boundary.

Source: EBRC / Dual-State.

### K5 VERIFY
K4 plus:
- one decision-changing discriminator/tool/verifier;
- bounded correction;
- zero-VOI stop.

Sources: v3.0 Decision Assurance + WMX.

### K6 TRIALECTIC
K5 plus:
- ANGEL = constructive sufficient support;
- DEVIL = one materially plausible action-changing countermodel;
- no repeated debate.

Source: original TRIAXIS, reinterpreted through Trialectic Closure.

## Benchmark routing

No single benchmark can identify every component.

| Benchmark | Main component stress |
|---|---|
| UMWP / AbstentionBench | K4 epistemic resolution / abstention |
| NeuroState-Bench | K3 context/state + K4 commitment integrity |
| CorrectBench | K5 external verifier / correction |
| InterveneBench / STRIDES | K5 discriminator + K6 countermodel |
| LUMINA | K3 compact state/history + K5 tool/orchestrator |
| Boundary/DI/DS internal controls | witness, reopen, semantic contract diagnostics |

## Primary causal questions

1. Does K1 beat K0?
2. Does K2 add anything over K1?
3. Does K3 prevent context/provenance failures that K2 misses?
4. Does K4 specifically reduce over-answer / semantic conflation?
5. Does K5 rescue wrong outputs using external evidence?
6. Does K6 add value **after** K5, or is adversarial reasoning redundant once a verifier exists?

## Kill rules

- If `K1 ≈ K0`, evidence prompting alone is not a product.
- If `K2 ≈ K1`, origin analysis should be conditional only.
- If `K3 ≈ K2` except on contaminated contexts, scope it to ingestion-heavy tasks.
- If `K4 ≈ K3`, EBRC's dual-state semantics are not independently useful.
- If `K5 >> K4`, weak-model value is primarily external verification.
- If `K6 ≈ K5`, DEVIL/ANGEL remain conceptual aids, not required runtime.
- If `K6 < K5`, Trialectic overhead is harmful and should be removed from default execution.

## Grail criterion

A candidate "grail" must satisfy all:

1. material lift on at least two external benchmark families;
2. no material action-accuracy harm;
3. lower or comparable cost to the full historical stack;
4. clear mechanism-level attribution from these ablations;
5. robustness on at least one genuinely weak model;
6. no dependence on a benchmark oracle owned by TRIAXIS.
