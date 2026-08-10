# ToolBench-X External Targets v0.1

## Source-derived benchmark facts

ToolBench-X v2 reports 1,106 tasks spanning sequential, parallel and mixture workflows, with five hazard families: Specification Drift, Invocation Error, Execution Failure, Output Drift and Cross-Source Conflict.

The paper's 200-task diagnostic subset compares four settings:

- Baseline: exception-injected tools;
- Test-time scaling: +10 extra recovery rounds without hazard information;
- Hint: brief targeted anomaly information;
- Oracle: clean non-exception environment.

Across the five models in Figure 4, Hint improves Baseline by roughly 25.5-35.5 absolute points and recovers about 60-80% of the Baseline-to-Oracle gap. Test-time scaling improves far less; the paper attributes the dominant bottleneck to hazard diagnosis rather than raw inference budget.

The full-benchmark table also shows no model above 0.60 overall; GPT-5.4 is reported at 0.453 overall. Invocation, Execution and Cross-Source hazards are among the harder classes, while Output is materially easier.

## AVR X2 target

AVR X2 is deliberately weaker than the paper's Hint arm: it does **not** receive the hazard label or prescribed recovery guidance. It must infer the hazard from runtime evidence.

Frozen survival criteria before native results:

1. X2 exact-match improvement over X0 >= +5 pp.
2. X2 recovers >=25% of X1/Hint positive-control gain.
3. Regressions <=25% of newly recovered tasks.
4. No material tool-call budget inflation.

Interpretation bands:

- `< +5 pp`: AVR native hypothesis fails this gate.
- `+5 to +10 pp`: weak but real diagnosis signal; keep research-only.
- `+10 to +20 pp`: material native support for hazard-aware control.
- `> +20 pp` with low regressions/cost: strong support; require independent replication before promotion.
- Approaching the Hint arm without labels would be the strongest result, but is **not preregistered as necessary**.

## Claim boundary

No native AVR X2 result exists yet. These thresholds are prospective and must not be edited after first native X2 scoring without versioning the trigger/criteria.
