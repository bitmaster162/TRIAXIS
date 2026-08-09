# Decision Closure / EBD Research

This research branch separates four objects:

1. **Decision Closure Protocol** — compact procedure for sufficiency, witness, flip boundary, discriminator, and stop.
2. **Decision Closure Benchmark** — method-neutral evaluator for those closure dimensions.
3. **Decision Trace / Auditability** — provenance and replayability layer, motivated by the observed +12.5 pp evidence-binding candidate lift with zero action lift on Boundary-20.
4. **Trialectic Closure** — conditional `REALITY → ANGEL → DEVIL → CLOSURE` implementation used to test whether constructive sufficiency plus one action-changing countermodel improves false-closure resistance.

## Current empirical state

- Z8.1 and EBD Pilot40 reached an action ceiling: Ordinary and Structured both perfect on the tested actions.
- Boundary-20: U0 and U1 both 20/20 actions; after symmetric oracle quarantine, evidence binding was U0 14/16 vs U1 16/16 (+12.5 pp), zero action harm.
- GPT-5.6 Sol self-test on Decision Closure-24: U0, U1 and Trialectic U2 all passed the full closure vector, but this is **author-contaminated sanity control only**, not blind evidence.

The current empirical result does **not** support a claim that TRIAXIS improves final decision accuracy. The branch exists to test narrower, falsifiable hypotheses:

- sufficiency detection;
- minimal sufficient witness construction;
- counterfactual / flip-boundary precision;
- cost-aware discriminator selection;
- decision-frontier stopping;
- provenance / traceability / auditability;
- false-closure resistance from conditional ANGEL/DEVIL checks.

`TRIAXIS_IS_CONTESTANT=true`

`TRIAXIS_IS_ORACLE=false`

No production/runtime change is authorized by this research branch.

See:
- `DECISION_CLOSURE_PROTOCOL_v0_1.md`
- `DECISION_CLOSURE_BENCHMARK_v0_1.md`
- `EVIDENCE_TRACEABILITY_AUDITABILITY_v0_1.md`
- `TRIALECTIC_CLOSURE_v0_1.md`
- `SELF_TEST_GPT56SOL_2026-08-09.md`
- `RESEARCH_STATE_2026-08-09.md`
- `DC24_RELEASE_v0_1_1.md`
- `decision_closure_record.schema.json`