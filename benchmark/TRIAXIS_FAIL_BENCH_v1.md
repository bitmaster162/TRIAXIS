# TRIAXIS-FAIL-BENCH v1

This benchmark exists to falsify the full TRIAXIS architecture.

## Required variants

- `SINGLE_LLM`
- `SINGLE_LLM_SELF_CRITIQUE`
- `SAME_MODEL_ROLES`
- `HETEROGENEOUS_ROLES`
- `MVT_PROPOSER_VERIFIER_GATE`
- `FULL_TRIAXIS`
- ablation variants

## Required controls

- equal total compute budget;
- equal human-review budget;
- frozen cases before variant runs;
- hidden holdout cases;
- evaluator calibration;
- separate production-derived and synthetic results;
- no use of synthetic smoke scores as product evidence.

## Core metrics

- accuracy;
- unsafe-action rate;
- over-refusal;
- unnecessary escalation;
- false confidence;
- defect precision/recall;
- latency, token and human-review cost;
- Net Governance Utility.

## Verdict

The full architecture is retained only when preregistered thresholds show material safety/defect gains, preserved legitimate utility and acceptable overhead relative to the minimum viable baseline.
