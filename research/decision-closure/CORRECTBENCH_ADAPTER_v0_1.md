# CorrectBench compatibility adapter v0.1

The goal is not to replace CorrectBench scoring. It is to expose our methods through its correction-loop concept while preserving its native evaluator.

## Arms

### CB-P0
Use CorrectBench's direct or CoT baseline unchanged.

### CB-P1 — EBRC Correction Gate
After the first candidate:
1. ingest only benchmark-provided critique/verifier/tool feedback;
2. classify whether feedback identifies a material defect that can change the judged result;
3. if no material defect: STOP and retain candidate;
4. if material defect: make one bounded correction;
5. rerun the same native verifier/evaluator.

### CB-P2 — Trialectic EBRC
Before correction:
- ANGEL: minimal case that candidate is valid;
- DEVIL: one concrete failure/counterexample consistent with available feedback;
- if DEVIL has no grounded defect, stop;
- otherwise correct the named defect and rerun native verifier.

### CB-P3 — WMX External
Prefer externally executable feedback whenever the task supplies it:
compiler/testbench/calculator/search/program execution/etc.
The external result is evidence; model self-critique is not promoted to oracle status.

## Metrics to retain from CorrectBench
- native accuracy/pass metric
- number of correction rounds
- latency/token cost if available
- correction success conditional on initial failure

Additional diagnostics:
- unnecessary revision rate on initially correct outputs
- verified rescue rate
