# Evidence Provenance, Traceability & Decision Auditability v0.1

## Hypothesis

The value of a structured decision protocol may not be higher final-answer accuracy. It may be better **decision trace quality**: a third party can identify which evidence was sufficient, where it came from, what would have changed the decision, and why further investigation stopped.

This layer is evaluated independently of answer correctness.

## Provenance
Can each decision-relevant observation be tied to an origin with the authority, scope, timestamp/currentness, and measurement conditions required for the claim?

Provenance is not an editable provider label, filename, PASS marker, or unsupported free-text assertion of independence.

## Traceability
Can the final action be mapped back to a bounded witness set and decision rule?

Minimum trace:

`action -> witness IDs -> evidence records -> scope/authority conditions`

## Auditability
Can an independent evaluator replay the decision from frozen evidence and obtain the same action without hidden model reasoning?

Auditability is an external property of the decision record, not a claim that chain-of-thought is faithful.

## Candidate metrics

- **Witness Sufficiency Accuracy (WSA)** — selected evidence contains at least one acceptable sufficient witness set.
- **Witness Redundancy** — `selected_evidence_count / minimal_sufficient_count`; lower is better after sufficiency is satisfied.
- **Forbidden-Evidence Reliance (FER)** — cites rhetoric, stale context, unbound labels, or invalid instrumentation as a basis.
- **Provenance Integrity Accuracy (PIA)** — provenance claims have the required origin/session/authority bindings.
- **Replay Consistency (RC)** — deterministic replay from cited evidence reproduces the action.
- **Counterfactual Boundary Precision (CBP)** — declared flip conditions actually flip the oracle action under controlled injection.
- **Decision Trace Compression (DTC)** — `minimal_sufficient_count / selected_evidence_count`, maximum 1.0.

## Current empirical signal

Boundary-20:

- U0 Ordinary action accuracy: 20/20
- U1 Structured action accuracy: 20/20
- action lift: 0 pp
- after symmetric oracle quarantine, evidence binding:
  - U0: 14/16 = 87.5%
  - U1: 16/16 = 100%
  - delta: +12.5 pp
- U1 action harms: 0

Interpretation: **candidate evidence-discipline improvement**, not demonstrated decision-accuracy improvement.

## Caution

Self-reported rationales are not treated as ground-truth internal reasoning. Primary scoring should use externally checkable evidence references, frozen provenance records, counterfactual injections, and replayable decision records.