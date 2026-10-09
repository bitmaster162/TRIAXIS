# Evidence Provenance, Traceability & Decision Auditability v0.1

Status: Research candidate
Date: 2026-08-09

## Hypothesis

The value of a structured decision protocol may not be higher final-answer accuracy. It may be better **decision trace quality**: a third party can identify which evidence was sufficient, where it came from, what would have changed the decision, and why further investigation stopped.

This layer must be evaluated independently of answer correctness.

## Three distinct properties

### Provenance
Can each decision-relevant observation be tied to an origin with the authority, scope, timestamp/currentness, and measurement conditions needed for the claim?

Provenance is not:
- an editable provider label;
- a filename;
- a human-entered PASS marker;
- a free-text assertion of independence.

### Traceability
Can the final action be mapped back to a bounded witness set and decision rule?

Minimum trace:
`action -> witness IDs -> evidence records -> scope/authority conditions`.

### Auditability
Can an independent evaluator replay the decision from the frozen evidence and obtain the same action without access to hidden model reasoning?

Auditability is an external property of the decision record, not a claim that a chain-of-thought explanation is faithful.

## Candidate metrics

### 1. Witness Sufficiency Accuracy (WSA)
Fraction of decisions whose selected evidence contains at least one acceptable minimal sufficient witness set.

### 2. Witness Minimality / Redundancy
For a correct sufficient trace:

`redundancy = selected_evidence_count / minimal_sufficient_count`

Lower is better, but never at the cost of sufficiency.

### 3. Forbidden-Evidence Reliance (FER)
Fraction of cases where the trace cites rhetoric, stale context, unbound labels, or known-invalid instrumentation as a decision basis.

### 4. Provenance Integrity Accuracy (PIA)
Fraction of provenance claims whose required origin/session/authority bindings are actually present.

### 5. Replay Consistency (RC)
Fraction of cases where an independent deterministic replay from the cited evidence reproduces the action.

### 6. Counterfactual Boundary Precision (CBP)
Fraction of declared flip conditions that actually cause the oracle action to flip under controlled injection.

### 7. Decision Trace Compression (DTC)
How compactly a system represents a sufficient decision trace:

`DTC = minimal_sufficient_count / selected_evidence_count`

Maximum 1.0.

## Current empirical signal

Boundary-20 produced:
- U0 Ordinary action accuracy: 20/20
- U1 Structured action accuracy: 20/20
- action lift: 0 pp
- after symmetric oracle quarantine, evidence binding:
  - U0: 14/16 = 87.5%
  - U1: 16/16 = 100%
  - delta: +12.5 pp
- U1 action harms: 0

Interpretation: candidate evidence-discipline improvement, not demonstrated decision-accuracy improvement.

## Required caution

Self-reported rationales are not treated as ground-truth internal reasoning. The benchmark scores externally checkable evidence references and replayable decision records.
