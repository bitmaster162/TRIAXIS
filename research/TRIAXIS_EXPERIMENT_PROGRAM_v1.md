# TRIAXIS Experiment Program v1

## Core comparison

Run every case under equal total compute and equal human-review budget:

1. Single strong LLM.
2. Single LLM + self-critique.
3. Same model × named roles.
4. Heterogeneous models × isolated roles.
5. Minimum viable system: Proposer + external verifier + deterministic gate.
6. Full TRIAXIS.
7. Full TRIAXIS without independent evidence.
8. Full TRIAXIS without FALSIFIER.
9. Full TRIAXIS without ANGEL.
10. Full TRIAXIS without deterministic gate.

## First 20 experiments

1. Correlated Blind-Spot Injection.
2. Semantic Substitution Payload.
3. Adversarial Debater Collusion / objection flooding.
4. Latency-to-Safety Degradation.
5. Blind review versus full-context review.
6. Independent retrieval versus shared RAG.
7. Duplicate URL versus common-upstream source detection.
8. Executable verifier versus textual FALSIFIER.
9. DEVIL precision/recall on seeded defects.
10. ANGEL on benign refusals and hidden harmful intent.
11. Synthesizer minority-defeater preservation.
12. Citation-to-claim entailment.
13. Stale evidence and future-dated evidence.
14. Stale policy, approval and state witness.
15. Payload, object and tenant substitution.
16. Nonce replay and exact retry.
17. Timeout after possible side effect.
18. Policy rollback and emergency revocation.
19. Human escalation quality and review time.
20. Role/model routing cost versus Net Governance Utility.

## Project falsification condition

Simplify or reject the full role architecture if it does not materially outperform the minimum viable baseline on all three dimensions:

- unsafe-action reduction;
- true defect discovery;
- preserved legitimate utility;

while remaining inside an explicit latency, cost and human-review budget.

The numeric thresholds must be preregistered for each domain. Numbers from research prose are hypotheses, not universal constants.
