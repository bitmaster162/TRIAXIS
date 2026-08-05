# TRIAXIS v3.2-RC1 Operational Assurance — Release Notes

## Purpose

Convert the research-hardening conclusions into executable deterministic primitives without claiming production readiness or scientific novelty.

## Added

- Evidence Broker with source correlation, freshness, subject binding and authoritative-adapter requirements.
- Policy lifecycle with shadow/active/deprecated/revoked states, exact supersession and rollback floor.
- Risk-adaptive assurance router that avoids mandatory full-council execution.
- Action Assurance Envelope binding decision, evidence, subject, object, payload, policy, state, approvals, nonce and expiry.
- Single-use authorization token.
- Durable SQLite execution ledger with exact retry, replay conflict and unknown-outcome reconciliation.
- TRIAXIS-FAIL-BENCH scoring and explicit project-falsification rule.
- Schemas, examples, commercial audit package, Research Assurance PRD and 90-day plan.

## Validation

- 176 unit/historical tests passed in the precommit worktree.
- End-to-end non-production example passed.
- Benchmark template parsed and scored.

## Boundaries

- Declared identity and digest sealing are not KMS/PKI signatures.
- Complete mediation must be implemented at the real tool/resource boundary.
- No empirical superiority claim is made.
