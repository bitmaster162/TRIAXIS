# AI-Agent Reliability Audit — commercial service package

## Outcome

A decision-ready report showing where an AI agent can hallucinate, misuse tools, act with excess authority, rely on stale/correlated evidence, duplicate side effects or bypass approvals.

## Input

- agent architecture and prompts;
- tool/API inventory;
- identity and credential model;
- sample traces;
- policies and approvals;
- incident history;
- test environment.

## Audit lanes

1. **Reasoning and evidence** — claims, sources, contradictions, provenance, calibration.
2. **Agent theatre** — correlated roles, shared context/RAG and false consensus.
3. **Tool and authority** — least privilege, capability scope and bypass routes.
4. **State and time** — stale state, TOCTOU, expiry and rollback.
5. **Side effects** — idempotency, replay, unknown outcomes and compensation.
6. **Release assurance** — adversarial cases, regression suite and readiness gate.

## Deliverables

- executive risk summary;
- threat model;
- architecture map;
- prioritized defect register;
- reproducible adversarial cases;
- Decision Assurance Case for the highest-risk workflow;
- policy/action envelope proposal;
- remediation roadmap;
- retest receipt.

## Packages

### Diagnostic

One workflow, document/code review, up to ten adversarial cases, prioritized report.

### Full Assurance Audit

Up to three workflows, tool/authority review, evidence audit, FAIL-BENCH cases, remediation and one retest.

### Continuous Assurance

Recurring regression, policy drift review, incident-to-test conversion and release gate.

Pricing remains a commercial decision and is deliberately not hard-coded into the protocol.
