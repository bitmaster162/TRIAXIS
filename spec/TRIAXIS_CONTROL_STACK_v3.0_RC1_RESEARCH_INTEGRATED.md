# TRIAXIS Control Stack v3.0-RC1 — Research-Integrated Decision Assurance

## Status

- Specification: Release Candidate
- Implementation: Partially implemented
- Production-qualified: No
- Baseline: TRIAXIS v2.44-RC2 Recovery

## Reframing

TRIAXIS is not defined as a fixed cast of AI personalities. It is a Decision Assurance protocol with replaceable epistemic branches and a non-LLM authority boundary.

```text
INTAKE / AUTHORITY ENVELOPE
  ↓
EPISTEMIC BRANCHES
  ↓
EVIDENCE BROKER
  ↓
ASSURANCE COMPILER
  ↓
FALSIFICATION CONTRACT
  ↓
SYNTHESIS OF THE CASE
  ↓
INDEPENDENT REVIEW WHEN REQUIRED
  ↓
DETERMINISTIC GATE
  ↓
EXECUTION BROKER
  ↓
OUTCOME / CALIBRATION / REGRESSION
```

## Plane A — Intake and authority envelope

Before reasoning, fix:

- authenticated principal and intent;
- permitted goal and forbidden outcomes;
- capability set and tool scope;
- maximum risk class;
- budget and approval constraints.

All later stages may only narrow this envelope.

## Plane B — Epistemic branches

Canonical functions remain PRIMARY, SELF_AUDIT, DEVIL, ANGEL, FALSIFIER and INDEPENDENT_REVIEW, but they are contracts, not persons.

Every branch records provider, model family, context ID, retrieval set, verification mode and claims. Role names do not establish independence.

Independence classes:

- I0: role play only — same model, context and retrieval.
- I1: procedural isolation or partial decoupling.
- I2: heterogeneous review — distinct provider/model and independent retrieval.
- I3: external verifier — deterministic checker, solver, executable test or external observation.

## Plane C — Evidence broker

Evidence records bind:

- evidence ID;
- source correlation group;
- source type and verification mode;
- content SHA-256;
- covered claims;
- freshness and provenance in production implementations.

A load-bearing claim has evidence or is explicitly `UNVERIFIED_ASSUMPTION`.

## Plane D — Assurance compiler

The Decision Assurance Case contains:

- claims and alternatives;
- evidence and assumptions;
- defeaters and mitigations;
- opportunity costs;
- falsification contract;
- synthesis and minimal authority request;
- deterministic gate request.

Defeater states:

- OPEN;
- MITIGATED;
- REBUTTED;
- ACCEPTED;
- RESOLVED.

An OPEN or ACCEPTED `DECISION_BLOCKING` defeater requires escalation and cannot be erased by synthesis prose.

## Plane E — Falsification contract

For A2/A3 the contract requires:

- hypothesis;
- competing hypothesis;
- observable variable;
- measurement;
- threshold;
- time window;
- decision-update rule.

Missing fields are a decorative falsifier and block assurance closure.

## Plane F — Synthesis

Synthesis compares alternatives, preserves minority defeaters and emits a minimal authority request. It cannot set `permission_status`, issue a gate outcome or expand capabilities/risk beyond Intake.

## Plane G — Review requirements

- R3/R4: heterogeneous independent review (I2 or I3).
- R4: explicit human approval.
- A3: verifier with a distinct failure mode (I3).

These are protocol defaults; project policy may add stronger controls but may not silently weaken them.

## Plane H — Deterministic gate and execution

The generative case creates a gate request, not a decision token. A production gate must validate policy version, exact payload digest, exact target, state snapshot, nonce, expiry, approvals and resource-bound authorization.

The execution broker is the only write-capable component and must re-read state, consume single-use authorization, execute, record a durable receipt and reconcile unknown outcomes.

## Plane I — Learning

Store, by task class and version:

- true and false defects found by each branch;
- calibration;
- unsafe actions and over-refusals;
- escalation quality;
- latency/cost;
- outcome versus decision quality;
- regression cases generated from incidents.

A role remains mandatory only if an ablation test demonstrates material net value.

## Formal invariants

1. Non-self-authorization.
2. Authority monotonicity.
3. Complete mediation for external side effects.
4. Exact payload and state binding.
5. Temporal validity and single-use authorization.
6. Evidence provenance or honest assumption state.
7. Defeater preservation.
8. No implicit approval.
9. Honest uncertainty: UNKNOWN is not SAFE.
10. Separation of credentials: reasoning branches do not hold write credentials.
11. Version traceability.
12. Identical authoritative inputs yield identical deterministic gate outcomes.
13. Role labels never count as independent evidence.
14. High-risk closure requires a distinct failure mode.
15. No universal risk threshold without task-specific calibration evidence.

## Product direction

Initial surfaces:

1. AI-Agent Reliability Audit.
2. Research Assurance and multi-model adjudication.
3. Decision Assurance Engine.
4. Runtime Execution Firewall after live-tool validation.

## Explicit limitations

This release validates structure, provenance references, independence metadata, defeater semantics, falsification completeness and authority monotonicity. It does not validate the truth of natural-language claims, provide production identity/KMS, perform complete mediation, or prove that multiple branches outperform a simpler baseline.
