# TRIAXIS Control Stack v3.2-RC1 — Operational Assurance Core

## Status

- Specification: Release Candidate.
- Implementation: partial, executable reference core.
- Production-qualified: no.
- External execution permission: not implied.
- `can_trade=false`, `capital_permission=DENY`, `deploy_permission=DENY`.

## Research trigger

The three attached research reports converged on the following conclusions:

1. Prompt-role diversity is not statistical or functional independence.
2. The strongest TRIAXIS property is the separation between probabilistic reasoning and deterministic authorization.
3. A textual FALSIFIER is weaker than an executable, symbolic or authoritative verifier.
4. Evidence requires subject binding, freshness, provenance and correlation analysis.
5. The execution boundary requires least privilege, state binding, expiry, single-use authorization and durable receipts.
6. Full TRIAXIS must survive equal-budget ablation against a smaller `Proposer + external verifier + deterministic gate` baseline.

The reports do not establish scientific or patent novelty. v3.2 therefore implements an engineering assurance core and an explicit falsification benchmark, not a novelty claim.

## Architecture

```text
INTAKE / AUTHORITY ENVELOPE
        |
        v
RISK-ADAPTIVE ASSURANCE ROUTER
        |
        +--> PRIMARY
        +--> optional SELF_AUDIT
        +--> blind DEVIL when material
        +--> ANGEL only for measured over-refusal risk
        +--> independent FALSIFIER / external verifier
        +--> independent reviewer for R3/R4
        |
        v
DECISION ASSURANCE CASE
        |
        v
EVIDENCE BROKER
        |
        +--> subject binding
        +--> freshness
        +--> source correlation
        +--> authoritative-adapter requirement
        +--> contradictions
        |
        v
SYNTHESIS (NO EXECUTION AUTHORITY)
        |
        v
POLICY LIFECYCLE / POLICY-AS-CODE
        |
        v
ACTION ASSURANCE ENVELOPE
        |
        +--> exact decision/evidence digests
        +--> subject/object/capability/tool/target
        +--> payload digest
        +--> policy sequence
        +--> authenticated state witness
        +--> approvals
        +--> risk / nonce / expiry
        |
        v
SINGLE-USE AUTHORIZATION TOKEN
        |
        v
EXECUTION LEDGER AT RESOURCE BOUNDARY
        |
        +--> PREPARED
        +--> COMPLETED
        +--> UNKNOWN
        +--> RECONCILED_COMPLETE / RECONCILED_DENY
```

## Implemented modules

### `evidence_broker.py`

- sealed evidence packages;
- source and claim identity;
- subject binding;
- source type and attestation level;
- freshness and future-date detection;
- duplicate-content and common-upstream correlation;
- support/contradiction adjudication;
- authoritative-adapter requirement for security-critical facts;
- `PASS`, `ESCALATE`, or structural `BLOCK`.

The broker verifies provenance structure and independence requirements. It does not prove semantic truth.

### `policy_lifecycle.py`

- `DRAFT`, `SHADOW`, `ACTIVE`, `DEPRECATED`, `REVOKED`;
- strict sequence monotonicity;
- exact supersession digest;
- minimum accepted sequence floor;
- temporal validity;
- deterministic capability/tool/target/risk/approval predicates;
- replay-stable decision trace.

Natural-language policy interpretation cannot activate a policy or issue an allow decision.

### `assurance_router.py`

- minimum plan selected from risk, ambiguity, irreversibility and side effects;
- full council is not the default;
- DEVIL and ANGEL may be disabled by empirical role-performance evidence;
- ANGEL is included only where false-denial/opportunity cost is material;
- R3/R4 require independent review;
- irreversible or R4 actions require human approval and recovery controls;
- reasoning plane never owns write credentials.

### `action_assurance.py`

- exact action scope digest;
- decision/evidence digest binding;
- subject/object binding;
- policy and state binding;
- scoped approvals;
- independent trust-domain threshold for R3/R4;
- mandatory HUMAN approval for R4;
- sealed single-use token;
- SQLite WAL/FULL ledger;
- nonce replay conflict detection;
- exact retry idempotency;
- explicit unknown-outcome reconciliation.

### `fail_bench.py`

Benchmark vectors:

- CBSI — correlated blind-spot injection;
- SSP — semantic substitution payload;
- ADC — adversarial debate collusion / objection flooding;
- LTSD — latency-to-safety degradation;
- blind review;
- source correlation;
- stale state;
- replay/rollback;
- policy ambiguity;
- irreversible action.

Compared variants include single-model, self-critique, same-model roles, heterogeneous roles, minimum viable baseline, full TRIAXIS and ablations.

## Formal invariants enforced or represented

1. Non-self-authorization.
2. Authority monotonicity.
3. Complete mediation is an integration requirement.
4. Payload binding.
5. State binding.
6. Temporal validity.
7. Single-use authorization.
8. Policy freshness and rollback resistance.
9. Evidence provenance and subject binding.
10. Defeater preservation in the Decision Assurance Case.
11. No implicit approval.
12. Fail-closed ambiguity.
13. Reversibility alignment.
14. Evidence does not expand authority.
15. Durable side-effect state/receipt.
16. Separation of credentials.
17. Independent approval threshold.
18. Deterministic policy replay.
19. Version traceability.
20. UNKNOWN is not SAFE.

## Known boundaries

- Model/provider identity is declared metadata unless an external identity adapter attests it.
- Evidence content hashes do not prove semantic truth.
- Policy records are digest-sealed but not yet signed by KMS/PKI in this reference package.
- The execution ledger does not itself intercept tools; it must be deployed at the real API/resource boundary.
- Multi-host consensus, distributed fencing, trusted external time and hostile-admin resistance remain unimplemented.
- No empirical claim is made that the full role system outperforms the minimum viable baseline.
