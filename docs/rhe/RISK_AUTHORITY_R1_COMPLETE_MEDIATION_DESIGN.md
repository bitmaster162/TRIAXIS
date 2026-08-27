# TRIAXIS RHE Risk Authority R1 — Complete Mediation Design

Status: **DESIGN + TEST ONLY / NOT RUNTIME-WIRED**  
Owner gate consumed for this bounded stacked branch/PR only:

`APPROVE_TRIAXIS_RHE_RISK_AUTHORITY_R1_COMPLETE_MEDIATION_DESIGN_AND_TEST_PR:153372ee58552cffc5143690e3d976b366c8d780:28b2488a0fd4866bab346276d51e2e1eb40c928c:NO_MERGE:NO_DEPLOY:NO_EFFECTS`

## Authority binding

Fresh authority inputs at gate consumption:

- `main` commit: `153372ee58552cffc5143690e3d976b366c8d780`
- `main` tree: `749178828fd910cde7cefd26ce643b7c74c4a811`
- Risk Authority PR #20 head: `28b2488a0fd4866bab346276d51e2e1eb40c928c`
- PR #20 state at consumption: OPEN + DRAFT + UNMERGED

This design branch is stacked from the exact PR #20 head. It does not replace, rewrite, merge, or abandon PR #20.

## Problem

PR #20 proves a deterministic anti-downgrade classifier:

`trusted consequence facts -> minimum R0-R4 risk`

It intentionally does not prove repository-wide complete mediation. A caller can still invoke the existing authorization entry point without first invoking Risk Authority.

The design in this branch defines the narrow boundary that must sit in front of the existing authorization stack before any future effect-capable runtime integration is accepted.

## Required flow

```text
exact action/effect subject
    -> trusted bounded risk-fact adapter
    -> Risk Authority R1 assess_risk
    -> existing TRIAXIS authorizer
    -> existing PEP / Cedar PDP where configured
    -> sealed authorization token
    -> verify exact effect + effective-risk binding
    -> sealed risk-mediation receipt bound to token SHA-256
```

There is no second PDP. Cedar/PEP remains the authorization authority.

## Component added by this branch

`src/triaxis/risk_mediation.py` adds an inert `RiskMediatedAuthorizationBoundary` with these properties:

1. **Trusted adapter provenance** — risk facts are accepted only from one exact configured adapter id, version and in-process object instance held by an immutable trust registry.
2. **Exact risk subject** — the adapter observation is bound to subject, object, capability, tool, execution target, payload digest and authenticated state-witness digest.
3. **Caller risk independence** — `risk_class` is deliberately excluded from the risk-subject digest, so caller risk metadata cannot change which consequence facts are observed.
4. **Mutation containment** — the adapter and authorizer receive detached materialized copies; a mutating adapter cannot alter the action subsequently authorized.
5. **Anti-downgrade** — Risk Authority rejects caller risk below the trusted derived minimum before the existing authorizer is called.
6. **Existing authorization preserved** — the boundary delegates to an injected existing authorizer rather than implementing authorization or policy evaluation itself.
7. **Token integrity** — returned authorization must carry a valid canonical `token_sha256` seal.
8. **Effect binding** — the returned token must bind the same subject/object/capability/tool/target/payload/state-witness risk subject that was classified.
9. **Risk binding** — token `risk_class` must equal the mediated effective risk.
10. **Audit chain** — the mediation receipt binds adapter identity/version, exact risk subject, trusted effect facts, derived/effective risk and the authorization token SHA-256.

Any mismatch fails closed with a deterministic mediation error.

## What this branch proves

The tests prove the mediation component blocks:

- caller downgrade;
- R4 critical-domain downgrade;
- untrusted same-id/version adapter substitution;
- stale/cross-action observations;
- adapter mutation of the action copy;
- adapter failure or malformed observation;
- authorization token effect substitution;
- authorization token risk substitution;
- missing token digest;
- tool/target/payload/state-witness substitution.

They also prove caller over-classification remains allowed and the risk claim itself does not drive adapter fact selection.

## What this branch does NOT prove

This branch does **not** claim repository-wide complete mediation yet.

Specifically it does not:

- modify `action_assurance.authorize_action`;
- replace direct authorization call sites;
- wire this boundary into `AuthenticatedTrustedWorkloadExecutionBoundary`;
- change PREPARED ledger semantics;
- bind the mediation receipt into the production execution ledger;
- change Cedar policy or R3/R4 approval semantics;
- invoke any provider or external target;
- perform AWS/IAM/Secrets/S3/TSA writes;
- deploy anything;
- execute a model;
- enable trading or capital actions.

A direct caller can still bypass this component until a future separately reviewed runtime-integration gate changes the effect-capable entry path. Therefore the correct implementation status after this PR is:

`COMPLETE_MEDIATION_COMPONENT_DESIGNED_AND_TESTED__RUNTIME_BINDING_NOT_IMPLEMENTED`

## Residual architecture questions

### Cedar R4 control floor

The current reference Cedar policy does not itself encode the legacy R4 HUMAN approval floor. A future runtime integration must prove that authoritative R4 cannot produce an effect-capable ALLOW without the intended R4 control floor. Merely passing the string `R4` into Cedar is insufficient evidence.

### Deployment classification

PR #20 does not add `DEPLOYMENT` as a `CriticalDomain`. This branch does not silently change classifier semantics. Whether production deployment becomes an explicit R4 domain remains a separate reviewed classifier decision.

### Adapter trust across process boundaries

The registry here is an in-process exact-instance trust binding. If risk facts are ever produced across a process or network boundary, object identity is not sufficient and authenticated/cryptographically bound provenance will be required.

### Ledger binding

The new receipt binds the mediation result to the authorization token digest, but the existing execution ledger does not yet require or persist this receipt. A future runtime-integration PR must close that gap before repository-wide complete mediation can be claimed.

## Frozen scope

Under this consumed gate:

- `NO_MERGE`
- `NO_DEPLOY`
- `NO_EFFECTS`
- `NO_AWS`
- `NO_PROVIDER_INVOCATION`
- `NO_PRODUCTION_LEDGER_MUTATION`
- `NO_MODEL_EXECUTION`
- `NO_TRADING`
- `NO_CAPITAL`

Permanent prior closures remain unchanged:

- `RERUN_R4_1=DENY`
- `RERUN_V036=DENY`
- `REUSE_CONSUMED_APPROVALS=DENY`
- `model_execution_authorized=false`
- `model_execution_performed=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Next gate after independent review

If this stacked design/test PR passes independent review, any repository-wide runtime binding must use a fresh exact owner gate bound to the then-current `main`, PR #20 state/head, and this mediation PR head. That future gate must explicitly name the runtime files/call paths allowed to change and remain `NO_EFFECTS` unless a separately bounded effect lifecycle is also approved.
