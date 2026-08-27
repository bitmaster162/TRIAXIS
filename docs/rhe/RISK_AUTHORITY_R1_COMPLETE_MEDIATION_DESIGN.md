# TRIAXIS RHE Risk Authority R1 — Complete Mediation Design

Status: **DESIGN + TEST ONLY / NOT RUNTIME-WIRED**

Initial owner gate consumed for the bounded stacked design/test PR:

`APPROVE_TRIAXIS_RHE_RISK_AUTHORITY_R1_COMPLETE_MEDIATION_DESIGN_AND_TEST_PR:153372ee58552cffc5143690e3d976b366c8d780:28b2488a0fd4866bab346276d51e2e1eb40c928c:NO_MERGE:NO_DEPLOY:NO_EFFECTS`

Adversarial-review fix gate consumed for the two reproduced PR #21 blockers only:

`APPROVE_TRIAXIS_RHE_RISK_AUTHORITY_R1_COMPLETE_MEDIATION_PR21_FIX_R1:153372ee58552cffc5143690e3d976b366c8d780:28b2488a0fd4866bab346276d51e2e1eb40c928c:072cc5b53ff0919b8b3197cf50eef831223340c2:NO_MERGE:NO_DEPLOY:NO_EFFECTS`

## Authority binding

Fresh authority inputs at FIX_R1 gate consumption:

- `main` commit: `153372ee58552cffc5143690e3d976b366c8d780`
- `main` tree: `749178828fd910cde7cefd26ce643b7c74c4a811`
- Risk Authority PR #20 head: `28b2488a0fd4866bab346276d51e2e1eb40c928c`
- mediation PR #21 head before FIX_R1: `072cc5b53ff0919b8b3197cf50eef831223340c2`
- PR #20 and PR #21 state at consumption: OPEN + DRAFT + UNMERGED

This branch remains stacked from PR #20. It does not replace, rewrite, merge, or abandon PR #20.

## Problem

PR #20 proves a deterministic anti-downgrade classifier:

`trusted consequence facts -> minimum R0-R4 risk`

It intentionally does not prove repository-wide complete mediation. A caller can still invoke the existing authorization entry point without first invoking Risk Authority.

PR #21 defines the narrow side-effect-free mediation component that must sit in front of the existing authorization stack before a later runtime-binding gate can be considered.

## Required flow

```text
exact action/effect subject
    -> construct frozen bounded RiskSubject
    -> trusted bounded risk-fact adapter sees RiskSubject only
    -> Risk Authority R1 assess_risk
    -> existing TRIAXIS authorizer
    -> existing PEP / Cedar PDP where configured
    -> canonical TRIAXIS authorization-token validation
    -> verify exact effect + effective-risk binding
    -> sealed risk-mediation receipt bound to token SHA-256
```

There is no second PDP. Cedar/PEP remains the authorization authority.

## FIX_R1 adversarial findings and closure

Independent read-only adversarial review reproduced two blockers in the original PR #21 head `072cc5b53ff0919b8b3197cf50eef831223340c2`.

### Blocker 1 — caller risk could influence fact selection

The original code excluded `risk_class` from the subject digest but still passed the entire action, including caller-controlled `risk_class`, to the trusted adapter. A trusted adapter could therefore select different facts based on caller risk while returning the same valid subject digest.

FIX_R1 closes this by introducing frozen `RiskSubject`. The adapter receives only:

- subject id;
- object id;
- capability;
- tool id;
- execution target;
- payload SHA-256;
- authenticated state-witness SHA-256.

`risk_class` and all other action fields are absent from the adapter interface. The same bounded object is the canonical input to `risk_subject_sha256`.

### Blocker 2 — generic sealed mappings could masquerade as authorization tokens

The original code required only a valid `token_sha256` seal plus local effect/risk fields. A generic sealed mapping without the TRIAXIS authorization-token contract could therefore pass mediation.

FIX_R1 now requires the existing canonical `action_assurance.validate_authorization_token(..., require_allow=False)` to return `PASS` before any effect/risk binding or mediation receipt is accepted. This preserves DENY as a valid authorization result while rejecting non-TRIAXIS token contracts, malformed token fields, invalid expiry semantics, and invalid canonical seals.

## Component properties after FIX_R1

`src/triaxis/risk_mediation.py` remains inert and side-effect free and now provides:

1. **Trusted adapter provenance** — facts are accepted only from one exact configured adapter id, version and in-process object instance.
2. **Bounded fact input** — the adapter receives a frozen `RiskSubject`, not the complete caller action.
3. **Caller-risk independence** — caller `risk_class` is not present in the adapter input and cannot drive fact selection through this interface.
4. **Exact risk subject** — facts bind subject/object/capability/tool/target/payload/state-witness semantics.
5. **Mutation containment** — the frozen subject cannot be modified by the adapter; the authorizer receives a detached materialized action.
6. **Anti-downgrade** — caller risk below the trusted derived minimum blocks before authorization.
7. **Existing authorization preserved** — the boundary delegates to the existing authorizer rather than implementing policy decisions.
8. **Canonical token contract validation** — returned authorization must pass TRIAXIS `validate_authorization_token` with the same evaluation tick.
9. **Effect binding** — validated token semantics must match the mediated risk subject.
10. **Risk binding** — validated token `risk_class` must equal mediated effective risk.
11. **Audit chain** — the sealed mediation receipt binds adapter identity/version, risk subject, facts, derived/effective risk and authorization token digest.

Any mismatch fails closed with a deterministic mediation error.

## Exact targeted verification after FIX_R1

GitHub readback identities:

- `src/triaxis/risk_mediation.py`: `b30cf2e75044dbe69f78c3bccdf8555fbb38dca8`
- `tests/test_risk_mediation_r1.py`: `a1f8bc263b337314b15c4e7a37658adaf2026f6b`
- unchanged `src/triaxis/risk_authority.py`: `3bceec4753ca475c78d1e0ac7ad57b9deeb6ae1f`
- unchanged `tests/test_risk_authority_r1.py`: `9b17f1064a11a597de485845911cfc016f31d669`

The local candidate bytes used for the post-fix mediation test were verified with `git hash-object` to equal the GitHub-written source/test blobs above. Mediation targeted result:

`23 passed`

The unchanged Risk Authority R1 source/test blobs were previously exact-byte verified at:

`24 passed`

Therefore current bounded evidence covers 47 passing targeted cases across the two unchanged/current suites, but this is **not** represented as a fresh full-repository regression run or GitHub Actions result.

New adversarial regression cases explicitly prove:

- caller `risk_class` is absent from the adapter input;
- changing caller risk does not change the bounded subject seen by the adapter;
- the adapter input is frozen;
- an arbitrary SHA-sealed mapping is rejected as a non-TRIAXIS authorization token;
- a wrong authorization-token contract id fails closed;
- an invalid evaluation tick blocks before adapter/authorizer invocation.

Existing tests continue to cover caller downgrade, R4 critical-domain downgrade, adapter substitution/failure, stale observations, token effect/risk substitution, missing digest and effect-subject substitutions.

No manual GitHub Actions/CI run was invoked.

## What this branch does NOT prove

This branch does **not** claim repository-wide complete mediation yet.

It still does not:

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

A direct caller can still bypass this component until a future separately reviewed runtime-binding gate changes the effect-capable entry path. The correct implementation status remains:

`COMPLETE_MEDIATION_COMPONENT_DESIGNED_AND_TESTED__RUNTIME_BINDING_NOT_IMPLEMENTED`

## Residual architecture questions

### Cedar R4 control floor

The current reference Cedar policy does not itself encode the legacy R4 HUMAN approval floor. A future runtime integration must prove that authoritative R4 cannot produce an effect-capable ALLOW without the intended R4 control floor. Merely passing the string `R4` into Cedar is insufficient evidence.

### Deployment classification

PR #20 does not add `DEPLOYMENT` as a `CriticalDomain`. FIX_R1 does not silently change classifier semantics. Whether production deployment becomes an explicit R4 domain remains a separate reviewed classifier decision.

### Adapter trust across process boundaries

The registry remains an in-process exact-instance trust binding. If risk facts are produced across a process or network boundary, object identity is insufficient and authenticated/cryptographically bound provenance is required.

### Ledger binding

The mediation receipt binds the result to the authorization token digest, but the existing execution ledger does not yet require or persist this receipt. A future runtime-integration PR must close that gap before repository-wide complete mediation can be claimed.

## Frozen scope

Under the consumed FIX_R1 gate:

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

## Next gate after fresh independent review

FIX_R1 does not itself authorize runtime binding. The updated PR #21 must receive a fresh read-only adversarial review. Only if that review passes may a new owner gate be prepared for repository-wide runtime binding. That future gate must bind the then-current `main`, PR #20 head, and updated PR #21 head; explicitly name the runtime files/call paths allowed to change; and remain `NO_EFFECTS` unless a separately bounded effect lifecycle is approved.
