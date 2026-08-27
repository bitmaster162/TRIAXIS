# TRIAXIS RHE Risk Authority R1 — Authenticated Runtime Binding Design

Status: **DESIGN + TEST ONLY / DRAFT STACKED PR / NO MERGE / NO DEPLOY / NO EFFECTS**

## Consumed owner gate

This lane was authorized exactly once by:

`APPROVE_TRIAXIS_RHE_RISK_AUTHORITY_R1_AUTHENTICATED_RUNTIME_BINDING_DESIGN_AND_TEST_PR:153372ee58552cffc5143690e3d976b366c8d780:28b2488a0fd4866bab346276d51e2e1eb40c928c:f50028314e7cea39add652677adeee50ff4b6835:NO_MERGE:NO_DEPLOY:NO_EFFECTS`

The gate is consumed by creation and mutation of the bounded stacked branch. It is not reusable for merge, deployment, effects, provider invocation, production-ledger mutation, model execution, trading or capital action.

Authority at consumption:

- `main` HEAD: `153372ee58552cffc5143690e3d976b366c8d780`
- `main` tree: `749178828fd910cde7cefd26ce643b7c74c4a811`
- PR #20 head: `28b2488a0fd4866bab346276d51e2e1eb40c928c`
- PR #21 head / stacked base: `f50028314e7cea39add652677adeee50ff4b6835`
- stacked branch: `feat/rhe-risk-authority-r1-authenticated-runtime-binding`

## Purpose

PR #21 creates an inert, fail-closed risk mediation component. This lane binds that component to the existing authenticated authorization and authenticated PREPARED boundaries without creating any external-effect authority.

The design preserves the existing Cedar/PEP stack as the only policy decision point. Risk Authority remains a consequence classifier and anti-downgrade control; it does not become a second PDP.

## Binding sequence

The intended authenticated path is:

1. authenticate assurance attestation, state witness, policy bundle and approvals;
2. obtain trusted consequence facts through the exact in-process `RiskFactsAdapter` binding;
3. derive the minimum R0-R4 class and reject caller downgrade;
4. call the existing `authorize_action` stack with the exact mediated action;
5. validate exact authorization-token contract, effect subject and effective-risk binding;
6. create the canonical `TRIAXIS_RISK_MEDIATION_RECEIPT_v1` bound to `authorization_token_sha256`;
7. sign the authorization token under `AUTHORIZATION_TOKEN`;
8. sign the mediation receipt separately under the new `RISK_MEDIATION_RECEIPT` purpose;
9. before any authenticated PREPARED transition, authenticate both objects and require:
   - expected gate signer and trust domain;
   - receipt -> exact token SHA binding;
   - receipt -> exact effect-subject binding;
   - receipt effective risk == token risk;
   - internally self-consistent effect facts and risk assessment;
10. authenticate observed state;
11. on the SPIFFE RHE path, perform the existing fresh trusted workload-identity check;
12. reach at most `PREPARED` and stop.

## One-way receipt binding

The mediation receipt contains `authorization_token_sha256`. The token does not contain the receipt digest.

This deliberately avoids a circular token <-> receipt hash dependency. The independent Ed25519 envelope authenticates the receipt, while the receipt's canonical contents bind it one-way to the already-sealed authorization token.

## PREPARED fail-closed rules

Two authenticated PREPARED paths are covered in this lane:

- `AuthenticatedSQLiteExecutionLedger.prepare_authenticated(...)`
- `AuthenticatedTrustedWorkloadExecutionBoundary.prepare(...)`

A signed ALLOW token plus signed state is no longer sufficient on either path. A separately authenticated and semantically valid risk-mediation receipt is mandatory.

For the SPIFFE-composed boundary, missing or invalid mediation evidence is rejected before signed-state processing, before the fresh workload-provider fetch, and before any execution-ledger row can be created.

## Compatibility boundary

`authorize_authenticated_action(...)` retains its historical non-mediated issuance mode when no risk adapter configuration is supplied. This avoids silently reinterpreting old callers as having passed Risk Authority.

That legacy signed token is **not** sufficient to enter the authenticated PREPARED paths modified by this lane. Execution authority is therefore stricter than legacy issuance compatibility.

Supplying any partial mediation configuration fails closed. Supplying the complete configuration makes mediation mandatory before a usable authenticated ALLOW result can carry signed mediation evidence.

## Test obligations

The bounded tests cover:

- mediated authenticated ALLOW with exact signed receipt;
- caller downgrade -> DENY / no signed mediation receipt;
- untrusted same-id/version adapter object -> DENY;
- incomplete mediation configuration -> DENY;
- signed token without mediation -> no PREPARED;
- forged mediation signature -> no provider fetch / no PREPARED;
- mediation receipt replayed against another token -> no provider fetch / no PREPARED;
- effect-subject substitution -> no provider fetch / no PREPARED;
- risk substitution -> no provider fetch / no PREPARED;
- unsigned or wrongly signed state remains blocked;
- workload mapping drift remains blocked;
- stable workload identity certificate rotation remains allowed;
- same token + same mediation + same workload PREPARED retry remains idempotent.

All test providers in these tests are deterministic in-process mocks. Any SQLite use is disposable test state. No real external provider is invoked.

## Explicit non-claims and remaining gates

This lane does **not** claim repository-wide complete mediation.

Still open and requiring separately scoped owner authority:

1. **Cedar R4 control floor.** Existing Cedar reference policy semantics do not by themselves prove the legacy R4 HUMAN/control floor. This lane does not change Cedar policy or PEP semantics.
2. **DEPLOYMENT classification.** `DEPLOYMENT` is not silently added to `CriticalDomain`; its R4 treatment remains a separate policy/design decision.
3. **Cross-process risk-fact provenance.** `TrustedRiskFactsAdapterRegistry` remains an exact in-process object binding. A remote adapter would require separately designed authenticated/cryptographic provenance.
4. **Production ledger persistence.** The mediation receipt is verified before PREPARED but is not added to the production execution-ledger schema in this lane.
5. **Non-authenticated / legacy direct paths.** This lane closes the two authenticated PREPARED paths named above. It does not prove that every historical or lower-level repository call path is unreachable in production composition.
6. **External effect lifecycle.** No provider effect, completion path, deployment, AWS write, model execution, trading or capital action is authorized or performed.

## Frozen ceiling

The strongest allowed terminal state in this lane is:

`AUTHENTICATED_RISK_MEDIATION_BOUND_TO_EXACT_ALLOW_TOKEN__PREPARED_ONLY__NO_EXTERNAL_EFFECT`

Permanent invariants remain:

- `RERUN_R4_1=DENY`
- `RERUN_V036=DENY`
- `REUSE_CONSUMED_APPROVALS=DENY`
- `model_execution_authorized=false`
- `model_execution_performed=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

No merge, deploy or effect authority is created by this document or its PR.
