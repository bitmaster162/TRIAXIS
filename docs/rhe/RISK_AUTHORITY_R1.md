# TRIAXIS RHE Risk Authority R1

Status: **DESIGN + TEST PR ONLY**  
Owner gate: `APPROVE_TRIAXIS_RHE_RISK_AUTHORITY_R1_DESIGN_AND_TEST_PR:NO_MERGE:NO_DEPLOY:NO_EFFECTS`

## Baseline

This design is bound to TRIAXIS `main`:

- commit: `153372ee58552cffc5143690e3d976b366c8d780`
- tree: `749178828fd910cde7cefd26ce643b7c74c4a811`

The existing runtime already has an R0-R4 contract in `action_assurance.py`, Cedar/PEP authorization, SPIFFE workload identity, authenticated token/state composition, and a single-use execution ledger. This R1 does **not** replace or bypass any of them.

## Purpose

Risk Authority answers one narrow question before authorization:

> Given trusted, typed consequence facts about an action, what is the minimum TRIAXIS risk class that downstream policy must treat as authoritative?

It is a deterministic consequence classifier, **not** an authorization engine and not a policy decision point.

## Authority boundary

The classifier accepts only typed facts from a trusted/bounded adapter. It deliberately does not infer risk from prompts, free-form action names, capability strings, model output, or caller prose.

R1 consequence matrix:

| Facts | Minimum risk |
|---|---|
| no effect | R0 |
| local + reversible | R1 |
| local + irreversible | R2 |
| external + reversible | R2 |
| external + irreversible | R3 |
| capital / trading / security-admin / identity-admin / policy-admin | R4 |

The five-level mapping intentionally follows the **existing runtime R0-R4 contract**. It resolves the earlier threat-model shorthand that grouped capital/trading/security-admin into an R3-like top tier: in the current codebase, critical authority remains R4 so it receives the strongest existing floor rather than being silently weakened.

## Anti-downgrade rule

`derived_risk` is a minimum. A caller may request a higher risk class, but may never lower it. Unknown, contradictory, malformed, or under-classified facts fail closed.

This PR does not yet wire the result into `ExecutionRequest` or `authorize_action`. Integration requires a separate reviewed gate because runtime wiring changes authorization behavior.

## Non-goals / frozen effects

This PR performs or authorizes none of the following:

- merge to `main`;
- deployment;
- AWS/IAM/Secrets Manager/S3/TSA writes;
- provider invocation;
- production ledger mutation;
- model execution;
- trading or capital action;
- runtime authorization changes.

Frozen invariants remain:

- `model_execution_authorized=false`
- `model_execution_performed=false`
- `can_trade=false`
- `capital_permission=DENY`
- `deploy_permission=DENY`

## Test obligations

The R1 tests prove:

1. exact deterministic consequence matrix;
2. every critical domain maps to R4;
3. set ordering cannot change the result;
4. caller downgrade is rejected;
5. caller over-classification is allowed;
6. contradictory and unknown facts fail closed;
7. no external target or provider is invoked by this module.

## Next gate after review

If this design is accepted, a separate owner-approved integration PR may bind the authoritative derived risk to the existing action-assurance request path and prove that no caller-controlled `risk_class` can bypass the minimum. That future gate is explicitly **not** authorized here.
