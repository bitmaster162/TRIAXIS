# TRIAXIS v3.28-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.23_RC1_EXTERNAL_SANDBOX_ATTESTATION.md`
- `TRIAXIS_CONTROL_STACK_v3.24_RC1_CROSS_HARNESS_GOVERNANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.25_RC1_CANONICAL_TARGET_AUTHORIZATION.md`
- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.27_RC1_EXTERNAL_EXECUTION_LEDGER.md`
- `TRIAXIS_CONTROL_STACK_v3.28_RC1_MONOTONIC_EXECUTION_HEAD_AND_PROVIDER_RECONCILIATION.md`
- `TRIAXIS_CROSS_HARNESS_ADOPTION_REGISTER_v3.json`
- `TRIAXIS_v3.28_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.28_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/harness_durability_v3.py`
- `src/triaxis/external_execution_ledger.py`
- `src/triaxis/external_execution_ledger_http.py`
- `src/triaxis/execution_ledger_head_authority.py`
- `src/triaxis/execution_ledger_head_http.py`
- `src/triaxis/idempotent_effect_provider.py`
- `src/triaxis/idempotent_effect_provider_http.py`
- `tools/run_execution_ledger_authority.py`
- `tools/run_execution_ledger_head_authority.py`
- `tools/run_idempotent_effect_provider.py`

## Schemas

- `schemas/triaxis_execution_intent_v1.schema.json`
- `schemas/triaxis_execution_ledger_event_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_response_v1.schema.json`
- `schemas/triaxis_provider_effect_status_v1.schema.json`

## Deployment reference

- `deploy/Dockerfile.execution-ledger`
- `deploy/Dockerfile.execution-ledger-head`
- `deploy/Dockerfile.idempotent-provider`
- `deploy/execution-ledger.env.example`
- `deploy/execution-ledger-head.env.example`
- `deploy/idempotent-provider.env.example`
- `deploy/triaxis-execution-ledger.service`
- `deploy/triaxis-execution-ledger-head.service`
- `deploy/triaxis-idempotent-provider.service`
- `deploy/execution-effect-control-plane/README.md`

## Validation

- `validation/execution_ledger_head/TRIAXIS_v3.28_EXECUTION_HEAD_AND_PROVIDER_PROTOCOL.md`
- `validation/execution_ledger_head/run_v328_execution_head_and_provider_closure.py`
- `validation/execution_ledger_head/run_v328_postcommit_full_effect_state_rollback.py`
- `evidence/TRIAXIS_v3.28_EXECUTION_HEAD_AND_PROVIDER_CLOSURE.json`
- `evidence/TRIAXIS_v3.28_POSTCOMMIT_FULL_EFFECT_STATE_ROLLBACK_BOUNDARY.json`
- `TRIAXIS_v3.28_RC2_VALIDATION_RECEIPT.md`

## Claim boundary

This package proves only the executable reference contracts under the frozen
tests. It does not establish physical or administrative independence,
provider-native exactly-once execution, coordinated anti-rollback across all
state domains, production availability, KMS/HSM custody, trusted time, mTLS,
capacity, or independent certification.
