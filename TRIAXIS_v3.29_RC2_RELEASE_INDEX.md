# TRIAXIS v3.29-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.23_RC1_EXTERNAL_SANDBOX_ATTESTATION.md`
- `TRIAXIS_CONTROL_STACK_v3.24_RC1_CROSS_HARNESS_GOVERNANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.25_RC1_CANONICAL_TARGET_AUTHORIZATION.md`
- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.27_RC1_EXTERNAL_EXECUTION_LEDGER.md`
- `TRIAXIS_CONTROL_STACK_v3.28_RC1_MONOTONIC_EXECUTION_HEAD_AND_PROVIDER_RECONCILIATION.md`
- `TRIAXIS_CONTROL_STACK_v3.29_RC1_INDEPENDENT_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS.md`
- `TRIAXIS_CROSS_HARNESS_ADOPTION_REGISTER_v3.json`
- `TRIAXIS_v3.29_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.29_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/external_execution_ledger.py`
- `src/triaxis/external_execution_ledger_http.py`
- `src/triaxis/execution_ledger_head_authority.py`
- `src/triaxis/execution_ledger_head_http.py`
- `src/triaxis/execution_ledger_head_quorum.py`
- `src/triaxis/idempotent_effect_provider.py`
- `src/triaxis/idempotent_effect_provider_http.py`
- `src/triaxis/external_completion_witness.py`
- `src/triaxis/external_completion_witness_http.py`
- `tools/run_execution_ledger_authority.py`
- `tools/run_execution_ledger_head_authority.py`
- `tools/run_idempotent_effect_provider.py`
- `tools/run_external_completion_witness.py`

## Schemas

- `schemas/triaxis_execution_intent_v1.schema.json`
- `schemas/triaxis_execution_ledger_event_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_response_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_quorum_config_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_quorum_witness_v1.schema.json`
- `schemas/triaxis_provider_effect_status_v1.schema.json`
- `schemas/triaxis_provider_outcome_receipt_v1.schema.json`
- `schemas/triaxis_external_completion_witness_event_v1.schema.json`
- `schemas/triaxis_external_completion_witness_head_v1.schema.json`
- `schemas/triaxis_external_completion_witness_status_v1.schema.json`

## Deployment reference

- `deploy/Dockerfile.execution-ledger`
- `deploy/Dockerfile.execution-ledger-head`
- `deploy/Dockerfile.idempotent-provider`
- `deploy/Dockerfile.external-completion-witness`
- `deploy/triaxis-execution-ledger.service`
- `deploy/triaxis-execution-ledger-head.service`
- `deploy/triaxis-execution-ledger-head@.service`
- `deploy/triaxis-idempotent-provider.service`
- `deploy/triaxis-external-completion-witness.service`
- `deploy/execution-ledger-head-quorum/`
- `deploy/execution-effect-control-plane/README_v3.29.md`

## Validation

- `validation/execution_head_quorum_completion_witness/TRIAXIS_v3.29_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS_PROTOCOL.md`
- `validation/execution_head_quorum_completion_witness/run_v329_execution_head_quorum_and_completion_witness_closure.py`
- `validation/execution_head_quorum_completion_witness/run_v329_service_process_smoke.py`
- `validation/execution_head_quorum_completion_witness/run_v329_postcommit_threshold_and_completion_witness_rollback.py`
- `evidence/TRIAXIS_v3.29_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS_CLOSURE.json`
- `evidence/TRIAXIS_v3.29_SERVICE_PROCESS_SMOKE.json`
- `evidence/TRIAXIS_v3.29_POSTCOMMIT_THRESHOLD_AND_COMPLETION_WITNESS_ROLLBACK_BOUNDARY.json`
- `TRIAXIS_v3.29_RC2_VALIDATION_RECEIPT.md`
- `TRIAXIS_v3.29_RC2_DECLARATION.json`

## Claim boundary

This package proves only the executable reference contracts under the frozen
tests. It does not establish physical or administrative independence,
provider-native exactly-once execution, resistance to compromise or rollback of
a quorum threshold and completion-memory domain, production availability,
KMS/HSM custody, trusted time, mTLS, capacity, or independent certification.
