# TRIAXIS v3.32-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.32_RC1_PROVIDER_NATIVE_IDEMPOTENCY_AND_COMPLETION_TRANSPARENCY.md`
- `TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`
- `TRIAXIS_v3.32_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.32_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/provider_native_idempotency.py`
- `src/triaxis/provider_native_idempotency_http.py`
- `src/triaxis/completion_transparency_quorum.py`
- `src/triaxis/completion_transparency_http.py`
- `src/triaxis/provider_transparency_guard.py`
- `tools/run_provider_native_idempotency.py`
- `tools/run_completion_transparency_authority.py`
- `deploy/v3.32/`

## Schemas

- `schemas/triaxis_provider_native_idempotency_policy_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_event_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_head_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_status_v1.schema.json`
- `schemas/triaxis_completion_transparency_quorum_config_v1.schema.json`
- `schemas/triaxis_completion_transparency_response_v1.schema.json`
- `schemas/triaxis_completion_transparency_quorum_witness_v1.schema.json`

## Validation

- `tests/test_v3_32_provider_native_and_completion_transparency.py`
- `tests/test_v3_32_provider_native_and_completion_transparency_schemas.py`
- `validation/provider_native_completion_transparency/run_v332_provider_native_and_completion_transparency_closure.py`
- `validation/provider_native_completion_transparency/run_v332_service_process_smoke.py`
- `validation/provider_native_completion_transparency/run_v332_postcommit_terminal_local_rollback_boundary.py`
- `evidence/TRIAXIS_v3.32_PROVIDER_NATIVE_AND_COMPLETION_TRANSPARENCY_CLOSURE.json`
- `evidence/TRIAXIS_v3.32_SERVICE_PROCESS_SMOKE.json`
- `evidence/TRIAXIS_v3.32_POSTCOMMIT_TERMINAL_LOCAL_ROLLBACK_BOUNDARY.json`

## Claim boundary

RC2 is validation-only. This package proves a local executable reference, not
real provider-native guarantees, physical WORM, independent administration,
hardware monotonicity, production exactly-once execution, or certification.
