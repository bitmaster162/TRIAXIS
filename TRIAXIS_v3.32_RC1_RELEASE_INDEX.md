# TRIAXIS v3.32-RC1 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.32_RC1_PROVIDER_NATIVE_IDEMPOTENCY_AND_COMPLETION_TRANSPARENCY.md`
- `TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`
- `TRIAXIS_v3.32_RC1_OPERATOR_CARD.md`
- `TRIAXIS_v3.32_RC1_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/provider_native_idempotency.py`
- `src/triaxis/provider_native_idempotency_http.py`
- `src/triaxis/completion_transparency_quorum.py`
- `src/triaxis/completion_transparency_http.py`
- `tools/run_provider_native_idempotency.py`
- `tools/run_completion_transparency_authority.py`

## Schemas

- `schemas/triaxis_provider_native_idempotency_policy_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_event_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_head_v1.schema.json`
- `schemas/triaxis_provider_native_idempotency_status_v1.schema.json`
- `schemas/triaxis_completion_transparency_quorum_config_v1.schema.json`
- `schemas/triaxis_completion_transparency_head_response_v1.schema.json`
- `schemas/triaxis_completion_transparency_quorum_witness_v1.schema.json`

## Validation

- `tests/test_v3_32_provider_native_and_completion_transparency.py`
- `tests/test_v3_32_provider_native_and_completion_transparency_schemas.py`
- `validation/provider_native_completion_transparency/`
- `evidence/TRIAXIS_v3.32_SERVICE_PROCESS_SMOKE.json`

## Claim boundary

This release is the terminal local-reference feature layer. A successor requires
external evidence under `TRIAXIS_PHYSICAL_EVIDENCE_GATE_v1.md`.
