# TRIAXIS v3.31-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.23_RC1_EXTERNAL_SANDBOX_ATTESTATION.md`
- `TRIAXIS_CONTROL_STACK_v3.24_RC1_CROSS_HARNESS_GOVERNANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.25_RC1_CANONICAL_TARGET_AUTHORIZATION.md`
- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.27_RC1_EXTERNAL_EXECUTION_LEDGER.md`
- `TRIAXIS_CONTROL_STACK_v3.28_RC1_MONOTONIC_EXECUTION_HEAD_AND_PROVIDER_RECONCILIATION.md`
- `TRIAXIS_CONTROL_STACK_v3.29_RC1_INDEPENDENT_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS.md`
- `TRIAXIS_CONTROL_STACK_v3.30_RC1_COMPLETION_WITNESS_QUORUM_AND_WORM_ANCHOR.md`
- `TRIAXIS_CONTROL_STACK_v3.31_RC1_AVAILABILITY_CLOSED_COMPLETION_AND_IMMUTABLE_ANCHOR.md`
- `TRIAXIS_v3.31_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.31_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/completion_availability_control.py`
- `src/triaxis/completion_immutable_anchor.py`
- `src/triaxis/completion_immutable_anchor_http.py`
- `tools/run_completion_immutable_anchor.py`

## Schemas

- `schemas/triaxis_completion_availability_policy_v1.schema.json`
- `schemas/triaxis_completion_availability_witness_v1.schema.json`
- `schemas/triaxis_completion_immutable_object_receipt_v1.schema.json`
- `schemas/triaxis_completion_immutable_anchor_event_v1.schema.json`
- `schemas/triaxis_completion_immutable_anchor_head_v1.schema.json`
- `schemas/triaxis_completion_immutable_anchor_status_v1.schema.json`

## Deployment reference

- `deploy/Dockerfile.completion-immutable-anchor`
- `deploy/triaxis-completion-immutable-anchor.service`
- `deploy/completion-immutable-anchor.env.example`
- `deploy/execution-effect-control-plane/README_v3.31.md`

## Validation

- `tests/test_v3_31_availability_closed_and_immutable_anchor.py`
- `tests/test_v3_31_availability_closed_and_immutable_anchor_schemas.py`
- `validation/availability_closed_completion_immutable_anchor/TRIAXIS_v3.31_AVAILABILITY_CLOSED_COMPLETION_AND_IMMUTABLE_ANCHOR_PROTOCOL.md`
- `validation/availability_closed_completion_immutable_anchor/run_v331_availability_closed_completion_and_immutable_anchor_closure.py`
- `validation/availability_closed_completion_immutable_anchor/run_v331_service_process_smoke.py`
- `validation/availability_closed_completion_immutable_anchor/run_v331_postcommit_coordinated_completion_evidence_rollback.py`
- `evidence/TRIAXIS_v3.31_AVAILABILITY_CLOSED_COMPLETION_AND_IMMUTABLE_ANCHOR_CLOSURE.json`
- `evidence/TRIAXIS_v3.31_SERVICE_PROCESS_SMOKE.json`
- `evidence/TRIAXIS_v3.31_POSTCOMMIT_COORDINATED_COMPLETION_EVIDENCE_ROLLBACK_BOUNDARY.json`
- `TRIAXIS_v3.31_RC2_VALIDATION_RECEIPT.md`
- `TRIAXIS_v3.31_RC2_DECLARATION.json`

## Claim boundary

This package proves executable logical contracts under the frozen tests. It
does not establish physical or administrative independence, physical WORM or
object-lock conformance, protected checkpoint memory, provider-native durable
idempotency, resistance to coordinated rollback of every completion-evidence
domain and checkpoint, production availability, KMS/HSM custody, trusted time,
mTLS, capacity or independent certification.
