# TRIAXIS v3.30-RC1 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.23_RC1_EXTERNAL_SANDBOX_ATTESTATION.md`
- `TRIAXIS_CONTROL_STACK_v3.24_RC1_CROSS_HARNESS_GOVERNANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.25_RC1_CANONICAL_TARGET_AUTHORIZATION.md`
- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.27_RC1_EXTERNAL_EXECUTION_LEDGER.md`
- `TRIAXIS_CONTROL_STACK_v3.28_RC1_MONOTONIC_EXECUTION_HEAD_AND_PROVIDER_RECONCILIATION.md`
- `TRIAXIS_CONTROL_STACK_v3.29_RC1_INDEPENDENT_EXECUTION_HEAD_QUORUM_AND_COMPLETION_WITNESS.md`
- `TRIAXIS_CONTROL_STACK_v3.30_RC1_COMPLETION_WITNESS_QUORUM_AND_WORM_ANCHOR.md`
- `TRIAXIS_v3.30_RC1_OPERATOR_CARD.md`
- `TRIAXIS_v3.30_RC1_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/completion_witness_quorum.py`
- `src/triaxis/completion_worm_anchor.py`
- `src/triaxis/completion_worm_anchor_http.py`
- `tools/run_completion_worm_anchor.py`

## Schemas

- `schemas/triaxis_completion_witness_quorum_config_v1.schema.json`
- `schemas/triaxis_completion_witness_quorum_witness_v1.schema.json`
- `schemas/triaxis_completion_worm_anchor_event_v1.schema.json`
- `schemas/triaxis_completion_worm_anchor_head_v1.schema.json`
- `schemas/triaxis_completion_worm_anchor_status_v1.schema.json`

## Deployment reference

- `deploy/Dockerfile.completion-worm-anchor`
- `deploy/triaxis-completion-worm-anchor.service`
- `deploy/completion-worm-anchor.env.example`
- `deploy/execution-effect-control-plane/README_v3.30.md`

## Validation

- `tests/test_v3_30_completion_witness_quorum_and_worm_anchor.py`
- `tests/test_v3_30_completion_witness_quorum_and_worm_anchor_schemas.py`
- `validation/completion_witness_quorum_worm_anchor/TRIAXIS_v3.30_COMPLETION_WITNESS_QUORUM_AND_WORM_ANCHOR_PROTOCOL.md`
- `validation/completion_witness_quorum_worm_anchor/run_v330_completion_witness_quorum_and_worm_anchor_closure.py`
- `validation/completion_witness_quorum_worm_anchor/run_v330_service_process_smoke.py`
- `evidence/TRIAXIS_v3.30_COMPLETION_WITNESS_QUORUM_AND_WORM_ANCHOR_CLOSURE.json`
- `evidence/TRIAXIS_v3.30_SERVICE_PROCESS_SMOKE.json`

## Claim boundary

This RC1 proves only executable logical contracts under the frozen tests. It
does not establish physical or administrative independence, physical WORM
storage, provider-native exactly-once execution, resistance to coordinated
rollback of both quorum thresholds and the anchor, production availability,
KMS/HSM custody, trusted time, mTLS, capacity or independent certification.
