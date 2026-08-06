# TRIAXIS v3.27-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.23_RC1_EXTERNAL_SANDBOX_ATTESTATION.md`
- `TRIAXIS_CONTROL_STACK_v3.24_RC1_CROSS_HARNESS_GOVERNANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.25_RC1_CANONICAL_TARGET_AUTHORIZATION.md`
- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CONTROL_STACK_v3.27_RC1_EXTERNAL_EXECUTION_LEDGER.md`
- `TRIAXIS_CROSS_HARNESS_ADOPTION_REGISTER_v3.json`
- `TRIAXIS_v3.27_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.27_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/harness_durability_v3.py`
- `src/triaxis/external_execution_ledger.py`
- `src/triaxis/external_execution_ledger_http.py`
- `tools/run_execution_ledger_authority.py`

## Schemas

- `schemas/triaxis_execution_intent_v1.schema.json`
- `schemas/triaxis_execution_ledger_event_v1.schema.json`
- `schemas/triaxis_execution_ledger_head_v1.schema.json`

## Deployment reference

- `deploy/Dockerfile.execution-ledger`
- `deploy/execution-ledger.env.example`
- `deploy/triaxis-execution-ledger.service`

## Validation

- `validation/execution_ledger/TRIAXIS_v3.27_EXTERNAL_EXECUTION_LEDGER_PROTOCOL.md`
- `validation/execution_ledger/run_v327_external_execution_ledger_closure.py`
- `validation/execution_ledger/run_v327_postcommit_whole_ledger_db_rollback.py`
- `evidence/TRIAXIS_v3.27_EXTERNAL_EXECUTION_LEDGER_CLOSURE.json`
- `evidence/TRIAXIS_v3.27_POSTCOMMIT_WHOLE_EXECUTION_LEDGER_DB_ROLLBACK_BOUNDARY.json`
- `TRIAXIS_v3.27_RC2_VALIDATION_RECEIPT.md`

## Claim boundary

This package blocks local-queue rollback replay only while the separately persisted execution ledger remains current. It does not establish ledger anti-rollback, provider-side exactly-once effects, physical or administrative independence, production availability, or independent certification.
