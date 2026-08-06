# TRIAXIS v3.26-RC2 Release Index

## Normative

- `TRIAXIS_CONTROL_STACK_v3.26_RC1_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE.md`
- `TRIAXIS_CROSS_HARNESS_ADOPTION_REGISTER_v3.json`
- `TRIAXIS_v3.26_RC2_OPERATOR_CARD.md`
- `TRIAXIS_v3.26_RC2_RELEASE_NOTES.md`

## Runtime

- `src/triaxis/harness_durability_v3.py`

## Schemas

- `schemas/triaxis_queued_input_v1.schema.json`
- `schemas/triaxis_dispatch_claim_v1.schema.json`
- `schemas/triaxis_dispatch_transition_v1.schema.json`
- `schemas/triaxis_provider_request_receipt_v1.schema.json`

## Validation

- `validation/harness_adoption/run_v326_durable_dispatch_closure.py`
- `validation/harness_adoption/run_v326_postcommit_whole_queue_db_rollback.py`
- `evidence/TRIAXIS_v3.26_DURABLE_DISPATCH_AND_PROVIDER_PROVENANCE_CLOSURE.json`
- `evidence/TRIAXIS_v3.26_POSTCOMMIT_WHOLE_QUEUE_DB_ROLLBACK_BOUNDARY.json`
- `TRIAXIS_v3.26_RC2_VALIDATION_RECEIPT.md`

## Claim boundary

This package does not establish exactly-once execution after whole-store rollback. It requires an external monotonic or authoritative execution boundary.
