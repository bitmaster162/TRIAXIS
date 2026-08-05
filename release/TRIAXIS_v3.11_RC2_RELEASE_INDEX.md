# TRIAXIS v3.11-RC2 Authenticated Quorum Policy — Release Index

## Normative

- `spec/TRIAXIS_CONTROL_STACK_v3.6_RC1_CRYPTOGRAPHIC_AUTHENTICITY.md`
- `spec/TRIAXIS_CONTROL_STACK_v3.7_RC1_MONOTONIC_TRUST_REGISTRY.md`
- `spec/TRIAXIS_CONTROL_STACK_v3.8_RC1_EXTERNAL_REGISTRY_ANCHOR.md`
- `spec/TRIAXIS_CONTROL_STACK_v3.9_RC1_CHALLENGE_BOUND_ANCHOR.md`
- `spec/TRIAXIS_CONTROL_STACK_v3.10_RC1_QUORUM_ANCHOR.md`
- `spec/TRIAXIS_CONTROL_STACK_v3.11_RC1_AUTHENTICATED_QUORUM_POLICY.md`

## Implementation

- `src/triaxis/crypto_trust.py`
- `src/triaxis/authenticated_action_assurance.py`
- `src/triaxis/trust_registry_state.py`
- `src/triaxis/trust_registry_anchor.py`
- `src/triaxis/trust_registry_quorum.py`
- `src/triaxis/anchor_quorum_policy.py`

## Schemas

- `schemas/triaxis_ed25519_trust_key_v1.schema.json`
- `schemas/triaxis_signed_contract_envelope_v1.schema.json`
- `schemas/triaxis_trust_registry_snapshot_v1.schema.json`
- `schemas/triaxis_trust_registry_head_witness_v1.schema.json`
- `schemas/triaxis_trust_registry_challenge_witness_v1.schema.json`
- `schemas/triaxis_trust_registry_quorum_member_witness_v1.schema.json`
- `schemas/triaxis_anchor_quorum_policy_v1.schema.json`
- `schemas/triaxis_trust_registry_policy_bound_quorum_witness_v1.schema.json`

## Validation

- `validation/TRIAXIS_CRYPTOGRAPHIC_ISSUER_AUTHENTICITY_TRIGGER_v2.py`
- `validation/TRIAXIS_TRUST_REGISTRY_ROLLBACK_TRIGGER_v2.py`
- `validation/TRIAXIS_WHOLE_REGISTRY_DATABASE_ROLLBACK_TRIGGER_v2.py`
- `validation/TRIAXIS_EXTERNAL_ANCHOR_REPLAY_TRIGGER_v2.py`
- `validation/TRIAXIS_QUORUM_AND_VERIFIER_EPOCH_TRIGGER_v1.py`
- `validation/TRIAXIS_AUTHENTICATED_QUORUM_POLICY_TRIGGER_v1.py`
- `validation/TRIAXIS_V311_POSTCOMMIT_WHOLE_POLICY_DB_ROLLBACK_TRIGGER_v1.py`

## Release evidence

- `release/TRIAXIS_v3.11_RC2_AUTHENTICATED_QUORUM_POLICY_VALIDATION_RECEIPT.md`
- `release/TRIAXIS_v3.11_RC2_DECLARATION.json`
- `evidence/TRIAXIS_v3.11_POSTCOMMIT_WHOLE_POLICY_DB_ROLLBACK_BOUNDARY.json`
