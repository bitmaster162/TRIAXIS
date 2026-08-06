"""Deterministic governance-gate projection for TRIAXIS.

This package does not implement the generative Audit/Devil/Angel/Synthesizer
passes. It implements machine-checkable structured-input, semantic-ingress,
routing, authority, integrity, and execution gates for validation purposes.
"""

from .input_contract import (
    INPUT_CONTRACT_ID,
    INPUT_CONTRACT_V1_ID,
    INPUT_CONTRACT_V2_ID,
    migrate_v1_to_v2,
    schema_document,
    schema_document_v1,
    schema_document_v2,
    validate_scenario,
    validate_scenario_v1,
    validate_scenario_v2,
)
from .projection import evaluate_candidate, evaluate_ingress, supported_versions
from .semantic_ingress import (
    ACTION_MINIMUM_X,
    SEMANTIC_INGRESS_CONTRACT_ID,
    SEMANTIC_INGRESS_RULESET_V1,
    SEMANTIC_INGRESS_RULESET_V2,
    scan_control_surface,
    schema_document as semantic_ingress_schema_document,
    validate_ingress,
    validate_ingress_v1,
    validate_ingress_v2,
)

__all__ = [
    "ACTION_MINIMUM_X",
    "INPUT_CONTRACT_ID",
    "INPUT_CONTRACT_V1_ID",
    "INPUT_CONTRACT_V2_ID",
    "SEMANTIC_INGRESS_CONTRACT_ID",
    "SEMANTIC_INGRESS_RULESET_V1",
    "SEMANTIC_INGRESS_RULESET_V2",
    "evaluate_candidate",
    "migrate_v1_to_v2",
    "evaluate_ingress",
    "scan_control_surface",
    "schema_document",
    "schema_document_v1",
    "schema_document_v2",
    "semantic_ingress_schema_document",
    "supported_versions",
    "validate_ingress",
    "validate_ingress_v1",
    "validate_ingress_v2",
    "validate_scenario",
    "validate_scenario_v1",
    "validate_scenario_v2",
]

# Recovered authority-analysis surface imported from the partial v2.34 snapshot.
from .analysis_v5 import (
    ANALYSIS_BUNDLE_CONTRACT_ID,
    validate_analysis_bundle as validate_analysis_bundle_v5,
)
from .authority_analysis import (
    AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V1_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID,
    AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID,
    AuthorityAnalysisSession,
    authority_analysis_required,
    authority_session_required_result,
    validate_authority_analysis_bundle,
)
from .provenance_trust_state import (
    ProvenanceTrustCheckpoint,
    ProvenanceTrustStateGuard,
    TRUST_CHECKPOINT_CONTRACT_ID,
    TRUST_CHECKPOINT_V2_CONTRACT_ID,
    TrustSnapshotStateError,
    validate_checkpoint_receipt,
)

__all__ += [
    "ANALYSIS_BUNDLE_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V1_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID",
    "AuthorityAnalysisSession",
    "ProvenanceTrustCheckpoint",
    "ProvenanceTrustStateGuard",
    "TRUST_CHECKPOINT_CONTRACT_ID",
    "TRUST_CHECKPOINT_V2_CONTRACT_ID",
    "TrustSnapshotStateError",
    "authority_analysis_required",
    "authority_session_required_result",
    "validate_analysis_bundle_v5",
    "validate_authority_analysis_bundle",
    "validate_checkpoint_receipt",
]

from .checkpoint_store import (
    CheckpointStoreError,
    SQLiteCheckpointStore,
)

__all__ += [
    "CheckpointStoreError",
    "SQLiteCheckpointStore",
]

from .checkpoint_scope import (
    AuthenticatedCheckpointScope,
    CHECKPOINT_NAMESPACE_CONTRACT_ID,
    CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID,
    CheckpointScopeError,
    checkpoint_namespace_sha256,
    checkpoint_scope_schema_document,
    verify_checkpoint_scope_envelope,
)

__all__ += [
    "AuthenticatedCheckpointScope",
    "CHECKPOINT_NAMESPACE_CONTRACT_ID",
    "CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID",
    "CheckpointScopeError",
    "checkpoint_namespace_sha256",
    "checkpoint_scope_schema_document",
    "verify_checkpoint_scope_envelope",
]

from .assurance_v1 import (
    ASSURANCE_CASE_CONTRACT_ID,
    validate_assurance_case,
)

__all__ += [
    "ASSURANCE_CASE_CONTRACT_ID",
    "validate_assurance_case",
]

from .assurance_v2 import (
    ASSURANCE_CASE_CONTRACT_ID as ASSURANCE_CASE_V2_CONTRACT_ID,
    validate_assurance_case as validate_assurance_case_v2,
)

__all__ += [
    "ASSURANCE_CASE_V2_CONTRACT_ID",
    "validate_assurance_case_v2",
]

# TRIAXIS v3.4 operational assurance surface (exact assured-action binding).
from .evidence_broker import (
    CLAIM_RECORD_CONTRACT_ID,
    EVIDENCE_PACKAGE_CONTRACT_ID,
    EVIDENCE_REPORT_CONTRACT_ID,
    SOURCE_RECORD_CONTRACT_ID,
    validate_evidence_package,
)
from .policy_lifecycle import (
    POLICY_BUNDLE_CONTRACT_ID,
    POLICY_DECISION_CONTRACT_ID,
    PolicyRegistry,
    PolicyRegistryError,
    evaluate_policy,
    validate_policy_bundle,
)
from .action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    AUTHORIZATION_TOKEN_CONTRACT_ID,
    EXECUTION_RECEIPT_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    validate_action_envelope,
    validate_assurance_attestation,
    validate_authorization_token,
    validate_state_witness,
)
from .assurance_router import ASSURANCE_PLAN_CONTRACT_ID, select_assurance_plan
from .fail_bench import compare_full_to_mvt, score_rows as score_fail_bench_rows

__all__ += [
    "ACTION_ENVELOPE_CONTRACT_ID",
    "APPROVAL_CONTRACT_ID",
    "ASSURANCE_ATTESTATION_CONTRACT_ID",
    "ASSURANCE_PLAN_CONTRACT_ID",
    "AUTHORIZATION_TOKEN_CONTRACT_ID",
    "CLAIM_RECORD_CONTRACT_ID",
    "EVIDENCE_PACKAGE_CONTRACT_ID",
    "EVIDENCE_REPORT_CONTRACT_ID",
    "EXECUTION_RECEIPT_CONTRACT_ID",
    "POLICY_BUNDLE_CONTRACT_ID",
    "POLICY_DECISION_CONTRACT_ID",
    "SOURCE_RECORD_CONTRACT_ID",
    "STATE_WITNESS_CONTRACT_ID",
    "ExecutionLedgerError",
    "PolicyRegistry",
    "PolicyRegistryError",
    "SQLiteExecutionLedger",
    "action_scope_sha256",
    "assured_action_request_sha256",
    "authorize_action",
    "compare_full_to_mvt",
    "evaluate_policy",
    "score_fail_bench_rows",
    "select_assurance_plan",
    "validate_action_envelope",
    "validate_assurance_attestation",
    "validate_authorization_token",
    "validate_evidence_package",
    "validate_policy_bundle",
    "validate_state_witness",
]

# TRIAXIS v3.6 cryptographic authenticity boundary.
from .crypto_trust import (
    PURPOSE_ACTION_APPROVAL,
    PURPOSE_ANCHOR_QUORUM_POLICY,
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_POLICY_HEAD_AUTHORITY,
    PURPOSE_POLICY_TRANSPARENCY_WITNESS,
    PURPOSE_STATE_WITNESS,
    SIGNED_CONTRACT_ENVELOPE_ID,
    TRUST_KEY_RECORD_CONTRACT_ID,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    authorize_authenticated_action,
    validate_authenticated_authorization,
)

__all__ += [
    "AuthenticatedSQLiteExecutionLedger",
    "PURPOSE_ACTION_APPROVAL",
    "PURPOSE_ANCHOR_QUORUM_POLICY",
    "PURPOSE_ASSURANCE_ATTESTATION",
    "PURPOSE_AUTHORIZATION_TOKEN",
    "PURPOSE_EXECUTION_RECEIPT",
    "PURPOSE_POLICY_BUNDLE",
    "PURPOSE_POLICY_HEAD_AUTHORITY",
    "PURPOSE_POLICY_TRANSPARENCY_WITNESS",
    "PURPOSE_STATE_WITNESS",
    "SIGNED_CONTRACT_ENVELOPE_ID",
    "TRUST_KEY_RECORD_CONTRACT_ID",
    "TrustKeyRegistry",
    "authorize_authenticated_action",
    "generate_ed25519_keypair",
    "make_trust_key_record",
    "sign_contract_envelope",
    "validate_authenticated_authorization",
    "verify_contract_envelope",
]

# TRIAXIS v3.7 monotonic root-signed trust registry.
from .trust_registry_state import (
    SQLiteTrustRegistryStore,
    TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID,
    TrustRegistryStateError,
    make_trust_registry_snapshot,
    validate_trust_registry_snapshot,
)

__all__ += [
    "SQLiteTrustRegistryStore",
    "TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID",
    "TrustRegistryStateError",
    "make_trust_registry_snapshot",
    "validate_trust_registry_snapshot",
]

# TRIAXIS v3.8 external registry head witness.
from .trust_registry_anchor import (
    SQLiteAnchorChallengeLedger,
    TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID,
    TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID,
    TrustRegistryAnchorError,
    load_registry_with_challenge_bound_anchor,
    load_registry_with_external_anchor,
    make_challenge_bound_head_witness,
    make_trust_registry_head_witness,
    validate_challenge_bound_head_witness,
    validate_trust_registry_head_witness,
)

__all__ += [
    "SQLiteAnchorChallengeLedger",
    "TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID",
    "TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID",
    "TrustRegistryAnchorError",
    "load_registry_with_challenge_bound_anchor",
    "load_registry_with_external_anchor",
    "make_challenge_bound_head_witness",
    "make_trust_registry_head_witness",
    "validate_challenge_bound_head_witness",
    "validate_trust_registry_head_witness",
]

# TRIAXIS v3.10 verifier epoch and distinct-anchor quorum.
from .trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    TRUST_REGISTRY_POLICY_BOUND_QUORUM_WITNESS_CONTRACT_ID,
    TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID,
    VerifierFreshnessSession,
    load_registry_with_managed_quorum_policy,
    load_registry_with_quorum_anchors,
    make_policy_bound_quorum_witness,
    make_quorum_member_witness,
    validate_policy_bound_quorum_witness,
    validate_quorum_member_witness,
)
from .anchor_quorum_policy import (
    ANCHOR_QUORUM_POLICY_CONTRACT_ID,
    SQLiteAnchorQuorumPolicyStore,
    make_anchor_quorum_policy,
    validate_anchor_quorum_policy,
)

__all__ += [
    "ANCHOR_QUORUM_POLICY_CONTRACT_ID",
    "SQLiteAnchorQuorumPolicyStore",
    "SQLiteEpochChallengeLedger",
    "TRUST_REGISTRY_POLICY_BOUND_QUORUM_WITNESS_CONTRACT_ID",
    "TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID",
    "VerifierFreshnessSession",
    "load_registry_with_managed_quorum_policy",
    "load_registry_with_quorum_anchors",
    "make_anchor_quorum_policy",
    "make_policy_bound_quorum_witness",
    "make_quorum_member_witness",
    "validate_anchor_quorum_policy",
    "validate_policy_bound_quorum_witness",
    "validate_quorum_member_witness",
]


# TRIAXIS v3.12 external policy-head freshness authority.
from .policy_head_authority import (
    POLICY_HEAD_RESPONSE_CONTRACT_ID,
    PolicyHeadAuthorityError,
    SQLitePolicyHeadAuthorityService,
    load_policy_with_external_head,
    make_policy_head_response,
    validate_policy_head_response,
)

__all__ += [
    "POLICY_HEAD_RESPONSE_CONTRACT_ID",
    "PolicyHeadAuthorityError",
    "SQLitePolicyHeadAuthorityService",
    "load_policy_with_external_head",
    "make_policy_head_response",
    "validate_policy_head_response",
]

from .policy_head_http import PolicyHeadHTTPApplication, build_http_server
__all__ += ["PolicyHeadHTTPApplication", "build_http_server"]


# TRIAXIS v3.13 distinct Policy Head Authority quorum.
from .policy_head_quorum import (
    POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID,
    load_policy_with_external_head_quorum,
    make_policy_head_quorum_config,
    validate_policy_head_quorum_config,
)
__all__ += [
    "POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID",
    "load_policy_with_external_head_quorum",
    "make_policy_head_quorum_config",
    "validate_policy_head_quorum_config",
]

# TRIAXIS v3.14 independent policy-transparency floor quorum.
from .policy_transparency_floor import (
    POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID,
    POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID,
    SQLitePolicyTransparencyWitnessService,
    enforce_policy_transparency_floor_quorum,
    make_policy_transparency_floor_quorum_config,
    make_policy_transparency_floor_response,
    validate_policy_transparency_floor_quorum_config,
    validate_policy_transparency_floor_response,
)

__all__ += [
    "POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID",
    "POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID",
    "SQLitePolicyTransparencyWitnessService",
    "enforce_policy_transparency_floor_quorum",
    "make_policy_transparency_floor_quorum_config",
    "make_policy_transparency_floor_response",
    "validate_policy_transparency_floor_quorum_config",
    "validate_policy_transparency_floor_response",
]
