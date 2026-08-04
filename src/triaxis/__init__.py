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
