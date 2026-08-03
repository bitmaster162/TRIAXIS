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
    scan_control_surface,
    schema_document as semantic_ingress_schema_document,
    validate_ingress,
)

__all__ = [
    "ACTION_MINIMUM_X",
    "INPUT_CONTRACT_ID",
    "INPUT_CONTRACT_V1_ID",
    "INPUT_CONTRACT_V2_ID",
    "SEMANTIC_INGRESS_CONTRACT_ID",
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
    "validate_scenario",
    "validate_scenario_v1",
    "validate_scenario_v2",
]
