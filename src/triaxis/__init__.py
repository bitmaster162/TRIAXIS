"""Deterministic governance-gate projection for TRIAXIS.

This package does not implement the generative Audit/Devil/Angel/Synthesizer
passes. It implements machine-checkable structured-input, semantic-ingress,
routing, authority, integrity, and execution gates for validation purposes.
"""

from .input_contract import INPUT_CONTRACT_ID, schema_document, validate_scenario
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
    "SEMANTIC_INGRESS_CONTRACT_ID",
    "evaluate_candidate",
    "evaluate_ingress",
    "scan_control_surface",
    "schema_document",
    "semantic_ingress_schema_document",
    "supported_versions",
    "validate_ingress",
    "validate_scenario",
]
