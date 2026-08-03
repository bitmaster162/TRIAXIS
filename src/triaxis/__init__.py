"""Deterministic governance-gate projection for TRIAXIS.

This package does not implement the generative Audit/Devil/Angel/Synthesizer
passes. It implements only machine-checkable routing, authority, integrity,
and execution gates for validation purposes.
"""

from .input_contract import INPUT_CONTRACT_ID, schema_document, validate_scenario
from .projection import evaluate_candidate, supported_versions

__all__ = [
    "INPUT_CONTRACT_ID",
    "evaluate_candidate",
    "schema_document",
    "supported_versions",
    "validate_scenario",
]
