"""Deterministic governance-gate projection for TRIAXIS.

This package does not implement the generative Audit/Devil/Angel/Synthesizer
passes. It implements only machine-checkable routing, authority, integrity,
and execution gates for validation purposes.
"""

from .projection import evaluate_candidate, supported_versions

__all__ = ["evaluate_candidate", "supported_versions"]
