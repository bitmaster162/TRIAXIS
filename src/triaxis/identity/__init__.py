"""TRIAXIS PI-002 Cryptographically-Backed Workload Identity Package."""

from .contract import WORKLOAD_IDENTITY_CONTRACT_ID, VerifiedWorkloadIdentity, validate_verified_workload_identity
from .mapping import SpiffeAgentMapping
from .provider import WorkloadIdentityProvider
from .spiffe_provider import SpiffeWorkloadIdentityProvider

__all__ = [
    "WORKLOAD_IDENTITY_CONTRACT_ID",
    "VerifiedWorkloadIdentity",
    "validate_verified_workload_identity",
    "SpiffeAgentMapping",
    "WorkloadIdentityProvider",
    "SpiffeWorkloadIdentityProvider",
]
