"""TRIAXIS PI-002 WorkloadIdentityProvider Abstraction Interface."""

from __future__ import annotations

from typing import Protocol

from .contract import VerifiedWorkloadIdentity


class WorkloadIdentityProvider(Protocol):
    """Canonical interface for cryptographically-backed workload identity providers."""

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        """Fetch X509-SVID runtime evidence and return verified workload identity object."""
        ...
