"""TRIAXIS PI-002 WorkloadIdentityProvider Abstraction Interface & Trusted Registry."""

from __future__ import annotations

import hashlib
from typing import Any, Protocol

from .contract import VerifiedWorkloadIdentity


class WorkloadIdentityProvider(Protocol):
    """Canonical interface for cryptographically-backed workload identity providers."""

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        """Fetch X509-SVID runtime evidence and return verified workload identity object."""
        ...


class TrustedWorkloadIdentityProviderRegistry:
    """Trusted runtime configuration registry for WorkloadIdentityProvider instances."""

    def __init__(self, allow_test_mocks: bool = False) -> None:
        self._registered_providers: dict[str, WorkloadIdentityProvider] = {}
        self._provider_configs: dict[str, dict[str, Any]] = {}
        self._allow_test_mocks = allow_test_mocks

    def register_provider(
        self,
        provider_id: str,
        provider: WorkloadIdentityProvider,
        provider_type: str = "spiffe_workload",
        expected_trust_domain: str = "triaxis.local",
        socket_path: str = "/tmp/spire-agent/public/api.sock",
        mapping_sha256: str = "",
    ) -> str:
        """Register a trusted workload identity provider and compute configuration digest."""
        config_payload = f"{provider_id}:{provider_type}:{expected_trust_domain}:{socket_path}:{mapping_sha256}"
        config_sha256 = hashlib.sha256(config_payload.encode("utf-8")).hexdigest()

        self._registered_providers[provider_id] = provider
        self._provider_configs[provider_id] = {
            "provider_id": provider_id,
            "provider_type": provider_type,
            "expected_trust_domain": expected_trust_domain,
            "socket_path": socket_path,
            "mapping_sha256": mapping_sha256,
            "provider_config_sha256": config_sha256,
        }
        return config_sha256

    def is_provider_trusted(self, provider_id: str, provider_obj: Any) -> bool:
        """Verify if provider instance and provider_id match a registered trusted provider."""
        if provider_id not in self._registered_providers:
            return False
        trusted_obj = self._registered_providers[provider_id]
        if trusted_obj is not provider_obj:
            return False
        if not self._allow_test_mocks:
            from .spiffe_provider import SpiffeWorkloadIdentityProvider
            if not isinstance(provider_obj, SpiffeWorkloadIdentityProvider):
                return False
        return True

    def get_provider_config(self, provider_id: str) -> dict[str, Any] | None:
        """Retrieve registered configuration metadata for provider."""
        return self._provider_configs.get(provider_id)
