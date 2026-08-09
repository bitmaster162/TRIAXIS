"""TRIAXIS PI-002 WorkloadIdentityProvider abstraction and trusted registry."""

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
    """Registry that binds a provider object to the configuration it was approved with."""

    def __init__(self, allow_test_mocks: bool = False) -> None:
        self._registered_providers: dict[str, WorkloadIdentityProvider] = {}
        self._provider_configs: dict[str, dict[str, Any]] = {}
        self._allow_test_mocks = allow_test_mocks

    def register_provider(
        self,
        provider_id: str,
        provider: WorkloadIdentityProvider,
        provider_type: str = "spiffe_workload",
        expected_trust_domain: str | None = "triaxis.local",
        socket_path: str | None = None,
        mapping_sha256: str | None = None,
    ) -> str:
        """Register a provider and seal its effective runtime configuration."""
        actual_trust_domain = getattr(provider, "expected_trust_domain", None)
        actual_socket_path = getattr(provider, "socket_path", None)
        actual_mapping = getattr(provider, "mapping", None)
        actual_mapping_sha256 = getattr(actual_mapping, "identity_mapping_sha256", None)

        effective_trust_domain = expected_trust_domain or actual_trust_domain or "triaxis.local"
        effective_socket_path = socket_path or actual_socket_path or "/tmp/spire-agent/public/api.sock"
        effective_mapping_sha256 = mapping_sha256 or actual_mapping_sha256 or ""

        if actual_trust_domain is not None and actual_trust_domain != effective_trust_domain:
            raise ValueError("provider trust domain does not match registry configuration")
        if actual_socket_path is not None and actual_socket_path != effective_socket_path:
            raise ValueError("provider socket path does not match registry configuration")
        if actual_mapping_sha256 is not None and actual_mapping_sha256 != effective_mapping_sha256:
            raise ValueError("provider mapping hash does not match registry configuration")

        config_payload = (
            f"{provider_id}:{provider_type}:{effective_trust_domain}:"
            f"{effective_socket_path}:{effective_mapping_sha256}"
        )
        config_sha256 = hashlib.sha256(config_payload.encode("utf-8")).hexdigest()

        self._registered_providers[provider_id] = provider
        self._provider_configs[provider_id] = {
            "provider_id": provider_id,
            "provider_type": provider_type,
            "expected_trust_domain": effective_trust_domain,
            "socket_path": effective_socket_path,
            "mapping_sha256": effective_mapping_sha256,
            "provider_config_sha256": config_sha256,
        }
        return config_sha256

    def is_provider_trusted(self, provider_id: str, provider_obj: Any) -> bool:
        """Require object identity, provider type, and current config to match registration."""
        trusted_obj = self._registered_providers.get(provider_id)
        config = self._provider_configs.get(provider_id)
        if trusted_obj is None or config is None or trusted_obj is not provider_obj:
            return False

        if not self._allow_test_mocks:
            from .spiffe_provider import SpiffeWorkloadIdentityProvider

            if not isinstance(provider_obj, SpiffeWorkloadIdentityProvider):
                return False

        actual_mapping = getattr(provider_obj, "mapping", None)
        actual_mapping_sha256 = getattr(actual_mapping, "identity_mapping_sha256", None)

        if getattr(provider_obj, "expected_trust_domain", None) != config["expected_trust_domain"]:
            return False
        if getattr(provider_obj, "socket_path", None) != config["socket_path"]:
            return False
        if (actual_mapping_sha256 or "") != config["mapping_sha256"]:
            return False
        return True

    def get_provider_config(self, provider_id: str) -> dict[str, Any] | None:
        """Retrieve registered configuration metadata for provider."""
        config = self._provider_configs.get(provider_id)
        return dict(config) if config is not None else None
