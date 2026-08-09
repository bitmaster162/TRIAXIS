"""TRIAXIS PI-002 Explicit SPIFFE-ID -> Agent Instance Mapping Configuration."""

from __future__ import annotations

from typing import Any, Mapping

from triaxis.integrity import canonical_sha256

SPIFFE_MAPPING_CONTRACT_ID = "TRIAXIS_SPIFFE_AGENT_MAPPING_v1"


class SpiffeAgentMapping:
    """Explicit, canonical versioned mapping from SPIFFE IDs to agent_instance_ids."""

    def __init__(self, mapping: Mapping[str, str], version: int = 1) -> None:
        self._raw_mapping = dict(mapping)
        self.version = version
        self.contract_id = SPIFFE_MAPPING_CONTRACT_ID

        # Canonical SHA-256 hash of mapping configuration
        mapping_repr = {
            "contract_id": self.contract_id,
            "version": self.version,
            "mapping": sorted(self._raw_mapping.items()),
        }
        self.identity_mapping_sha256 = canonical_sha256(mapping_repr)

    def resolve_agent_instance_id(self, spiffe_id: str) -> str | None:
        """Resolve a SPIFFE ID to its explicitly configured agent_instance_id."""
        if not isinstance(spiffe_id, str):
            return None
        return self._raw_mapping.get(spiffe_id.strip())

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "version": self.version,
            "mapping": dict(self._raw_mapping),
            "identity_mapping_sha256": self.identity_mapping_sha256,
        }
