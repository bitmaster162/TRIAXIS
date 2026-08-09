"""TRIAXIS PI-002 Verified Workload Identity Contract Definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

WORKLOAD_IDENTITY_CONTRACT_ID = "TRIAXIS_VERIFIED_WORKLOAD_IDENTITY_v1"


@dataclass(frozen=True)
class VerifiedWorkloadIdentity:
    """Immutable representation of cryptographically-verified workload identity evidence."""

    agent_instance_id: str
    spiffe_id: str
    trust_domain: str
    identity_provider: str
    certificate_fingerprint_sha256: str
    not_before_iso: str
    not_after_iso: str
    verification_status: str  # "VERIFIED", "DENIED", "ERROR"
    verification_reason: str
    identity_mapping_sha256: str
    request_id: str = ""
    contract_id: str = WORKLOAD_IDENTITY_CONTRACT_ID

    def to_dict(self) -> dict[str, Any]:
        """Convert to canonical serializable dictionary."""
        return {
            "contract_id": self.contract_id,
            "agent_instance_id": self.agent_instance_id,
            "spiffe_id": self.spiffe_id,
            "trust_domain": self.trust_domain,
            "identity_provider": self.identity_provider,
            "certificate_fingerprint_sha256": self.certificate_fingerprint_sha256,
            "not_before_iso": self.not_before_iso,
            "not_after_iso": self.not_after_iso,
            "verification_status": self.verification_status,
            "verification_reason": self.verification_reason,
            "identity_mapping_sha256": self.identity_mapping_sha256,
            "request_id": self.request_id,
        }


def validate_verified_workload_identity(value: Any) -> dict[str, Any]:
    """Validate structure and fields of a verified workload identity record."""
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "workload_identity", "message": "object required"}]}

    d = dict(value)
    if d.get("contract_id") != WORKLOAD_IDENTITY_CONTRACT_ID:
        errors.append({"code": "invalid_contract_id", "path": "workload_identity.contract_id", "message": f"expected {WORKLOAD_IDENTITY_CONTRACT_ID}"})

    for field in ("agent_instance_id", "spiffe_id", "trust_domain", "identity_provider", "verification_status", "verification_reason", "identity_mapping_sha256"):
        if not isinstance(d.get(field), str) or not d.get(field):
            errors.append({"code": "missing_required", "path": f"workload_identity.{field}", "message": f"{field} required"})

    if d.get("verification_status") not in ("VERIFIED", "DENIED", "ERROR"):
        errors.append({"code": "invalid_status", "path": "workload_identity.verification_status", "message": "status must be VERIFIED, DENIED, or ERROR"})

    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "identity": d if not errors else None,
    }
