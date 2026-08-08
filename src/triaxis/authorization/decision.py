"""TRIAXIS v4.0 Authorization Decision & Receipt Model (PI-001)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .compound_principal import CompoundPrincipal


class DecisionState(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"


@dataclass(frozen=True)
class AuthorizationDecisionReceipt:
    """Explicit Authorization Decision Receipt carrying evaluation telemetry and security evidence."""

    decision: DecisionState
    reason_code: str
    policy_version: int
    policy_hash: str
    provider: str
    provider_version: str
    request_id: str
    evaluated_principal: dict[str, Any]
    evaluated_task: str
    evaluated_action: str
    evaluated_resource: str
    evaluation_timestamp_iso: str
    error_class: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, DecisionState):
            raise ValueError("decision must be an instance of DecisionState")
        if not isinstance(self.reason_code, str) or not self.reason_code.strip():
            raise ValueError("reason_code must be a non-empty string")
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string")
        if not (self.evaluation_timestamp_iso.endswith("Z") or "+" in self.evaluation_timestamp_iso or "-" in self.evaluation_timestamp_iso[10:]):
            raise ValueError("evaluation_timestamp_iso must carry an explicit timezone suffix (Z or +HH:MM)")

    @property
    def is_verified_allow(self) -> bool:
        """Effect permission condition: ONLY VERIFIED ALLOW => EFFECT MAY CONTINUE."""
        return self.decision == DecisionState.ALLOW

    @property
    def decision_sha256(self) -> str:
        """Return the canonical SHA-256 digest of this decision receipt."""
        from ..integrity import canonical_sha256
        data = {
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "request_id": self.request_id,
            "evaluated_principal": dict(self.evaluated_principal),
            "evaluated_task": self.evaluated_task,
            "evaluated_action": self.evaluated_action,
            "evaluated_resource": self.evaluated_resource,
            "evaluation_timestamp_iso": self.evaluation_timestamp_iso,
            "error_class": self.error_class,
        }
        return canonical_sha256(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "provider": self.provider,
            "provider_version": self.provider_version,
            "request_id": self.request_id,
            "evaluated_principal": dict(self.evaluated_principal),
            "evaluated_task": self.evaluated_task,
            "evaluated_action": self.evaluated_action,
            "evaluated_resource": self.evaluated_resource,
            "evaluation_timestamp_iso": self.evaluation_timestamp_iso,
            "error_class": self.error_class,
            "is_verified_allow": self.is_verified_allow,
            "decision_sha256": self.decision_sha256,
        }
