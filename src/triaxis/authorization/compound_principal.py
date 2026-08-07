"""TRIAXIS v4.0 Typed Compound Principal Model (PI-001).

Implements: HUMAN x AGENT_INSTANCE x DELEGATION_GRANT x TASK
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CompoundPrincipal:
    """Typed compound principal representing four-dimensional identity and task context."""

    human_id: str
    agent_instance_id: str
    delegation_grant_id: str
    task_id: str
    action: str
    resource: str
    identity_provenance: dict[str, Any]
    request_id: str
    spiffe_id: str | None = None

    def __post_init__(self) -> None:
        errors = []
        for field_name in ("human_id", "agent_instance_id", "delegation_grant_id", "task_id", "action", "resource", "request_id"):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"{field_name} must be a non-empty string")
        if not isinstance(self.identity_provenance, dict):
            errors.append("identity_provenance must be a dictionary")
        if self.spiffe_id is not None and (not isinstance(self.spiffe_id, str) or not self.spiffe_id.strip()):
            errors.append("spiffe_id must be None or a non-empty string")
        if errors:
            raise ValueError(f"Invalid CompoundPrincipal: {'; '.join(errors)}")

    def to_dict(self) -> dict[str, Any]:
        res = {
            "human_id": self.human_id,
            "agent_instance_id": self.agent_instance_id,
            "delegation_grant_id": self.delegation_grant_id,
            "task_id": self.task_id,
            "action": self.action,
            "resource": self.resource,
            "identity_provenance": dict(self.identity_provenance),
            "request_id": self.request_id,
        }
        if self.spiffe_id is not None:
            res["spiffe_id"] = self.spiffe_id
        return res

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompoundPrincipal:
        if not isinstance(data, dict):
            raise ValueError("Input data must be a dictionary")
        return cls(
            human_id=str(data.get("human_id", "")),
            agent_instance_id=str(data.get("agent_instance_id", "")),
            delegation_grant_id=str(data.get("delegation_grant_id", "")),
            task_id=str(data.get("task_id", "")),
            action=str(data.get("action", "")),
            resource=str(data.get("resource", "")),
            identity_provenance=dict(data.get("identity_provenance", {})),
            request_id=str(data.get("request_id", "")),
            spiffe_id=data.get("spiffe_id"),
        )
