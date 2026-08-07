"""TRIAXIS v4.0 Authorization Request & AuthZEN-Compatible Adapter Contract (PI-001)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .compound_principal import CompoundPrincipal


@dataclass(frozen=True)
class AuthorizationRequest:
    """Internal TRIAXIS Authorization Request carrying typed compound principal and context."""

    principal: CompoundPrincipal
    policy_id: str
    risk_class: str = "R1"
    context_data: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.principal, CompoundPrincipal):
            raise ValueError("principal must be an instance of CompoundPrincipal")
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ValueError("policy_id must be a non-empty string")

    def to_authzen_payload(self) -> dict[str, Any]:
        """Convert internal AuthorizationRequest into OpenID AuthZEN-compatible REST JSON payload format.

        Classification: AUTHZEN_COMPATIBLE_ADAPTER
        """
        ctx = dict(self.context_data) if self.context_data else {}
        ctx.update({
            "human_id": self.principal.human_id,
            "agent_instance_id": self.principal.agent_instance_id,
            "delegation_grant_id": self.principal.delegation_grant_id,
            "task_id": self.principal.task_id,
            "request_id": self.principal.request_id,
            "risk_class": self.risk_class,
            "policy_id": self.policy_id,
            "identity_provenance": self.principal.identity_provenance,
        })
        if self.principal.spiffe_id:
            ctx["spiffe_id"] = self.principal.spiffe_id

        return {
            "subject": {
                "type": "CompoundPrincipal",
                "id": f"user:{self.principal.human_id}",
                "properties": {
                    "human_id": self.principal.human_id,
                    "agent_instance_id": self.principal.agent_instance_id,
                    "delegation_grant_id": self.principal.delegation_grant_id,
                }
            },
            "action": {
                "name": self.principal.action,
                "properties": {"task_id": self.principal.task_id}
            },
            "resource": {
                "type": "TRIAXISResource",
                "id": self.principal.resource,
                "properties": {}
            },
            "context": ctx
        }
