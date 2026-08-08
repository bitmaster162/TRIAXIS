"""TRIAXIS v4.0 Canonical Policy Enforcement Point (PEP) with Receipt Correlation Verification (PI-001 R2).

Responsibilities:
1. Accept typed AuthorizationRequest
2. Invoke configured PDP adapter
3. Perform strict PEP Receipt Correlation Verification
4. Convert decision into effect permission (Fail-closed: ONLY VERIFIED ALLOW => EFFECT MAY CONTINUE)
5. Emit decision receipt audit trail
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from .contract import AuthorizationRequest
from .decision import AuthorizationDecisionReceipt, DecisionState


class PDPAdapterProtocol(Protocol):
    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        ...


class PolicyEnforcementPoint:
    """Canonical Policy Enforcement Point (PEP) gating bounded effect paths."""

    def __init__(self, pdp_adapter: PDPAdapterProtocol | None = None) -> None:
        self.pdp_adapter = pdp_adapter
        self._last_receipt: AuthorizationDecisionReceipt | None = None

    def evaluate_request(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        """Enforce authorization request against configured PDP with strict receipt correlation verification."""
        if not isinstance(request, AuthorizationRequest):
            raise ValueError("request must be an instance of AuthorizationRequest")

        now_iso = datetime.now(timezone.utc).isoformat()

        if self.pdp_adapter is None:
            receipt = AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="PEP_PDP_ADAPTER_UNCONFIGURED",
                policy_version=1,
                triaxis_policy_sha256=request.triaxis_policy_sha256 or ("0" * 64),
                cedar_policy_sha256=request.cedar_policy_sha256 or ("0" * 64),
                provider="PEP",
                provider_version="4.0.0",
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class="UnconfiguredPDPAdapterError",
            )
            self._last_receipt = receipt
            return receipt

        try:
            receipt = self.pdp_adapter.evaluate(request)
        except Exception as exc:
            receipt = AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="PEP_ADAPTER_INVOCATION_EXCEPTION",
                policy_version=1,
                triaxis_policy_sha256=request.triaxis_policy_sha256 or ("0" * 64),
                cedar_policy_sha256=request.cedar_policy_sha256 or ("0" * 64),
                provider="PEP",
                provider_version="4.0.0",
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class=type(exc).__name__,
            )

        # PEP Receipt Correlation Verification (Section 4)
        if receipt.decision == DecisionState.ALLOW:
            p = receipt.evaluated_principal
            mismatches = []
            if receipt.request_id != request.principal.request_id:
                mismatches.append(f"request_id: expected {request.principal.request_id!r}, got {receipt.request_id!r}")
            if p.get("human_id") != request.principal.human_id:
                mismatches.append(f"human_id: expected {request.principal.human_id!r}, got {p.get('human_id')!r}")
            if p.get("agent_instance_id") != request.principal.agent_instance_id:
                mismatches.append(f"agent_instance_id: expected {request.principal.agent_instance_id!r}, got {p.get('agent_instance_id')!r}")
            if p.get("delegation_grant_id") != request.principal.delegation_grant_id:
                mismatches.append(f"delegation_grant_id: expected {request.principal.delegation_grant_id!r}, got {p.get('delegation_grant_id')!r}")
            if p.get("task_id") != request.principal.task_id:
                mismatches.append(f"task_id: expected {request.principal.task_id!r}, got {p.get('task_id')!r}")
            if p.get("action") != request.principal.action or receipt.evaluated_action != request.principal.action:
                mismatches.append(f"action: expected {request.principal.action!r}, got {receipt.evaluated_action!r}")
            if p.get("resource") != request.principal.resource or receipt.evaluated_resource != request.principal.resource:
                mismatches.append(f"resource: expected {request.principal.resource!r}, got {receipt.evaluated_resource!r}")
            if request.cedar_policy_sha256 and receipt.cedar_policy_sha256 != request.cedar_policy_sha256:
                mismatches.append(f"cedar_policy_sha256: expected {request.cedar_policy_sha256!r}, got {receipt.cedar_policy_sha256!r}")

            if mismatches:
                receipt = AuthorizationDecisionReceipt(
                    decision=DecisionState.ERROR,
                    reason_code="PDP_RECEIPT_CORRELATION_FAILURE",
                    policy_version=receipt.policy_version,
                    triaxis_policy_sha256=receipt.triaxis_policy_sha256,
                    cedar_policy_sha256=receipt.cedar_policy_sha256,
                    provider=receipt.provider,
                    provider_version=receipt.provider_version,
                    request_id=request.principal.request_id,
                    evaluated_principal=request.principal.to_dict(),
                    evaluated_task=request.principal.task_id,
                    evaluated_action=request.principal.action,
                    evaluated_resource=request.principal.resource,
                    evaluation_timestamp_iso=now_iso,
                    error_class="PEPReceiptCorrelationError",
                )

        self._last_receipt = receipt
        return receipt

    @property
    def last_receipt(self) -> AuthorizationDecisionReceipt | None:
        return self._last_receipt
