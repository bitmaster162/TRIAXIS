"""TRIAXIS v4.0 Canonical Policy Enforcement Point (PEP) (PI-001).

Responsibilities:
1. Accept typed AuthorizationRequest
2. Invoke configured PDP adapter
3. Validate decision receipt
4. Convert decision into effect permission (Fail-closed: ONLY VERIFIED ALLOW => EFFECT MAY CONTINUE)
5. Emit decision receipt audit trail
"""

from __future__ import annotations

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
        """Enforce authorization request against configured PDP. Fail closed if PDP is missing or errors."""
        if not isinstance(request, AuthorizationRequest):
            raise ValueError("request must be an instance of AuthorizationRequest")

        if self.pdp_adapter is None:
            # Missing PDP adapter -> Fail Closed ERROR
            from datetime import datetime, timezone
            receipt = AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="PEP_PDP_ADAPTER_UNCONFIGURED",
                policy_version=1,
                policy_hash="0" * 64,
                provider="PEP",
                provider_version="4.0.0",
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
                error_class="UnconfiguredPDPAdapterError",
            )
            self._last_receipt = receipt
            return receipt

        try:
            receipt = self.pdp_adapter.evaluate(request)
        except Exception as exc:
            from datetime import datetime, timezone
            receipt = AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="PEP_ADAPTER_INVOCATION_EXCEPTION",
                policy_version=1,
                policy_hash="0" * 64,
                provider="PEP",
                provider_version="4.0.0",
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
                error_class=type(exc).__name__,
            )

        self._last_receipt = receipt
        return receipt

    @property
    def last_receipt(self) -> AuthorizationDecisionReceipt | None:
        return self._last_receipt
