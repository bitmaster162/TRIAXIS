"""Semantic routing and X0 decision-gate templates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from validation.framework.case_bank import base_case


def _scenario(action: str, x_level: int, **changes: Any) -> Dict[str, Any]:
    row = base_case()
    row.update(
        declared_action_type=action,
        x_level=x_level,
        e_level=max(row["e_level"], 1),
    )
    row.update(changes)
    return row


def _exact(
    name: str,
    family: str,
    scenario: Dict[str, Any],
    status: str,
    reason: str,
) -> Dict[str, Any]:
    return {
        "template_name": name,
        "family": family,
        "scenario": deepcopy(scenario),
        "expected_status": status,
        "expected_reason": reason,
    }


def templates() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    minimum_x = {
        "WRITE": 1,
        "EXECUTE": 1,
        "DELETE": 1,
        "SEND": 2,
        "PUBLISH": 2,
        "DEPLOY": 2,
        "SPEND": 3,
        "TRADE": 3,
        "MODIFY_ACCESS": 3,
        "HANDLE_SECRETS": 3,
    }
    for action, lower_bound in minimum_x.items():
        for routed_x in range(lower_bound):
            rows.append(
                _exact(
                    f"underclassified_{action.lower()}_x{routed_x}",
                    "action_risk_lower_bound",
                    _scenario(action, routed_x),
                    "BLOCK",
                    "BLOCKED_BY_INPUT_CONTRACT",
                )
            )

    # Positive controls at each conservative lower bound.
    for action, lower_bound in minimum_x.items():
        rows.append(
            _exact(
                f"minimum_valid_{action.lower()}_x{lower_bound}",
                "action_risk_positive",
                _scenario(action, lower_bound),
                "ALLOW",
                "CONDITIONS_SATISFIED",
            )
        )

    x0 = _scenario("ANALYZE", 0)

    rows.extend(
        [
            _exact(
                "x0_stale_target_binding",
                "x0_binding",
                _scenario("ANALYZE", 0, target_binding_required=True, target_digest_match=False),
                "BLOCK",
                "BLOCKED_BY_STALE_BINDING",
            ),
            _exact(
                "x0_stale_object_binding",
                "x0_binding",
                _scenario("ANALYZE", 0, object_binding_required=True, object_binding_current=False),
                "BLOCK",
                "BLOCKED_BY_STALE_BINDING",
            ),
            _exact(
                "x0_failed_precondition",
                "x0_precondition",
                _scenario("ANALYZE", 0, preconditions_required=True, preconditions_pass=False),
                "BLOCK",
                "BLOCKED_BY_PRECONDITION",
            ),
            _exact(
                "x0_verification_failed",
                "x0_verification",
                _scenario("ANALYZE", 0, verification_required=True, verification_status="FAILED"),
                "BLOCK",
                "BLOCKED_BY_VERIFICATION",
            ),
            _exact(
                "x0_verification_not_run",
                "x0_verification",
                _scenario("ANALYZE", 0, verification_required=True, verification_status="NOT_RUN"),
                "BLOCK",
                "BLOCKED_BY_VERIFICATION",
            ),
            _exact(
                "x0_verification_inconclusive",
                "x0_verification",
                _scenario("ANALYZE", 0, verification_required=True, verification_status="INCONCLUSIVE"),
                "BLOCK",
                "BLOCKED_BY_VERIFICATION",
            ),
            _exact(
                "x0_verification_scope_inadequate",
                "x0_verification",
                _scenario(
                    "ANALYZE",
                    0,
                    verification_required=True,
                    verification_status="VERIFIED_WITHIN_SCOPE",
                    verified_scope_adequate=False,
                ),
                "BLOCK",
                "BLOCKED_BY_VERIFICATION",
            ),
            _exact(
                "x0_budget_exhausted",
                "x0_budget",
                _scenario("ANALYZE", 0, budget_gate_required=True, budget_status="EXHAUSTED"),
                "BLOCK",
                "BLOCKED_BY_BUDGET",
            ),
            _exact(
                "x0_budget_undefined",
                "x0_budget",
                _scenario("ANALYZE", 0, budget_gate_required=True, budget_status="UNDEFINED"),
                "BLOCK",
                "BLOCKED_BY_BUDGET",
            ),
            _exact(
                "x0_policy_limited",
                "x0_limit_propagation",
                _scenario("ANALYZE", 0, policy_status="ALLOW_WITH_LIMITS"),
                "ALLOW_WITH_LIMITS",
                "POLICY_LIMITS_APPLY",
            ),
            _exact(
                "x0_reliance_limited",
                "x0_limit_propagation",
                _scenario(
                    "ANALYZE",
                    0,
                    e_level=3,
                    downstream_reliance_material=True,
                    reliance_conditions_satisfied=False,
                ),
                "ALLOW_WITH_LIMITS",
                "RELIANCE_RESTRICTIONS_REQUIRED",
            ),
            _exact(
                "x0_reliance_cannot_mask_verification",
                "x0_blocker_precedence",
                _scenario(
                    "ANALYZE",
                    0,
                    e_level=3,
                    downstream_reliance_material=True,
                    reliance_conditions_satisfied=False,
                    verification_required=True,
                    verification_status="FAILED",
                ),
                "BLOCK",
                "BLOCKED_BY_VERIFICATION",
            ),
            _exact(
                "x0_reliance_cannot_mask_budget",
                "x0_blocker_precedence",
                _scenario(
                    "ANALYZE",
                    0,
                    e_level=3,
                    downstream_reliance_material=True,
                    reliance_conditions_satisfied=False,
                    budget_gate_required=True,
                    budget_status="EXHAUSTED",
                ),
                "BLOCK",
                "BLOCKED_BY_BUDGET",
            ),
            _exact(
                "x0_verified_positive",
                "x0_positive",
                _scenario(
                    "ANALYZE",
                    0,
                    verification_required=True,
                    verification_status="VERIFIED_WITHIN_SCOPE",
                    verified_scope_adequate=True,
                ),
                "ALLOW",
                "CONDITIONS_SATISFIED",
            ),
            _exact(
                "x0_bindings_positive",
                "x0_positive",
                _scenario(
                    "ANALYZE",
                    0,
                    target_binding_required=True,
                    target_digest_match=True,
                    object_binding_required=True,
                    object_binding_current=True,
                    preconditions_required=True,
                    preconditions_pass=True,
                ),
                "ALLOW",
                "CONDITIONS_SATISFIED",
            ),
            _exact(
                "x0_budget_positive",
                "x0_positive",
                _scenario("ANALYZE", 0, budget_gate_required=True, budget_status="WITHIN_LIMIT"),
                "ALLOW",
                "CONDITIONS_SATISFIED",
            ),
        ]
    )

    # Deterministic invariance controls: metadata must not alter the decision.
    for index in range(6):
        variant = deepcopy(x0)
        variant.update(
            nonce=50_000 + index,
            target_alias=f"routing-alias-{index}",
            environment_alias=f"routing-env-{index}",
            prose_hint=f"presentation-only-{index}",
        )
        rows.append(
            _exact(
                f"x0_metadata_invariance_{index}",
                "metadata_invariance",
                variant,
                "ALLOW",
                "CONDITIONS_SATISFIED",
            )
        )

    return rows
