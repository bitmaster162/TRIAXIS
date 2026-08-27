"""TRIAXIS v3.32 terminal local-reference external-effect guard.

The legacy v3.32 helper remains available for compatibility, but its caller-
supplied boolean authorization and prior-guard result are not cryptographic
action authority. ``verify_authenticated_terminal_external_effect_guard`` is
the RHE R1 composition boundary that closes those two substitution surfaces for
the authenticated reference path.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .authenticated_action_assurance import (
    validate_authenticated_authorization,
    validate_authenticated_risk_mediation,
)
from .completion_availability_control import (
    verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor,
)
from .completion_transparency_quorum import verify_completion_transparency_quorum
from .external_execution_ledger import validate_execution_intent
from .harness_governance_v2 import TargetValidationError, canonicalize_tool_target
from .provider_native_idempotency import verify_provider_native_status


class ProviderTransparencyGuardError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _pin_exact(
    kwargs: dict[str, Any],
    field: str,
    expected: Any,
    *,
    code: str,
) -> None:
    if field in kwargs and kwargs[field] != expected:
        raise ProviderTransparencyGuardError(
            code,
            f"{field}: expected={expected!r} observed={kwargs[field]!r}",
        )
    kwargs[field] = expected


def verify_terminal_external_effect_guard(
    *,
    v331_guard_result: Mapping[str, Any],
    separate_authorization_valid: bool,
    signed_provider_status: Mapping[str, Any],
    provider_status_kwargs: Mapping[str, Any],
    signed_local_anchor_head: Mapping[str, Any],
    signed_transparency_responses: Sequence[Mapping[str, Any]],
    transparency_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Legacy/local-reference v3.32 composition helper.

    ``separate_authorization_valid`` and ``v331_guard_result`` are caller-
    supplied values. This helper therefore does not establish authenticated
    action authority or repository-wide complete mediation.
    """
    if not isinstance(v331_guard_result, Mapping) or v331_guard_result.get("status") != "PASS":
        raise ProviderTransparencyGuardError("v331_guard_not_pass", str(v331_guard_result))
    if v331_guard_result.get("authority_granted") not in (False, None):
        raise ProviderTransparencyGuardError(
            "v331_authority_expansion",
            str(v331_guard_result.get("authority_granted")),
        )
    provider = verify_provider_native_status(
        signed_provider_status, **dict(provider_status_kwargs)
    )
    transparency = verify_completion_transparency_quorum(
        signed_local_anchor_head,
        signed_transparency_responses,
        **dict(transparency_kwargs),
    )
    if separate_authorization_valid is not True:
        raise ProviderTransparencyGuardError(
            "separate_authorization_required", str(separate_authorization_valid)
        )
    return {
        "status": "PASS",
        "provider_native_guard": provider,
        "completion_transparency_guard": transparency,
        "authorization_valid": True,
        "authority_granted": False,
        "external_effect_permitted": True,
        "required_separate_authorization": True,
        "local_reference_complete": True,
        "production_qualified": False,
        "exactly_once_established": False,
    }


def verify_authenticated_terminal_external_effect_guard(
    *,
    signed_authorization_token: Mapping[str, Any],
    signed_risk_mediation_receipt: Mapping[str, Any],
    authorization_registry: Any,
    evaluation_tick: int,
    intent: Mapping[str, Any],
    signed_in_flight_receipt: Mapping[str, Any],
    v331_guard_kwargs: Mapping[str, Any],
    signed_provider_status: Mapping[str, Any],
    provider_status_kwargs: Mapping[str, Any],
    signed_local_anchor_head: Mapping[str, Any],
    signed_transparency_responses: Sequence[Mapping[str, Any]],
    transparency_kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Authenticate and exact-bind authority before terminal effect permission.

    The boundary verifies the signed ALLOW token and signed risk-mediation
    receipt, binds them to the exact execution intent/action/target/payload,
    invokes the v3.31 cumulative preflight itself, and only then evaluates the
    provider-native and completion-transparency guards.

    The function is still a local reference verifier: it does not invoke an
    external provider and does not establish repository-wide complete mediation.
    """
    authorization = validate_authenticated_authorization(
        signed_authorization_token,
        registry=authorization_registry,
        evaluation_tick=evaluation_tick,
    )
    if authorization.get("status") != "PASS":
        raise ProviderTransparencyGuardError(
            "invalid_authenticated_authorization",
            str(authorization.get("errors", [])),
        )
    token = authorization.get("token")
    token_signer = authorization.get("verified_signer")
    if not isinstance(token, Mapping) or token_signer is None:
        raise ProviderTransparencyGuardError(
            "invalid_authenticated_authorization",
            "verified token and signer required",
        )

    mediation = validate_authenticated_risk_mediation(
        signed_risk_mediation_receipt,
        authorization_token_value=token,
        registry=authorization_registry,
        evaluation_tick=evaluation_tick,
        expected_signer_id=token_signer.signer_id,
        expected_trust_domain=token_signer.trust_domain,
    )
    if mediation.get("status") != "PASS":
        raise ProviderTransparencyGuardError(
            "invalid_authenticated_risk_mediation",
            str(mediation.get("errors", [])),
        )

    intent_result = validate_execution_intent(intent)
    if intent_result.get("status") != "PASS":
        raise ProviderTransparencyGuardError(
            "invalid_execution_intent",
            str(intent_result.get("errors", [])),
        )
    bound_intent = intent_result["intent"]

    if bound_intent.get("authorization_token_sha256") != token.get("token_sha256"):
        raise ProviderTransparencyGuardError(
            "execution_intent_authorization_binding_mismatch",
            str(bound_intent.get("authorization_token_sha256")),
        )
    if bound_intent.get("action_envelope_sha256") != token.get("action_sha256"):
        raise ProviderTransparencyGuardError(
            "execution_intent_action_binding_mismatch",
            str(bound_intent.get("action_envelope_sha256")),
        )

    try:
        target = canonicalize_tool_target(token.get("execution_target"))
    except (TargetValidationError, TypeError, ValueError) as exc:
        raise ProviderTransparencyGuardError(
            "authorization_target_invalid", str(exc)
        ) from exc
    if bound_intent.get("canonical_target_sha256") != target.get("target_sha256"):
        raise ProviderTransparencyGuardError(
            "execution_intent_target_binding_mismatch",
            str(bound_intent.get("canonical_target_sha256")),
        )

    payload_sha256 = token.get("payload_sha256")
    if (
        not isinstance(payload_sha256, str)
        or len(payload_sha256) != 64
        or any(ch not in "0123456789abcdef" for ch in payload_sha256)
    ):
        raise ProviderTransparencyGuardError(
            "authorization_payload_invalid", str(payload_sha256)
        )

    v331_kwargs = dict(v331_guard_kwargs)
    provider_kwargs = dict(provider_status_kwargs)
    terminal_transparency_kwargs = dict(transparency_kwargs)

    _pin_exact(
        v331_kwargs,
        "evaluation_tick",
        evaluation_tick,
        code="v331_evaluation_tick_binding_mismatch",
    )
    _pin_exact(
        v331_kwargs,
        "expected_provider_payload_sha256",
        payload_sha256,
        code="v331_provider_payload_binding_mismatch",
    )

    provider_id = v331_kwargs.get("expected_provider_id")
    provider_service_id = v331_kwargs.get("expected_provider_service_id")
    if not isinstance(provider_id, str) or not provider_id:
        raise ProviderTransparencyGuardError(
            "v331_provider_identity_missing", str(provider_id)
        )
    if not isinstance(provider_service_id, str) or not provider_service_id:
        raise ProviderTransparencyGuardError(
            "v331_provider_service_identity_missing", str(provider_service_id)
        )

    _pin_exact(
        provider_kwargs,
        "expected_effect_id",
        bound_intent["effect_id"],
        code="provider_effect_binding_mismatch",
    )
    _pin_exact(
        provider_kwargs,
        "expected_payload_sha256",
        payload_sha256,
        code="provider_payload_binding_mismatch",
    )
    _pin_exact(
        provider_kwargs,
        "expected_provider_id",
        provider_id,
        code="provider_identity_binding_mismatch",
    )
    _pin_exact(
        provider_kwargs,
        "expected_service_id",
        provider_service_id,
        code="provider_service_binding_mismatch",
    )
    _pin_exact(
        provider_kwargs,
        "evaluation_tick",
        evaluation_tick,
        code="provider_evaluation_tick_binding_mismatch",
    )

    _pin_exact(
        terminal_transparency_kwargs,
        "expected_provider_id",
        provider_id,
        code="transparency_provider_identity_binding_mismatch",
    )
    _pin_exact(
        terminal_transparency_kwargs,
        "expected_provider_service_id",
        provider_service_id,
        code="transparency_provider_service_binding_mismatch",
    )
    _pin_exact(
        terminal_transparency_kwargs,
        "evaluation_tick",
        evaluation_tick,
        code="transparency_evaluation_tick_binding_mismatch",
    )

    v331 = verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor(
        bound_intent,
        signed_in_flight_receipt,
        **v331_kwargs,
    )
    if not isinstance(v331, Mapping) or v331.get("status") != "PASS":
        raise ProviderTransparencyGuardError("v331_guard_not_pass", str(v331))
    if v331.get("authority_granted") not in (False, None):
        raise ProviderTransparencyGuardError(
            "v331_authority_expansion", str(v331.get("authority_granted"))
        )

    provider = verify_provider_native_status(
        signed_provider_status,
        **provider_kwargs,
    )
    transparency = verify_completion_transparency_quorum(
        signed_local_anchor_head,
        signed_transparency_responses,
        **terminal_transparency_kwargs,
    )

    receipt = mediation.get("receipt")
    return {
        "status": "PASS",
        "authorization_token_sha256": token["token_sha256"],
        "risk_mediation_receipt_sha256": (
            receipt.get("receipt_sha256") if isinstance(receipt, Mapping) else None
        ),
        "execution_intent_sha256": bound_intent["intent_sha256"],
        "effect_id": bound_intent["effect_id"],
        "canonical_target_sha256": bound_intent["canonical_target_sha256"],
        "v331_guard": v331,
        "provider_native_guard": provider,
        "completion_transparency_guard": transparency,
        "authorization_valid": True,
        "risk_mediation_valid": True,
        "authority_granted": False,
        "external_effect_permitted": True,
        "required_separate_authorization": True,
        "authenticated_terminal_effect_bridge": True,
        "local_reference_complete": True,
        "production_qualified": False,
        "exactly_once_established": False,
    }


__all__ = [
    "ProviderTransparencyGuardError",
    "verify_authenticated_terminal_external_effect_guard",
    "verify_terminal_external_effect_guard",
]
