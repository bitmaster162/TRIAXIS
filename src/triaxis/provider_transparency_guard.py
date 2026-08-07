"""TRIAXIS v3.32 terminal local-reference external-effect guard."""
from __future__ import annotations
from collections.abc import Mapping, Sequence
from typing import Any

from .completion_transparency_quorum import verify_completion_transparency_quorum
from .provider_native_idempotency import verify_provider_native_status


class ProviderTransparencyGuardError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


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
    if not isinstance(v331_guard_result, Mapping) or v331_guard_result.get("status") != "PASS":
        raise ProviderTransparencyGuardError("v331_guard_not_pass", str(v331_guard_result))
    if v331_guard_result.get("authority_granted") not in (False, None):
        raise ProviderTransparencyGuardError("v331_authority_expansion", str(v331_guard_result.get("authority_granted")))
    provider = verify_provider_native_status(signed_provider_status, **dict(provider_status_kwargs))
    transparency = verify_completion_transparency_quorum(
        signed_local_anchor_head,
        signed_transparency_responses,
        **dict(transparency_kwargs),
    )
    if separate_authorization_valid is not True:
        raise ProviderTransparencyGuardError("separate_authorization_required", str(separate_authorization_valid))
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


__all__ = ["ProviderTransparencyGuardError", "verify_terminal_external_effect_guard"]
