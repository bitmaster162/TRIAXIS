"""RHE authenticated provider HTTP transport R2 tests.

Zero-effect tests: provider calls are mocks only. No network call, provider effect,
deployment, trading, capital action, or model execution occurs.
"""
from __future__ import annotations

import hashlib
from unittest.mock import Mock, patch

from triaxis.idempotent_effect_provider_http import (
    AuthenticatedIdempotentEffectProviderHTTPApplication,
    IdempotentEffectProviderHTTPApplication,
)
from triaxis.provider_transparency_guard import ProviderTransparencyGuardError

EFFECT_ID = "e" * 64
PAYLOAD_SHA256 = "b" * 64
TOKEN = "provider-client-secret"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


class ProviderStub:
    provider_id = "provider:rhe-http-r2"
    service_id = "service:rhe-http-r2"
    signer_id = "signer:rhe-http-r2"
    key_id = "key:rhe-http-r2"
    trust_domain = "triaxis:rhe-http-r2"

    def __init__(self) -> None:
        self.begin = Mock(
            return_value={
                "status": "PASS",
                "external_effect_permitted": True,
                "idempotent_replay": False,
            }
        )

    def effect_count(self) -> int:
        return 0


def _legacy_app(provider: ProviderStub) -> IdempotentEffectProviderHTTPApplication:
    return IdempotentEffectProviderHTTPApplication(
        provider,
        clock=lambda: 7,
        client_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
    )


def _authenticated_app(
    provider: ProviderStub,
) -> AuthenticatedIdempotentEffectProviderHTTPApplication:
    return AuthenticatedIdempotentEffectProviderHTTPApplication(
        provider,
        clock=lambda: 7,
        client_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
        authorization_registry=object(),
        v331_guard_kwargs={},
        provider_status_kwargs={},
        transparency_kwargs={},
    )


def _authenticated_body() -> dict:
    return {
        "signed_authorization_token": {
            "inner_contract": {"payload_sha256": PAYLOAD_SHA256}
        },
        "signed_risk_mediation_receipt": {},
        "intent": {"effect_id": EFFECT_ID},
        "signed_in_flight_receipt": {},
        "signed_provider_status": {},
        "signed_local_anchor_head": {},
        "signed_transparency_responses": [],
        "provider_request_id": "request:rhe-http-r2",
    }


def _guard_pass() -> dict:
    return {
        "status": "PASS",
        "effect_id": EFFECT_ID,
        "authority_granted": False,
        "external_effect_permitted": True,
        "authenticated_terminal_effect_bridge": True,
    }


def test_legacy_reference_begin_remains_transport_authenticated_only():
    provider = ProviderStub()
    app = _legacy_app(provider)

    status, result = app.handle(
        "POST",
        "/v1/effects/begin",
        {
            "effect_id": EFFECT_ID,
            "payload_sha256": PAYLOAD_SHA256,
            "provider_request_id": "request:legacy",
        },
        HEADERS,
    )

    assert status == 200
    assert result["external_effect_permitted"] is True
    provider.begin.assert_called_once_with(
        effect_id=EFFECT_ID,
        payload_sha256=PAYLOAD_SHA256,
        provider_request_id="request:legacy",
        now_tick=7,
    )


@patch(
    "triaxis.idempotent_effect_provider_http."
    "verify_authenticated_terminal_external_effect_guard"
)
def test_bearer_only_begin_is_blocked_before_authenticated_guard_and_provider(guard):
    provider = ProviderStub()
    app = _authenticated_app(provider)

    status, result = app.handle(
        "POST",
        "/v1/effects/begin",
        {"provider_request_id": "request:bearer-only"},
        HEADERS,
    )

    assert status == 403
    assert result["error"] == "authenticated_terminal_effect_guard_required"
    guard.assert_not_called()
    provider.begin.assert_not_called()


@patch(
    "triaxis.idempotent_effect_provider_http."
    "verify_authenticated_terminal_external_effect_guard",
    side_effect=ProviderTransparencyGuardError(
        "invalid_authenticated_authorization",
        "synthetic zero-effect rejection",
    ),
)
def test_authenticated_guard_failure_blocks_provider_begin(guard):
    provider = ProviderStub()
    app = _authenticated_app(provider)

    status, result = app.handle(
        "POST",
        "/v1/effects/begin",
        _authenticated_body(),
        HEADERS,
    )

    assert status == 403
    assert result["error"] == "invalid_authenticated_authorization"
    guard.assert_called_once()
    provider.begin.assert_not_called()


@patch(
    "triaxis.idempotent_effect_provider_http."
    "verify_authenticated_terminal_external_effect_guard",
    return_value=_guard_pass(),
)
def test_exact_authenticated_pass_invokes_provider_begin_once_with_derived_bindings(guard):
    provider = ProviderStub()
    app = _authenticated_app(provider)
    body = _authenticated_body()

    status, result = app.handle(
        "POST",
        "/v1/effects/begin",
        body,
        HEADERS,
    )

    assert status == 200
    assert result["authenticated_terminal_effect_bridge"] is True
    assert result["authenticated_effect_id"] == EFFECT_ID
    provider.begin.assert_called_once_with(
        effect_id=EFFECT_ID,
        payload_sha256=PAYLOAD_SHA256,
        provider_request_id="request:rhe-http-r2",
        now_tick=7,
    )

    kwargs = guard.call_args.kwargs
    assert kwargs["evaluation_tick"] == 7
    assert kwargs["v331_guard_kwargs"]["expected_provider_id"] == provider.provider_id
    assert (
        kwargs["v331_guard_kwargs"]["expected_provider_service_id"]
        == provider.service_id
    )
    assert (
        kwargs["provider_status_kwargs"]["expected_provider_id"]
        == provider.provider_id
    )
    assert (
        kwargs["provider_status_kwargs"]["expected_service_id"]
        == provider.service_id
    )
    assert (
        kwargs["transparency_kwargs"]["expected_provider_id"]
        == provider.provider_id
    )
    assert (
        kwargs["transparency_kwargs"]["expected_provider_service_id"]
        == provider.service_id
    )


@patch(
    "triaxis.idempotent_effect_provider_http."
    "verify_authenticated_terminal_external_effect_guard",
    return_value=_guard_pass(),
)
def test_caller_effect_or_payload_substitution_blocks_before_provider_mutation(guard):
    provider = ProviderStub()
    app = _authenticated_app(provider)

    body = _authenticated_body()
    body["effect_id"] = "f" * 64
    status, result = app.handle("POST", "/v1/effects/begin", body, HEADERS)
    assert status == 403
    assert result["error"] == "provider_effect_binding_mismatch"
    provider.begin.assert_not_called()

    body = _authenticated_body()
    body["payload_sha256"] = "f" * 64
    status, result = app.handle("POST", "/v1/effects/begin", body, HEADERS)
    assert status == 403
    assert result["error"] == "provider_payload_binding_mismatch"
    provider.begin.assert_not_called()
    assert guard.call_count == 2


def test_server_side_provider_identity_is_pinned_fail_closed():
    provider = ProviderStub()

    try:
        AuthenticatedIdempotentEffectProviderHTTPApplication(
            provider,
            clock=lambda: 7,
            client_token_sha256=hashlib.sha256(TOKEN.encode()).hexdigest(),
            authorization_registry=object(),
            v331_guard_kwargs={"expected_provider_id": "provider:substituted"},
            provider_status_kwargs={},
            transparency_kwargs={},
        )
    except ValueError as exc:
        assert "expected_provider_id" in str(exc)
    else:
        raise AssertionError("provider identity substitution must fail closed")
