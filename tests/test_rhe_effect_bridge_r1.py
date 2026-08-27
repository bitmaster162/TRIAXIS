"""RHE authenticated terminal-effect bridge R1 tests.

Zero-effect tests: real Ed25519 authorization and risk-mediation fixtures are
composed with mocked durability/transparency verifiers. No provider invocation,
network call, deployment, trading, capital action, or model execution occurs.
"""
from __future__ import annotations

from inspect import signature
from unittest.mock import patch

import pytest

from tests.test_authenticated_risk_mediation_runtime_binding_r1 import (
    _authorize_mediated,
)
from tests.test_v360_cryptographic_authenticity import Fixture
from triaxis.external_execution_ledger import seal_execution_intent
from triaxis.harness_governance_v2 import canonicalize_tool_target
from triaxis.provider_transparency_guard import (
    ProviderTransparencyGuardError,
    verify_authenticated_terminal_external_effect_guard,
)
from triaxis.risk_authority import EffectScope, Reversibility, RiskFacts


def _bridge_fixture() -> tuple[dict, dict, dict]:
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:rhe-effect-bridge-r1")
    authorization, _ = _authorize_mediated(
        fx,
        action,
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        ),
    )
    assert authorization["status"] == "PASS", authorization
    token = authorization["token"]
    target = canonicalize_tool_target(token["execution_target"])
    intent = seal_execution_intent(
        {
            "queue_id": "queue:rhe-effect-bridge-r1",
            "queued_input_sha256": "a" * 64,
            "action_envelope_sha256": token["action_sha256"],
            "authorization_token_sha256": token["token_sha256"],
            "canonical_target_sha256": target["target_sha256"],
            "risk_class": "MUTATING",
            "created_at_tick": 6,
            "metadata": {"fixture": "rhe-effect-bridge-r1"},
        }
    )
    kwargs = {
        "signed_authorization_token": authorization["signed_token"],
        "signed_risk_mediation_receipt": authorization[
            "signed_risk_mediation_receipt"
        ],
        "authorization_registry": fx.registry,
        "evaluation_tick": 6,
        "intent": intent,
        "signed_in_flight_receipt": {},
        "v331_guard_kwargs": {
            "expected_provider_id": "provider:rhe-test",
            "expected_provider_service_id": "service:rhe-test",
        },
        "signed_provider_status": {},
        "provider_status_kwargs": {
            "expected_provider_id": "provider:rhe-test",
            "expected_service_id": "service:rhe-test",
        },
        "signed_local_anchor_head": {},
        "signed_transparency_responses": [],
        "transparency_kwargs": {
            "expected_provider_id": "provider:rhe-test",
            "expected_provider_service_id": "service:rhe-test",
        },
    }
    return authorization, intent, kwargs


def test_authenticated_bridge_has_no_boolean_or_precomputed_v331_authority_inputs():
    params = signature(verify_authenticated_terminal_external_effect_guard).parameters
    assert "separate_authorization_valid" not in params
    assert "v331_guard_result" not in params


@patch(
    "triaxis.provider_transparency_guard.verify_completion_transparency_quorum",
    return_value={"status": "PASS"},
)
@patch(
    "triaxis.provider_transparency_guard.verify_provider_native_status",
    return_value={"status": "PASS"},
)
@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor",
    return_value={"status": "PASS", "authority_granted": False},
)
def test_exact_authenticated_composition_reaches_terminal_permission(
    v331_verify,
    provider_verify,
    transparency_verify,
):
    authorization, intent, kwargs = _bridge_fixture()

    result = verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert result["status"] == "PASS"
    assert result["external_effect_permitted"] is True
    assert result["authority_granted"] is False
    assert result["authenticated_terminal_effect_bridge"] is True
    assert result["authorization_token_sha256"] == authorization["token"]["token_sha256"]
    assert result["execution_intent_sha256"] == intent["intent_sha256"]

    v331_args, v331_kwargs = v331_verify.call_args
    assert v331_args[0]["intent_sha256"] == intent["intent_sha256"]
    assert v331_kwargs["evaluation_tick"] == 6
    assert (
        v331_kwargs["expected_provider_payload_sha256"]
        == authorization["token"]["payload_sha256"]
    )

    provider_kwargs = provider_verify.call_args.kwargs
    assert provider_kwargs["expected_effect_id"] == intent["effect_id"]
    assert (
        provider_kwargs["expected_payload_sha256"]
        == authorization["token"]["payload_sha256"]
    )
    assert provider_kwargs["expected_provider_id"] == "provider:rhe-test"
    assert provider_kwargs["expected_service_id"] == "service:rhe-test"
    assert provider_kwargs["evaluation_tick"] == 6

    transparency_kwargs = transparency_verify.call_args.kwargs
    assert transparency_kwargs["expected_provider_id"] == "provider:rhe-test"
    assert transparency_kwargs["expected_provider_service_id"] == "service:rhe-test"
    assert transparency_kwargs["evaluation_tick"] == 6


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_forged_signed_authorization_blocks_before_v331(v331_verify):
    _, _, kwargs = _bridge_fixture()
    forged = dict(kwargs["signed_authorization_token"])
    inner = dict(forged["inner_contract"])
    inner["outcome"] = "DENY"
    forged["inner_contract"] = inner
    kwargs["signed_authorization_token"] = forged

    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert caught.value.code == "invalid_authenticated_authorization"
    v331_verify.assert_not_called()


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_missing_or_forged_risk_receipt_blocks_before_v331(v331_verify):
    _, _, kwargs = _bridge_fixture()
    kwargs["signed_risk_mediation_receipt"] = {}

    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert caught.value.code == "invalid_authenticated_risk_mediation"
    v331_verify.assert_not_called()


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_execution_intent_must_bind_exact_authorization_token(v331_verify):
    _, intent, kwargs = _bridge_fixture()
    changed = dict(intent)
    changed["authorization_token_sha256"] = "f" * 64
    changed["intent_sha256"] = ""
    kwargs["intent"] = seal_execution_intent(changed)

    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert caught.value.code == "execution_intent_authorization_binding_mismatch"
    v331_verify.assert_not_called()


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_execution_intent_must_bind_exact_action_and_target(v331_verify):
    _, intent, kwargs = _bridge_fixture()

    changed = dict(intent)
    changed["action_envelope_sha256"] = "e" * 64
    changed.pop("effect_id", None)
    changed["intent_sha256"] = ""
    kwargs["intent"] = seal_execution_intent(changed)
    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)
    assert caught.value.code == "execution_intent_action_binding_mismatch"

    _, intent, kwargs = _bridge_fixture()
    changed = dict(intent)
    changed["canonical_target_sha256"] = "e" * 64
    changed.pop("effect_id", None)
    changed["intent_sha256"] = ""
    kwargs["intent"] = seal_execution_intent(changed)
    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)
    assert caught.value.code == "execution_intent_target_binding_mismatch"

    v331_verify.assert_not_called()


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_caller_cannot_substitute_provider_payload_or_identity(v331_verify):
    _, _, kwargs = _bridge_fixture()
    kwargs["provider_status_kwargs"] = {
        **kwargs["provider_status_kwargs"],
        "expected_payload_sha256": "e" * 64,
    }

    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert caught.value.code == "provider_payload_binding_mismatch"
    v331_verify.assert_not_called()

    _, _, kwargs = _bridge_fixture()
    kwargs["transparency_kwargs"] = {
        **kwargs["transparency_kwargs"],
        "expected_provider_id": "provider:substituted",
    }
    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)
    assert caught.value.code == "transparency_provider_identity_binding_mismatch"
    v331_verify.assert_not_called()


@patch(
    "triaxis.provider_transparency_guard."
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor"
)
def test_expired_authorization_blocks_before_any_terminal_evidence(v331_verify):
    _, _, kwargs = _bridge_fixture()
    kwargs["evaluation_tick"] = 26

    with pytest.raises(ProviderTransparencyGuardError) as caught:
        verify_authenticated_terminal_external_effect_guard(**kwargs)

    assert caught.value.code == "invalid_authenticated_authorization"
    v331_verify.assert_not_called()
