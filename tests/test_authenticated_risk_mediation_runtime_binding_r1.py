"""Authenticated Risk Authority runtime-binding design tests.

These tests are zero-effect. They exercise only deterministic in-process
adapters, Ed25519 test keys and disposable SQLite state. No provider, network,
deployment, trading or capital action is invoked here.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from triaxis.action_assurance import ExecutionLedgerError
from triaxis.authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    authorize_authenticated_action,
    validate_authenticated_authorization,
    validate_authenticated_risk_mediation,
)
from triaxis.crypto_trust import (
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_RISK_MEDIATION_RECEIPT,
    PURPOSE_STATE_WITNESS,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.risk_authority import EffectScope, Reversibility, RiskFacts
from triaxis.risk_mediation import (
    RiskFactObservation,
    TrustedRiskFactsAdapterRegistry,
    risk_subject_sha256,
)
from tests.test_v360_cryptographic_authenticity import Fixture


class StaticRiskAdapter:
    adapter_id = "risk:test"
    adapter_version = 1

    def __init__(self, facts: RiskFacts) -> None:
        self.facts = facts
        self.calls = 0

    def observe_risk_facts(self, risk_subject):
        self.calls += 1
        return RiskFactObservation(
            adapter_id=self.adapter_id,
            adapter_version=self.adapter_version,
            risk_subject_sha256=risk_subject_sha256(risk_subject),
            facts=self.facts,
        )


def _install_mediation_gate(fx: Fixture):
    pair = generate_ed25519_keypair()
    fx.registry.add(
        make_trust_key_record(
            key_id="key:risk-gate",
            signer_id="gate:risk",
            trust_domain="domain:risk-gate",
            public_key_b64=pair["public_key_b64"],
            purposes=[
                PURPOSE_AUTHORIZATION_TOKEN,
                PURPOSE_RISK_MEDIATION_RECEIPT,
            ],
            valid_from=1,
            valid_until=100,
        )
    )
    return pair


def _signed_inputs(fx: Fixture, action, policy):
    return {
        "signed_assurance_attestation": fx.sign(
            action["assurance_attestation"],
            field="attestation_sha256",
            purpose="ASSURANCE_ATTESTATION",
            key_id="key:assurance",
            signer="assurance:1",
            domain="domain:assurance",
            valid_until=20,
        ),
        "signed_state_witness": fx.sign(
            action["state_witness"],
            field="witness_sha256",
            purpose=PURPOSE_STATE_WITNESS,
            key_id="key:state",
            signer="adapter:state",
            domain="domain:state",
            valid_until=40,
        ),
        "signed_policy_bundle": fx.sign(
            policy,
            field="policy_sha256",
            purpose="POLICY_BUNDLE",
            key_id="key:policy",
            signer="policy-engine:1",
            domain="domain:policy",
            valid_until=50,
        ),
        "signed_approvals": [],
    }


def _authorize_mediated(fx: Fixture, action, facts: RiskFacts, *, trusted_adapter=None):
    policy = fx.policy()
    gate_pair = _install_mediation_gate(fx)
    adapter = StaticRiskAdapter(facts)
    trusted = adapter if trusted_adapter is None else trusted_adapter
    registry = TrustedRiskFactsAdapterRegistry(
        {adapter.adapter_id: (adapter.adapter_version, trusted)}
    )
    result = authorize_authenticated_action(
        action_value=action,
        policy_value=policy,
        evaluation_tick=6,
        registry=fx.registry,
        **_signed_inputs(fx, action, policy),
        gate_key_id="key:risk-gate",
        gate_signer_id="gate:risk",
        gate_trust_domain="domain:risk-gate",
        gate_private_key_b64=gate_pair["private_key_b64"],
        risk_adapter=adapter,
        trusted_risk_adapter_registry=registry,
        risk_adapter_id=adapter.adapter_id,
        risk_adapter_version=adapter.adapter_version,
    )
    return result, adapter


def test_mediated_authenticated_allow_returns_exact_signed_receipt():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:risk-mediated")
    result, adapter = _authorize_mediated(
        fx,
        action,
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        ),
    )

    assert result["status"] == "PASS", result
    assert result["token"]["outcome"] == "ALLOW"
    assert adapter.calls == 1
    assert result["risk_mediation_receipt"]["effective_risk"] == "R2"
    assert (
        result["risk_mediation_receipt"]["authorization_token_sha256"]
        == result["token"]["token_sha256"]
    )
    assert validate_authenticated_authorization(
        result["signed_token"], registry=fx.registry, evaluation_tick=6
    )["status"] == "PASS"
    mediation = validate_authenticated_risk_mediation(
        result["signed_risk_mediation_receipt"],
        authorization_token_value=result["token"],
        registry=fx.registry,
        evaluation_tick=6,
        expected_signer_id="gate:risk",
        expected_trust_domain="domain:risk-gate",
    )
    assert mediation["status"] == "PASS", mediation


def test_caller_risk_downgrade_blocks_before_usable_allow():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:risk-downgrade")
    result, adapter = _authorize_mediated(
        fx,
        action,
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.IRREVERSIBLE,
        ),
    )

    assert result["status"] == "BLOCK"
    assert result["token"]["outcome"] == "DENY"
    assert result["signed_risk_mediation_receipt"] is None
    assert adapter.calls == 1
    assert "RISK_DOWNGRADE_BLOCKED" in {row["code"] for row in result["errors"]}


def test_untrusted_same_identity_adapter_blocks_before_usable_allow():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:risk-untrusted")
    other = StaticRiskAdapter(
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        )
    )
    result, adapter = _authorize_mediated(
        fx,
        action,
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        ),
        trusted_adapter=other,
    )

    assert result["status"] == "BLOCK"
    assert result["token"]["outcome"] == "DENY"
    assert result["signed_risk_mediation_receipt"] is None
    assert adapter.calls == 0
    assert "UNTRUSTED_RISK_FACT_ADAPTER" in {row["code"] for row in result["errors"]}


def test_incomplete_mediation_configuration_fails_closed():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:risk-config")
    policy = fx.policy()
    gate_pair = _install_mediation_gate(fx)
    adapter = StaticRiskAdapter(
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        )
    )
    result = authorize_authenticated_action(
        action_value=action,
        policy_value=policy,
        evaluation_tick=6,
        registry=fx.registry,
        **_signed_inputs(fx, action, policy),
        gate_key_id="key:risk-gate",
        gate_signer_id="gate:risk",
        gate_trust_domain="domain:risk-gate",
        gate_private_key_b64=gate_pair["private_key_b64"],
        risk_adapter=adapter,
    )

    assert result["status"] == "BLOCK"
    assert result["token"]["outcome"] == "DENY"
    assert result["signed_risk_mediation_receipt"] is None
    assert "RISK_MEDIATION_CONFIGURATION_INCOMPLETE" in {
        row["code"] for row in result["errors"]
    }


def test_authenticated_sqlite_ledger_rejects_signed_token_without_mediation():
    fx = Fixture()
    result = fx.authorized()
    signed_state = fx.sign(
        fx.state(),
        field="witness_sha256",
        purpose=PURPOSE_STATE_WITNESS,
        key_id="key:state",
        signer="adapter:state",
        domain="domain:state",
        valid_until=40,
    )
    with tempfile.TemporaryDirectory() as tmp:
        with AuthenticatedSQLiteExecutionLedger(
            Path(tmp) / "ledger.db", fx.registry
        ) as ledger:
            with pytest.raises(ExecutionLedgerError) as exc_info:
                ledger.prepare_authenticated(result["signed_token"], signed_state, 6)
            assert exc_info.value.code == "RISK_MEDIATION_AUTHENTICATION_REQUIRED"
            assert ledger.get(result["token"]["nonce"]) is None
