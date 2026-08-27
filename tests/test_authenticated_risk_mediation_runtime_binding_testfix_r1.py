"""Test-only proof closure for authenticated Risk Authority runtime binding.

Zero external effects: deterministic in-process fixtures and disposable SQLite only.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from triaxis.action_assurance import ExecutionLedgerError, SQLiteExecutionLedger
from triaxis.authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    authorize_authenticated_action,
    validate_authenticated_authorization,
)
from triaxis.authorization import PolicyEnforcementPoint
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_STATE_WITNESS,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.risk_authority import EffectScope, Reversibility, RiskFacts
from triaxis.risk_mediation import TrustedRiskFactsAdapterRegistry
from tests.test_authenticated_risk_mediation_runtime_binding_r1 import (
    StaticRiskAdapter,
    _authorize_mediated,
    _cedar_action,
    _install_mediation_gate,
    _signed_inputs,
)
from tests.test_pi002_negative_controls import MockCedarPDP
from tests.test_v360_cryptographic_authenticity import Fixture


def test_authenticated_sqlite_ledger_accepts_exact_signed_token_mediation_and_state_to_prepared():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:generic-ledger-mediated-positive")
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
    assert result["signed_risk_mediation_receipt"] is not None

    signed_state = fx.sign(
        action["state_witness"],
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
            prepared = ledger.prepare_authenticated(
                result["signed_token"],
                signed_state,
                6,
                signed_risk_mediation_receipt_value=result[
                    "signed_risk_mediation_receipt"
                ],
            )
            assert prepared["state"] == "PREPARED"
            assert prepared["token_sha256"] == result["token"]["token_sha256"]
            assert prepared["outcome_sha256"] is None
            assert prepared["effect_id"] is None
            assert prepared["receipt"] is None
            assert ledger.get(result["token"]["nonce"]) == prepared


def test_invalid_authenticated_input_blocks_before_risk_adapter_and_cedar_pep():
    fx = Fixture()
    action = _cedar_action(fx)
    policy = fx.policy()
    gate_pair = _install_mediation_gate(fx)
    adapter = StaticRiskAdapter(
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        )
    )
    trusted = TrustedRiskFactsAdapterRegistry(
        {adapter.adapter_id: (adapter.adapter_version, adapter)}
    )
    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())

    signed_inputs = _signed_inputs(fx, action, policy)
    forged_pair = generate_ed25519_keypair()
    signed_inputs["signed_assurance_attestation"] = sign_contract_envelope(
        action["assurance_attestation"],
        digest_field="attestation_sha256",
        purpose=PURPOSE_ASSURANCE_ATTESTATION,
        key_id="key:assurance",
        signer_id="assurance:1",
        trust_domain="domain:assurance",
        private_key_b64=forged_pair["private_key_b64"],
        issued_at=5,
        valid_until=20,
    )

    result = authorize_authenticated_action(
        action_value=action,
        policy_value=policy,
        evaluation_tick=6,
        registry=fx.registry,
        **signed_inputs,
        gate_key_id="key:risk-gate",
        gate_signer_id="gate:risk",
        gate_trust_domain="domain:risk-gate",
        gate_private_key_b64=gate_pair["private_key_b64"],
        authorization_mode="cedar_reference",
        pep=pep,
        identity_mode="explicit_reference",
        risk_adapter=adapter,
        trusted_risk_adapter_registry=trusted,
        risk_adapter_id=adapter.adapter_id,
        risk_adapter_version=adapter.adapter_version,
    )

    assert result["status"] == "BLOCK"
    assert result["token"]["outcome"] == "DENY"
    assert result["signed_risk_mediation_receipt"] is None
    assert adapter.calls == 0
    assert pep.last_receipt is None
    assert "invalid_signature" in {row["code"] for row in result["errors"]}


def test_receipt_purpose_failure_revokes_allow_artifact_and_blocks_lower_level_prepare():
    fx = Fixture()
    action = fx.action(risk="R2", nonce="nonce:risk-purpose-fail-closed")
    policy = fx.policy()
    gate_pair = generate_ed25519_keypair()
    fx.registry.add(
        make_trust_key_record(
            key_id="key:risk-gate-auth-only",
            signer_id="gate:risk",
            trust_domain="domain:risk-gate",
            public_key_b64=gate_pair["public_key_b64"],
            purposes=[PURPOSE_AUTHORIZATION_TOKEN],
            valid_from=1,
            valid_until=100,
        )
    )
    adapter = StaticRiskAdapter(
        RiskFacts(
            effect_scope=EffectScope.EXTERNAL,
            reversibility=Reversibility.REVERSIBLE,
        )
    )
    trusted = TrustedRiskFactsAdapterRegistry(
        {adapter.adapter_id: (adapter.adapter_version, adapter)}
    )

    result = authorize_authenticated_action(
        action_value=action,
        policy_value=policy,
        evaluation_tick=6,
        registry=fx.registry,
        **_signed_inputs(fx, action, policy),
        gate_key_id="key:risk-gate-auth-only",
        gate_signer_id="gate:risk",
        gate_trust_domain="domain:risk-gate",
        gate_private_key_b64=gate_pair["private_key_b64"],
        risk_adapter=adapter,
        trusted_risk_adapter_registry=trusted,
        risk_adapter_id=adapter.adapter_id,
        risk_adapter_version=adapter.adapter_version,
    )

    assert adapter.calls == 1
    assert result["status"] == "BLOCK"
    assert result["token"]["outcome"] == "DENY"
    assert result["risk_mediation_receipt"] is None
    assert result["signed_risk_mediation_receipt"] is None
    assert "key_purpose_denied" in {row["code"] for row in result["errors"]}
    assert validate_authenticated_authorization(
        result["signed_token"],
        registry=fx.registry,
        evaluation_tick=6,
    )["status"] == "BLOCK"

    with tempfile.TemporaryDirectory() as tmp:
        with SQLiteExecutionLedger(Path(tmp) / "raw-ledger.db") as ledger:
            with pytest.raises(ExecutionLedgerError) as exc_info:
                ledger.prepare(result["token"], action["state_witness"], 6)
            assert exc_info.value.code == "invalid_authorization_token"
            assert ledger.get(result["token"]["nonce"]) is None
