"""Regression proof for complete-mediation hardening R1.

Zero external effects: deterministic in-process keys/adapters and disposable SQLite only.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from triaxis.action_assurance import ExecutionLedgerError
from triaxis.authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    validate_authenticated_authorization,
)
from triaxis.crypto_trust import (
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_STATE_WITNESS,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.risk_authority import EffectScope, Reversibility, RiskFacts
from tests.test_authenticated_risk_mediation_runtime_binding_r1 import _authorize_mediated
from tests.test_v360_cryptographic_authenticity import Fixture


def _mediated_allow(fx: Fixture, *, nonce: str):
    action = fx.action(risk="R2", nonce=nonce)
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
    assert result["signed_risk_mediation_receipt"] is not None
    assert adapter.calls == 1
    return action, result


def _signed_state(fx: Fixture, action):
    return fx.sign(
        action["state_witness"],
        field="witness_sha256",
        purpose=PURPOSE_STATE_WITNESS,
        key_id="key:state",
        signer="adapter:state",
        domain="domain:state",
        valid_until=40,
    )


def test_authenticated_ledger_raw_and_inherited_workload_prepare_are_fail_closed():
    fx = Fixture()
    action, result = _mediated_allow(
        fx,
        nonce="nonce:complete-mediation-hardening-raw-bypass",
    )

    with tempfile.TemporaryDirectory() as tmp:
        with AuthenticatedSQLiteExecutionLedger(
            Path(tmp) / "authenticated-ledger.db",
            fx.registry,
        ) as ledger:
            for invoke in (
                lambda: ledger.prepare(result["token"], action["state_witness"], 6),
                lambda: ledger.prepare_for_workload(
                    result["token"],
                    action["state_witness"],
                    6,
                    None,
                ),
            ):
                with pytest.raises(ExecutionLedgerError) as exc_info:
                    invoke()
                assert exc_info.value.code == "RISK_MEDIATION_AUTHENTICATION_REQUIRED"
                assert ledger.get(result["token"]["nonce"]) is None

            prepared = ledger.prepare_authenticated(
                result["signed_token"],
                _signed_state(fx, action),
                6,
                signed_risk_mediation_receipt_value=result[
                    "signed_risk_mediation_receipt"
                ],
            )
            assert prepared["state"] == "PREPARED"
            assert prepared["token_sha256"] == result["token"]["token_sha256"]


def test_authenticated_authorization_binds_verified_signer_to_token_issuer():
    fx = Fixture()
    _, result = _mediated_allow(
        fx,
        nonce="nonce:complete-mediation-hardening-signer-binding",
    )

    alternate = generate_ed25519_keypair()
    fx.registry.add(
        make_trust_key_record(
            key_id="key:alternate-auth-gate",
            signer_id="gate:alternate",
            trust_domain="domain:risk-gate",
            public_key_b64=alternate["public_key_b64"],
            purposes=[PURPOSE_AUTHORIZATION_TOKEN],
            valid_from=1,
            valid_until=100,
        )
    )
    mismatched_signed_token = sign_contract_envelope(
        result["token"],
        digest_field="token_sha256",
        purpose=PURPOSE_AUTHORIZATION_TOKEN,
        key_id="key:alternate-auth-gate",
        signer_id="gate:alternate",
        trust_domain="domain:risk-gate",
        private_key_b64=alternate["private_key_b64"],
        issued_at=6,
        valid_until=result["token"]["expires_at"],
    )

    validation = validate_authenticated_authorization(
        mismatched_signed_token,
        registry=fx.registry,
        evaluation_tick=6,
    )
    assert validation["status"] == "BLOCK"
    assert "authorization_token_signer_mismatch" in {
        row["code"] for row in validation["errors"]
    }
    assert validation["token"]["issuer_id"] == "gate:risk"
    assert validation["verified_signer"].signer_id == "gate:alternate"
