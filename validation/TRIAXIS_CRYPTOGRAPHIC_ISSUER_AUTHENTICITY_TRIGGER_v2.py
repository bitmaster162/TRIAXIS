#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.6 cryptographic issuer authenticity."""
from __future__ import annotations

from copy import deepcopy
import json
import tempfile
from pathlib import Path

from tests.test_v360_cryptographic_authenticity import Fixture
from triaxis.action_assurance import ExecutionLedgerError
from triaxis.authenticated_action_assurance import (
    AuthenticatedSQLiteExecutionLedger,
    authorize_authenticated_action,
    validate_authenticated_authorization,
)
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)


def row(case_id: str, expected: str, observed: str, passed: bool, positive_control: bool = False) -> dict:
    return {
        "case_id": case_id,
        "expected": expected,
        "observed": observed,
        "status": "PASS" if passed else "FAIL",
        "positive_control": positive_control,
    }


def run_trigger() -> dict:
    fx = Fixture()
    rows = []

    legitimate = fx.authorized()
    rows.append(row(
        "AUTHENTICATED_POSITIVE_CONTROL",
        "ALLOW",
        legitimate["token"]["outcome"],
        legitimate["status"] == "PASS" and validate_authenticated_authorization(
            legitimate["signed_token"], registry=fx.registry, evaluation_tick=6
        )["status"] == "PASS",
        True,
    ))

    action = fx.action()
    attacker = generate_ed25519_keypair()
    forged_assurance = sign_contract_envelope(
        action["assurance_attestation"],
        digest_field="attestation_sha256",
        purpose=PURPOSE_ASSURANCE_ATTESTATION,
        key_id="key:assurance",
        signer_id="assurance:1",
        trust_domain="domain:assurance",
        private_key_b64=attacker["private_key_b64"],
        issued_at=5,
        valid_until=20,
    )
    forged_result = authorize_authenticated_action(
        action_value=action,
        policy_value=fx.policy(),
        evaluation_tick=6,
        registry=fx.registry,
        signed_assurance_attestation=forged_assurance,
        signed_state_witness=fx.sign(action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40),
        signed_policy_bundle=fx.sign(fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
        signed_approvals=[],
        gate_key_id="key:gate",
        gate_signer_id="gate:1",
        gate_trust_domain="domain:gate",
        gate_private_key_b64=fx.keys["key:gate"]["private_key_b64"],
    )
    rows.append(row("FORGED_ASSURANCE_PRIVATE_KEY", "DENY", forged_result["token"]["outcome"], forged_result["status"] == "BLOCK"))

    unsigned_state_result = authorize_authenticated_action(
        action_value=action,
        policy_value=fx.policy(),
        evaluation_tick=6,
        registry=fx.registry,
        signed_assurance_attestation=fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20),
        signed_state_witness=action["state_witness"],
        signed_policy_bundle=fx.sign(fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
        signed_approvals=[],
        gate_key_id="key:gate",
        gate_signer_id="gate:1",
        gate_trust_domain="domain:gate",
        gate_private_key_b64=fx.keys["key:gate"]["private_key_b64"],
    )
    rows.append(row("UNSIGNED_STATE_WITNESS", "DENY", unsigned_state_result["token"]["outcome"], unsigned_state_result["status"] == "BLOCK"))

    wrong_gate = generate_ed25519_keypair()
    bad_gate_result = authorize_authenticated_action(
        action_value=action,
        policy_value=fx.policy(),
        evaluation_tick=6,
        registry=fx.registry,
        signed_assurance_attestation=fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20),
        signed_state_witness=fx.sign(action["state_witness"], field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40),
        signed_policy_bundle=fx.sign(fx.policy(), field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE, key_id="key:policy", signer="policy-engine:1", domain="domain:policy", valid_until=50),
        signed_approvals=[],
        gate_key_id="key:gate",
        gate_signer_id="gate:1",
        gate_trust_domain="domain:gate",
        gate_private_key_b64=wrong_gate["private_key_b64"],
    )
    rows.append(row("FORGED_GATE_PRIVATE_KEY", "DENY", bad_gate_result["token"]["outcome"], bad_gate_result["status"] == "BLOCK" and bad_gate_result["token"]["outcome"] == "DENY"))

    revoked_registry = TrustKeyRegistry()
    for record in fx.registry.as_records():
        if record["key_id"] == "key:assurance":
            record = make_trust_key_record(
                key_id=record["key_id"], signer_id=record["signer_id"], trust_domain=record["trust_domain"],
                public_key_b64=record["public_key_b64"], purposes=record["purposes"],
                valid_from=record["valid_from"], valid_until=record["valid_until"], revoked_at=6,
            )
        revoked_registry.add(record)
    signed_assurance = fx.sign(action["assurance_attestation"], field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION, key_id="key:assurance", signer="assurance:1", domain="domain:assurance", valid_until=20)
    revoked = verify_contract_envelope(
        signed_assurance,
        registry=revoked_registry,
        evaluation_tick=6,
        expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
        expected_digest_field="attestation_sha256",
    )
    rows.append(row("REVOKED_KEY", "BLOCK", revoked["status"], revoked["status"] == "BLOCK"))

    signed_state = fx.sign(fx.state(), field="witness_sha256", purpose=PURPOSE_STATE_WITNESS, key_id="key:state", signer="adapter:state", domain="domain:state", valid_until=40)
    forged_token = sign_contract_envelope(
        legitimate["token"], digest_field="token_sha256", purpose=PURPOSE_AUTHORIZATION_TOKEN,
        key_id="key:gate", signer_id="gate:1", trust_domain="domain:gate",
        private_key_b64=attacker["private_key_b64"], issued_at=6, valid_until=20,
    )
    ledger_observed = "REJECTED"
    with tempfile.TemporaryDirectory() as tmp:
        with AuthenticatedSQLiteExecutionLedger(Path(tmp) / "ledger.db", fx.registry) as ledger:
            try:
                ledger.prepare_authenticated(forged_token, signed_state, 6)
                ledger_observed = "PREPARED"
            except ExecutionLedgerError:
                ledger_observed = "REJECTED"
    rows.append(row("FORGED_AUTHORIZATION_TOKEN", "REJECTED", ledger_observed, ledger_observed == "REJECTED"))

    tampered = deepcopy(legitimate["signed_token"])
    tampered["inner_contract"]["payload_sha256"] = "e" * 64
    tampered_result = validate_authenticated_authorization(tampered, registry=fx.registry, evaluation_tick=6)
    rows.append(row("SIGNED_ENVELOPE_TAMPER", "BLOCK", tampered_result["status"], tampered_result["status"] == "BLOCK"))

    passed = sum(item["status"] == "PASS" for item in rows)
    return {
        "contract_id": "TRIAXIS_CRYPTOGRAPHIC_ISSUER_AUTHENTICITY_TRIGGER_RESULT_v2",
        "target": "TRIAXIS-v3.6-RC1-CRYPTOGRAPHIC-AUTHENTICITY",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
