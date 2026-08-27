"""RHE R1 composition: signed authorization/state + strict SPIFFE PREPARED boundary."""
from __future__ import annotations

from dataclasses import replace

import pytest

from triaxis.action_assurance import ExecutionLedgerError
from triaxis.authenticated_rhe_execution_boundary import (
    AuthenticatedTrustedWorkloadExecutionBoundary,
)
from triaxis.crypto_trust import (
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from tests.test_rhe_execution_identity_provenance_r1 import (
    issue_token,
    make_boundary,
    registered_provider,
)

GATE_KEY_ID = "key:rhe-gate"
GATE_SIGNER_ID = "gate:rhe"
GATE_TRUST_DOMAIN = "domain:rhe-gate"
STATE_KEY_ID = "key:rhe-state"
STATE_TRUST_DOMAIN = "domain:rhe-state"


def make_crypto_material(token, action):
    gate_pair = generate_ed25519_keypair()
    state_pair = generate_ed25519_keypair()
    registry = TrustKeyRegistry()
    registry.add(
        make_trust_key_record(
            key_id=GATE_KEY_ID,
            signer_id=GATE_SIGNER_ID,
            trust_domain=GATE_TRUST_DOMAIN,
            public_key_b64=gate_pair["public_key_b64"],
            purposes=[PURPOSE_AUTHORIZATION_TOKEN],
            valid_from=1,
            valid_until=1000,
        )
    )
    registry.add(
        make_trust_key_record(
            key_id=STATE_KEY_ID,
            signer_id=action["state_witness"]["adapter_id"],
            trust_domain=STATE_TRUST_DOMAIN,
            public_key_b64=state_pair["public_key_b64"],
            purposes=[PURPOSE_STATE_WITNESS],
            valid_from=1,
            valid_until=1000,
        )
    )
    signed_token = sign_contract_envelope(
        token,
        digest_field="token_sha256",
        purpose=PURPOSE_AUTHORIZATION_TOKEN,
        key_id=GATE_KEY_ID,
        signer_id=GATE_SIGNER_ID,
        trust_domain=GATE_TRUST_DOMAIN,
        private_key_b64=gate_pair["private_key_b64"],
        issued_at=150,
        valid_until=1000,
    )
    signed_state = sign_contract_envelope(
        action["state_witness"],
        digest_field="witness_sha256",
        purpose=PURPOSE_STATE_WITNESS,
        key_id=STATE_KEY_ID,
        signer_id=action["state_witness"]["adapter_id"],
        trust_domain=STATE_TRUST_DOMAIN,
        private_key_b64=state_pair["private_key_b64"],
        issued_at=150,
        valid_until=1000,
    )
    return registry, gate_pair, state_pair, signed_token, signed_state


def make_composed_boundary(tmp_path, provider, workload_registry, crypto_registry):
    ledger, workload_boundary = make_boundary(tmp_path, provider, workload_registry)
    boundary = AuthenticatedTrustedWorkloadExecutionBoundary(
        workload_boundary,
        crypto_registry=crypto_registry,
        expected_token_signer_id=GATE_SIGNER_ID,
        expected_token_trust_domain=GATE_TRUST_DOMAIN,
    )
    return ledger, boundary


def test_signed_spiffe_token_and_signed_state_reach_exactly_prepared(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, signed_state = make_crypto_material(token, action)
    issuance_calls = provider.calls
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        row = boundary.prepare(signed_token, signed_state, 150)
        assert provider.calls == issuance_calls + 1
        assert row["state"] == "PREPARED"
        assert row["token_sha256"] == token["token_sha256"]
        assert row["outcome_sha256"] is None
        assert row["effect_id"] is None
        assert row["receipt"] is None
    finally:
        ledger.close()


def test_unsigned_raw_token_is_rejected_before_workload_fetch(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, _, signed_state = make_crypto_material(token, action)
    calls_before = provider.calls
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, signed_state, 150)
        assert exc_info.value.code == "invalid_authenticated_authorization"
        assert provider.calls == calls_before
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_forged_token_signature_is_rejected_before_workload_fetch(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, _, signed_state = make_crypto_material(token, action)
    forged_pair = generate_ed25519_keypair()
    forged_token = sign_contract_envelope(
        token,
        digest_field="token_sha256",
        purpose=PURPOSE_AUTHORIZATION_TOKEN,
        key_id=GATE_KEY_ID,
        signer_id=GATE_SIGNER_ID,
        trust_domain=GATE_TRUST_DOMAIN,
        private_key_b64=forged_pair["private_key_b64"],
        issued_at=150,
        valid_until=1000,
    )
    calls_before = provider.calls
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(forged_token, signed_state, 150)
        assert exc_info.value.code == "invalid_authenticated_authorization"
        assert provider.calls == calls_before
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_authenticated_token_from_wrong_gate_authority_is_rejected(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, signed_state = make_crypto_material(token, action)
    ledger, workload_boundary = make_boundary(tmp_path, provider, workload_registry)
    boundary = AuthenticatedTrustedWorkloadExecutionBoundary(
        workload_boundary,
        crypto_registry=crypto_registry,
        expected_token_signer_id="gate:other",
        expected_token_trust_domain=GATE_TRUST_DOMAIN,
    )
    calls_before = provider.calls
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(signed_token, signed_state, 150)
        assert exc_info.value.code == "AUTHORIZATION_TOKEN_SIGNER_MISMATCH"
        assert provider.calls == calls_before
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_unsigned_state_is_rejected_before_workload_fetch(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, _ = make_crypto_material(token, action)
    calls_before = provider.calls
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(signed_token, action["state_witness"], 150)
        assert exc_info.value.code == "invalid_authenticated_state"
        assert provider.calls == calls_before
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_state_signed_by_non_adapter_is_rejected_before_workload_fetch(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, _ = make_crypto_material(token, action)
    other_pair = generate_ed25519_keypair()
    crypto_registry.add(
        make_trust_key_record(
            key_id="key:other-state",
            signer_id="adapter:other",
            trust_domain=STATE_TRUST_DOMAIN,
            public_key_b64=other_pair["public_key_b64"],
            purposes=[PURPOSE_STATE_WITNESS],
            valid_from=1,
            valid_until=1000,
        )
    )
    wrong_state = sign_contract_envelope(
        action["state_witness"],
        digest_field="witness_sha256",
        purpose=PURPOSE_STATE_WITNESS,
        key_id="key:other-state",
        signer_id="adapter:other",
        trust_domain=STATE_TRUST_DOMAIN,
        private_key_b64=other_pair["private_key_b64"],
        issued_at=150,
        valid_until=1000,
    )
    calls_before = provider.calls
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(signed_token, wrong_state, 150)
        assert exc_info.value.code == "state_signer_mismatch"
        assert provider.calls == calls_before
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_signed_path_still_rejects_workload_mapping_drift(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, signed_state = make_crypto_material(token, action)
    provider.identity = replace(
        provider.identity,
        identity_mapping_sha256="9" * 64,
    )
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(signed_token, signed_state, 150)
        assert exc_info.value.code == "EXECUTION_WORKLOAD_IDENTITY_PROVENANCE_MISMATCH"
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_signed_path_allows_certificate_rotation_for_same_stable_identity(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, signed_state = make_crypto_material(token, action)
    provider.identity = replace(
        provider.identity,
        certificate_fingerprint_sha256="7" * 64,
    )
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        row = boundary.prepare(signed_token, signed_state, 150)
        assert row["state"] == "PREPARED"
    finally:
        ledger.close()


def test_signed_same_token_same_workload_retry_is_idempotent(tmp_path):
    provider, workload_registry = registered_provider()
    token, action = issue_token(provider, workload_registry)
    crypto_registry, _, _, signed_token, signed_state = make_crypto_material(token, action)
    ledger, boundary = make_composed_boundary(
        tmp_path, provider, workload_registry, crypto_registry
    )
    try:
        first = boundary.prepare(signed_token, signed_state, 150)
        second = boundary.prepare(signed_token, signed_state, 150)
        assert second == first
        assert ledger.get(token["nonce"]) == first
    finally:
        ledger.close()
