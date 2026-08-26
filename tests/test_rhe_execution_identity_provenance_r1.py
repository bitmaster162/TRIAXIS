"""RHE execution-time workload identity provenance hardening tests."""

from __future__ import annotations

from dataclasses import replace

import pytest

from triaxis.action_assurance import (
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    authorize_action,
)
from triaxis.authorization import PolicyEnforcementPoint
from triaxis.identity import (
    TrustedWorkloadIdentityProviderRegistry,
    VerifiedWorkloadIdentity,
)
from triaxis.rhe_execution_boundary import TrustedWorkloadExecutionBoundary
from tests.test_pi002_negative_controls import (
    MockCedarPDP,
    MockIdentityProvider,
    make_negative_action_envelope,
)


PROVIDER_ID = "rhe_test_spiffe"
SPIFFE_ID = "spiffe://triaxis.local/agent/operator-001"
AGENT_ID = "agent_inst_001"


def verified_identity(
    *,
    agent_instance_id: str = AGENT_ID,
    spiffe_id: str = SPIFFE_ID,
    trust_domain: str = "triaxis.local",
    fingerprint: str = "1" * 64,
    status: str = "VERIFIED",
    reason: str = "SPIFFE_SVID_VERIFIED",
) -> VerifiedWorkloadIdentity:
    return VerifiedWorkloadIdentity(
        agent_instance_id=agent_instance_id,
        spiffe_id=spiffe_id,
        trust_domain=trust_domain,
        identity_provider="rhe-test-provider",
        certificate_fingerprint_sha256=fingerprint,
        not_before_iso="2026-08-27T00:00:00Z",
        not_after_iso="2026-08-27T01:00:00Z",
        verification_status=status,
        verification_reason=reason,
        identity_mapping_sha256="2" * 64,
        request_id="",
    )


def registered_provider(identity: VerifiedWorkloadIdentity | None = None):
    provider = MockIdentityProvider(identity or verified_identity())
    registry = TrustedWorkloadIdentityProviderRegistry(allow_test_mocks=True)
    registry.register_provider(
        PROVIDER_ID,
        provider,
        expected_trust_domain="triaxis.local",
        mapping_sha256="2" * 64,
    )
    return provider, registry


def issue_token(provider, registry):
    action, policy = make_negative_action_envelope(
        agent_instance_id=AGENT_ID,
        spiffe_id=SPIFFE_ID,
        delegation_grant_id="grant_prod_001",
        task_id="task_001",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())
    token = authorize_action(
        action,
        policy,
        evaluation_tick=150,
        issuer_id="issuer_001",
        trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference",
        pep=pep,
        identity_mode="spiffe_workload",
        workload_identity_provider=provider,
        trusted_provider_registry=registry,
        provider_id=PROVIDER_ID,
    )
    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow
    return token, action


def make_boundary(tmp_path, provider, registry):
    ledger = SQLiteExecutionLedger(tmp_path / "rhe_provenance.sqlite")
    boundary = TrustedWorkloadExecutionBoundary(
        ledger,
        trusted_provider_registry=registry,
        provider_id=PROVIDER_ID,
        provider_instance=provider,
    )
    return ledger, boundary


def test_trusted_provider_matching_identity_reaches_prepared(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        row = boundary.prepare(token, action["state_witness"], 150)
        assert row["state"] == "PREPARED"
        assert row["outcome_sha256"] is None
        assert row["effect_id"] is None
        assert row["receipt"] is None
    finally:
        ledger.close()


def test_same_token_same_trusted_workload_is_idempotent(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        first = boundary.prepare(token, action["state_witness"], 150)
        second = boundary.prepare(token, action["state_witness"], 150)
        assert second == first
        assert ledger.get(token["nonce"]) == first
    finally:
        ledger.close()


def test_rotated_certificate_same_stable_identity_is_allowed(tmp_path):
    provider, registry = registered_provider(
        verified_identity(fingerprint="1" * 64)
    )
    token, action = issue_token(provider, registry)
    provider.identity = replace(
        provider.identity,
        certificate_fingerprint_sha256="3" * 64,
        request_id="",
    )
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        row = boundary.prepare(token, action["state_witness"], 150)
        assert row["state"] == "PREPARED"
    finally:
        ledger.close()


def test_unregistered_provider_is_rejected_at_boundary_construction(tmp_path):
    provider = MockIdentityProvider(verified_identity())
    registry = TrustedWorkloadIdentityProviderRegistry(allow_test_mocks=True)
    ledger = SQLiteExecutionLedger(tmp_path / "untrusted.sqlite")
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            TrustedWorkloadExecutionBoundary(
                ledger,
                trusted_provider_registry=registry,
                provider_id=PROVIDER_ID,
                provider_instance=provider,
            )
        assert exc_info.value.code == "UNTRUSTED_IDENTITY_PROVIDER"
    finally:
        ledger.close()


def test_missing_registry_is_rejected(tmp_path):
    provider = MockIdentityProvider(verified_identity())
    ledger = SQLiteExecutionLedger(tmp_path / "missing_registry.sqlite")
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            TrustedWorkloadExecutionBoundary(
                ledger,
                trusted_provider_registry=None,
                provider_id=PROVIDER_ID,
                provider_instance=provider,
            )
        assert exc_info.value.code == "UNTRUSTED_IDENTITY_PROVIDER"
    finally:
        ledger.close()


def test_missing_provider_instance_is_rejected(tmp_path):
    registry = TrustedWorkloadIdentityProviderRegistry(allow_test_mocks=True)
    ledger = SQLiteExecutionLedger(tmp_path / "missing_provider.sqlite")
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            TrustedWorkloadExecutionBoundary(
                ledger,
                trusted_provider_registry=registry,
                provider_id=PROVIDER_ID,
                provider_instance=None,
            )
        assert exc_info.value.code == "UNTRUSTED_IDENTITY_PROVIDER"
    finally:
        ledger.close()


def test_identity_becomes_unverified_before_prepare_fails_closed(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    provider.identity = replace(
        provider.identity,
        verification_status="DENIED",
        verification_reason="WORKLOAD_ATTESTATION_SELECTOR_MISMATCH",
    )
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, action["state_witness"], 150)
        assert exc_info.value.code == "EXECUTION_WORKLOAD_IDENTITY_MISMATCH"
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_cross_workload_identity_change_before_prepare_is_rejected(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    provider.identity = replace(
        provider.identity,
        agent_instance_id="agent_inst_other",
        spiffe_id="spiffe://triaxis.local/agent/other",
    )
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, action["state_witness"], 150)
        assert exc_info.value.code == "EXECUTION_WORKLOAD_IDENTITY_MISMATCH"
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_trust_domain_change_before_prepare_is_rejected(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    provider.identity = replace(provider.identity, trust_domain="evil.example")
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, action["state_witness"], 150)
        assert exc_info.value.code == "EXECUTION_WORKLOAD_IDENTITY_MISMATCH"
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_caller_cannot_inject_preconstructed_current_identity(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)
    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(TypeError):
            boundary.prepare(
                token,
                action["state_witness"],
                150,
                current_workload_identity=verified_identity(),
            )
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()
