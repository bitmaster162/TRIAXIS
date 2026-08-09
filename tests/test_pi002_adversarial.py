"""TRIAXIS PI-002 Adversarial Security Review & Replay/Downgrade/Rotation Tests."""

from __future__ import annotations

from pathlib import Path
import tempfile
import pytest

from triaxis.action_assurance import ExecutionLedgerError, SQLiteExecutionLedger, authorize_action
from triaxis.authorization import PolicyEnforcementPoint
from triaxis.identity import TrustedWorkloadIdentityProviderRegistry, VerifiedWorkloadIdentity
from tests.test_pi002_negative_controls import MockCedarPDP, MockIdentityProvider, make_negative_action_envelope


class FakeIdentityProviderReturningVerified:
    """Adversarial fake identity provider returning VERIFIED status without real attestation."""

    def __init__(self, spiffe_id: str = "spiffe://triaxis.local/agent/operator-001", agent_instance_id: str = "agent_inst_001"):
        self.spiffe_id = spiffe_id
        self.agent_instance_id = agent_instance_id

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        return VerifiedWorkloadIdentity(
            agent_instance_id=self.agent_instance_id,
            spiffe_id=self.spiffe_id,
            trust_domain="triaxis.local",
            identity_provider="SPIFFE-SPIRE-WorkloadAPI",
            certificate_fingerprint_sha256="a" * 64,
            not_before_iso="2026-08-08T00:00:00Z",
            not_after_iso="2026-08-08T01:00:00Z",
            verification_status="VERIFIED",
            verification_reason="SPIFFE_SVID_VERIFIED",
            identity_mapping_sha256="b" * 64,
            request_id=request_id,
        )


def test_adversarial_1_caller_spoofs_agent_instance_id():
    """Caller spoofs agent_instance_id in action envelope while runtime identity is agent_inst_001."""
    action, policy = make_negative_action_envelope(
        agent_instance_id="SPOOFED_AGENT_INSTANCE_ID",
        spiffe_id="spiffe://triaxis.local/agent/operator-001",
    )
    verified = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001",
        spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local",
        identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="a" * 64,
        not_before_iso="2026-08-08T00:00:00Z",
        not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED",
        verification_reason="SPIFFE_SVID_VERIFIED",
        identity_mapping_sha256="b" * 64,
        request_id="intent_pi002_neg",
    )
    provider = MockIdentityProvider(verified)
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
        allow_unregistered_providers=True,
    )
    assert token["outcome"] == "DENY"
    assert any(e["code"] == "WORKLOAD_IDENTITY_MISMATCH" for e in token["errors"])
    assert pep.last_receipt is None


def test_adversarial_2_caller_spoofs_spiffe_id():
    """Caller claims spiffe_id spiffe://triaxis.local/agent/admin in action envelope."""
    action, policy = make_negative_action_envelope(
        agent_instance_id="agent_inst_001",
        spiffe_id="spiffe://triaxis.local/agent/admin",
    )
    verified = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001",
        spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local",
        identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="a" * 64,
        not_before_iso="2026-08-08T00:00:00Z",
        not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED",
        verification_reason="SPIFFE_SVID_VERIFIED",
        identity_mapping_sha256="b" * 64,
        request_id="intent_pi002_neg",
    )
    provider = MockIdentityProvider(verified)
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
        allow_unregistered_providers=True,
    )
    assert token["outcome"] == "DENY"
    assert any(e["code"] == "WORKLOAD_IDENTITY_MISMATCH" for e in token["errors"])
    assert pep.last_receipt is None


def test_untrusted_identity_provider_fake_object_negative_control():
    """Section 1: Fake provider returning VERIFIED status rejected by trusted boundary."""
    action, policy = make_negative_action_envelope(
        agent_instance_id="agent_inst_001",
        spiffe_id="spiffe://triaxis.local/agent/operator-001",
    )
    fake_provider = FakeIdentityProviderReturningVerified()
    registry = TrustedWorkloadIdentityProviderRegistry(allow_test_mocks=False)
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
        workload_identity_provider=fake_provider,
        trusted_provider_registry=registry,
        provider_id="spiffe_spire_local",
    )

    assert token["outcome"] == "DENY"
    assert any(e["code"] == "UNTRUSTED_IDENTITY_PROVIDER" for e in token["errors"])
    assert pep.last_receipt is None  # CRITICAL: NO CEDAR CALL!


def test_adversarial_11_receipt_replay_under_different_identity():
    """Cedar ALLOW receipt from workload A replayed under workload B's action."""
    action_a, policy = make_negative_action_envelope(agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001")
    action_b, _ = make_negative_action_envelope(agent_instance_id="agent_inst_002", spiffe_id="spiffe://triaxis.local/agent/operator-002")

    verified_a = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="a" * 64, not_before_iso="2026-08-08T00:00:00Z", not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_a",
    )
    verified_b = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_002", spiffe_id="spiffe://triaxis.local/agent/operator-002",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="c" * 64, not_before_iso="2026-08-08T00:00:00Z", not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_b",
    )

    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())

    token_a = authorize_action(
        action_a, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_a), allow_unregistered_providers=True
    )
    assert token_a["outcome"] == "ALLOW"
    receipt_a_sha = pep.last_receipt.decision_sha256

    token_b = authorize_action(
        action_b, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_b), allow_unregistered_providers=True
    )
    assert token_b["outcome"] == "ALLOW"
    receipt_b_sha = pep.last_receipt.decision_sha256

    assert receipt_a_sha != receipt_b_sha
    assert token_a["token_sha256"] != token_b["token_sha256"]


def test_adversarial_12_token_reuse_by_different_workload():
    """Section 6: Workload A obtains valid unused token T. Workload B presents A's token T as FIRST use."""
    action_a, policy = make_negative_action_envelope(agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001")
    verified_a = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="a" * 64, not_before_iso="2026-08-08T00:00:00Z", not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_a",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())
    token_a = authorize_action(
        action_a, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_a), allow_unregistered_providers=True
    )
    assert token_a["outcome"] == "ALLOW"

    verified_b = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_002", spiffe_id="spiffe://triaxis.local/agent/operator-002",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="c" * 64, not_before_iso="2026-08-08T00:00:00Z", not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_b",
    )

    with tempfile.NamedTemporaryFile(suffix=".sq3") as tmp_db:
        with SQLiteExecutionLedger(tmp_db.name) as ledger:
            # Workload B presents A's unused token as FIRST use
            with pytest.raises(ExecutionLedgerError) as exc_info:
                ledger.prepare_for_workload(
                    token_value=token_a,
                    observed_state_witness=action_a["state_witness"],
                    evaluation_tick=150,
                    current_workload_identity=verified_b,
                )
            assert exc_info.value.code == "EXECUTION_WORKLOAD_IDENTITY_MISMATCH"
            assert ledger.get(token_a["nonce"]) is None  # CRITICAL: Token A remained unprepared!

            # Workload A presents token A -> Reaches PREPARED!
            prep_row = ledger.prepare_for_workload(
                token_value=token_a,
                observed_state_witness=action_a["state_witness"],
                evaluation_tick=150,
                current_workload_identity=verified_a,
            )
            assert prep_row["state"] == "PREPARED"


def test_rotation_safe_ownership_control():
    """Section 7: Rotation-safe workload identity correlation across SVID cert fingerprint rotation."""
    action_a, policy = make_negative_action_envelope(agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001")
    verified_cert_a1 = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="11" * 32, not_before_iso="2026-08-08T00:00:00Z", not_after_iso="2026-08-08T01:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_a",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())
    token_a = authorize_action(
        action_a, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_cert_a1), allow_unregistered_providers=True
    )

    # SVID rotates -> new cert fingerprint A2, same SPIFFE ID & agent mapping
    verified_cert_a2 = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001", spiffe_id="spiffe://triaxis.local/agent/operator-001",
        trust_domain="triaxis.local", identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="22" * 32, not_before_iso="2026-08-08T01:00:00Z", not_after_iso="2026-08-08T02:00:00Z",
        verification_status="VERIFIED", verification_reason="SPIFFE_SVID_VERIFIED", identity_mapping_sha256="b" * 64, request_id="intent_a_rot",
    )

    assert verified_cert_a1.certificate_fingerprint_sha256 != verified_cert_a2.certificate_fingerprint_sha256

    with tempfile.NamedTemporaryFile(suffix=".sq3") as tmp_db:
        with SQLiteExecutionLedger(tmp_db.name) as ledger:
            # Rotated Workload A (fingerprint A2) presents token authorized under fingerprint A1 -> PREPARED allowed!
            row = ledger.prepare_for_workload(
                token_value=token_a,
                observed_state_witness=action_a["state_witness"],
                evaluation_tick=150,
                current_workload_identity=verified_cert_a2,
            )
            assert row["state"] == "PREPARED"
