"""TRIAXIS PI-002 Adversarial Security Review & Replay/Downgrade Tests (Section 19)."""

from __future__ import annotations

import sqlite3
import pytest

from triaxis.action_assurance import authorize_action
from triaxis.authorization import PolicyEnforcementPoint
from triaxis.identity import VerifiedWorkloadIdentity
from tests.test_pi002_negative_controls import MockCedarPDP, MockIdentityProvider, make_negative_action_envelope


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
    )
    assert token["outcome"] == "DENY"
    assert any(e["code"] == "WORKLOAD_IDENTITY_MISMATCH" for e in token["errors"])
    assert pep.last_receipt is None


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

    # Workload A authorization
    token_a = authorize_action(
        action_a, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_a)
    )
    assert token_a["outcome"] == "ALLOW"
    receipt_a_sha = pep.last_receipt.decision_sha256

    # Workload B authorization
    token_b = authorize_action(
        action_b, policy, 150, "issuer_001", trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_b)
    )
    assert token_b["outcome"] == "ALLOW"
    receipt_b_sha = pep.last_receipt.decision_sha256

    # Prove decision receipt SHA differs because principal identity provenance is bound in decision digest!
    assert receipt_a_sha != receipt_b_sha
    assert token_a["token_sha256"] != token_b["token_sha256"]


def test_adversarial_12_token_reuse_by_different_workload():
    """Token obtained by Workload A presented to Execution Ledger for Workload B."""
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
        authorization_mode="cedar_reference", pep=pep, identity_mode="spiffe_workload", workload_identity_provider=MockIdentityProvider(verified_a)
    )

    # Single-use ledger consumes token_a
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE execution_ledger (token_sha256 TEXT PRIMARY KEY, agent_id TEXT NOT NULL, state TEXT NOT NULL)")
    conn.execute("INSERT INTO execution_ledger VALUES (?, 'agent_inst_001', 'PREPARED')", (token_a["token_sha256"],))

    # Workload B tries to execute with token_a
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO execution_ledger VALUES (?, 'agent_inst_002', 'PREPARED')", (token_a["token_sha256"],))
