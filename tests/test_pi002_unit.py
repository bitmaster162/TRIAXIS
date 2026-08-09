"""TRIAXIS PI-002 Unit Tests for Workload Identity Contracts, Mapping, and Provider Abstraction."""

from __future__ import annotations

import pytest

from triaxis.identity import (
    WORKLOAD_IDENTITY_CONTRACT_ID,
    SpiffeAgentMapping,
    SpiffeWorkloadIdentityProvider,
    VerifiedWorkloadIdentity,
    validate_verified_workload_identity,
)


def test_verified_workload_identity_contract_creation():
    id_obj = VerifiedWorkloadIdentity(
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
        request_id="req_001",
    )
    assert id_obj.contract_id == WORKLOAD_IDENTITY_CONTRACT_ID
    assert id_obj.agent_instance_id == "agent_inst_001"
    assert id_obj.spiffe_id == "spiffe://triaxis.local/agent/operator-001"

    d = id_obj.to_dict()
    assert d["contract_id"] == WORKLOAD_IDENTITY_CONTRACT_ID
    assert d["verification_status"] == "VERIFIED"

    val_res = validate_verified_workload_identity(d)
    assert val_res["status"] == "PASS"
    assert val_res["errors"] == []


def test_spiffe_agent_mapping_resolution_and_digest():
    mapping_dict = {
        "spiffe://triaxis.local/agent/operator-001": "agent_inst_001",
        "spiffe://triaxis.local/agent/operator-002": "agent_inst_002",
    }
    mapping = SpiffeAgentMapping(mapping_dict, version=1)

    assert mapping.resolve_agent_instance_id("spiffe://triaxis.local/agent/operator-001") == "agent_inst_001"
    assert mapping.resolve_agent_instance_id("spiffe://triaxis.local/agent/operator-002") == "agent_inst_002"
    assert mapping.resolve_agent_instance_id("spiffe://triaxis.local/agent/unknown") is None
    assert len(mapping.identity_mapping_sha256) == 64

    # Digest idempotency
    mapping2 = SpiffeAgentMapping(mapping_dict, version=1)
    assert mapping.identity_mapping_sha256 == mapping2.identity_mapping_sha256


def test_spiffe_provider_offline_handling():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/operator-001": "agent_inst_001"})
    provider = SpiffeWorkloadIdentityProvider(
        expected_trust_domain="triaxis.local",
        mapping=mapping,
        socket_path="/nonexistent/path/spire.sock",
        spire_agent_binary="/nonexistent/bin/spire-agent",
    )

    res = provider.fetch_and_verify_identity(request_id="req_offline")
    assert res.verification_status in ("ERROR", "DENIED")
    assert "UNAVAILABLE" in res.verification_reason or "MISMATCH" in res.verification_reason or "ERROR" in res.verification_reason
