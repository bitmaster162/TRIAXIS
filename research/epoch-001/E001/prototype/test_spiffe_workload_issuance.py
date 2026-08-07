import time
import pytest
from spiffe_identity_model import SPIFFEID, WorkloadAttestor, SPIREServerSimulator, SPIREAgentSimulator, SVID

def test_spiffe_id_formatting():
    sid = SPIFFEID("triaxis.internal", "/ns/prod/sa/harness")
    assert sid.uri() == "spiffe://triaxis.internal/ns/prod/sa/harness"

def test_workload_attestation_success():
    server = SPIREServerSimulator("triaxis.internal")
    current_selectors = WorkloadAttestor.attest_current_process()
    server.register_workload("entry-001", "/ns/prod/sa/harness-engine", current_selectors)
    
    agent = SPIREAgentSimulator(server)
    svid, status = agent.fetch_workload_svid()
    assert status == "SUCCESS"
    assert svid is not None
    assert svid.spiffe_id.uri() == "spiffe://triaxis.internal/ns/prod/sa/harness-engine"
    assert server.verify_svid(svid) is True

def test_workload_attestation_failure_on_mismatched_selectors():
    server = SPIREServerSimulator("triaxis.internal")
    bogus_selectors = {"uid": 99999, "executable": "/usr/bin/malicious"}
    server.register_workload("entry-002", "/ns/prod/sa/secure-vault", bogus_selectors)
    
    agent = SPIREAgentSimulator(server)
    svid, status = agent.fetch_workload_svid()
    assert svid is None
    assert "ATTESTATION_FAILED" in status

def test_svid_expiration_and_tamper_rejection():
    server = SPIREServerSimulator("triaxis.internal")
    current_selectors = WorkloadAttestor.attest_current_process()
    server.register_workload("entry-001", "/ns/prod/sa/harness-engine", current_selectors)
    
    start_time = 100000.0
    svid, _ = server.issue_svid(current_selectors, ttl_seconds=300.0, current_time=start_time)
    
    # Valid before expiration
    assert server.verify_svid(svid, current_time=start_time + 100.0) is True
    
    # Expired after 300s
    assert server.verify_svid(svid, current_time=start_time + 301.0) is False
    
    # Tampered signature rejected
    tampered_svid = SVID(svid.spiffe_id, svid.issued_at, svid.ttl_seconds, "forged_signature_hash", svid.payload)
    assert server.verify_svid(tampered_svid, current_time=start_time + 100.0) is False

def test_svid_jwt_token_generation():
    server = SPIREServerSimulator("triaxis.internal")
    current_selectors = WorkloadAttestor.attest_current_process()
    server.register_workload("entry-001", "/ns/prod/sa/harness-engine", current_selectors)
    svid, _ = server.issue_svid(current_selectors)
    jwt_str = svid.to_jwt()
    assert "spiffe://triaxis.internal/ns/prod/sa/harness-engine" in jwt_str or len(jwt_str.split(".")) == 3
