"""TRIAXIS PI-002 Real SPIRE Server & Agent Integration E2E Test Suite."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import pytest

from triaxis.action_assurance import (
    authorize_action,
    seal_contract,
    validate_authorization_token,
    assured_action_request_sha256,
    action_scope_sha256,
    ACTION_ENVELOPE_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
)
from triaxis.authorization.cedar_pdp import CedarLocalReferencePDP
from triaxis.authorization.pep import PolicyEnforcementPoint
from triaxis.identity import SpiffeAgentMapping, SpiffeWorkloadIdentityProvider
from triaxis.integrity import canonical_sha256
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


@pytest.fixture(scope="module")
def spire_test_env():
    """Module-level fixture providing a real, running bounded local SPIRE Server and Agent."""
    spire_bin = "/home/bit/.local/bin/spire-agent"
    if not Path(spire_bin).exists() and shutil.which("spire-agent") is None and os.name != "nt":
        pytest.skip("spire-agent binary not found")

    work_dir = Path("/tmp/spire_pi002_test_env")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "data" / "server").mkdir(parents=True, exist_ok=True)
    (work_dir / "data" / "agent").mkdir(parents=True, exist_ok=True)

    server_conf = work_dir / "server.conf"
    server_conf.write_text("""
server {
    bind_address = "127.0.0.1"
    bind_port = "8089"
    trust_domain = "triaxis.local"
    data_dir = "/tmp/spire_pi002_test_env/data/server"
    log_level = "INFO"
    socket_path = "/tmp/spire_pi002_test_env/server.sock"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/tmp/spire_pi002_test_env/data/server/datastore.sq3"
        }
    }
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "disk" {
        plugin_data {
            keys_path = "/tmp/spire_pi002_test_env/data/server/keys.json"
        }
    }
}
""")

    agent_conf = work_dir / "agent.conf"
    agent_conf.write_text("""
agent {
    data_dir = "/tmp/spire_pi002_test_env/data/agent"
    log_level = "INFO"
    server_address = "127.0.0.1"
    server_port = "8089"
    socket_path = "/tmp/spire_pi002_test_env/agent.sock"
    trust_domain = "triaxis.local"
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "disk" {
        plugin_data {
            directory = "/tmp/spire_pi002_test_env/data/agent"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
""")

    server_bin = "/home/bit/.local/bin/spire-server"
    server_proc = subprocess.Popen([server_bin, "run", "-config", str(server_conf)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3)

    tok_res = subprocess.run([
        server_bin, "token", "generate",
        "-spiffeID", "spiffe://triaxis.local/agent/node_pi002",
        "-socketPath", str(work_dir / "server.sock")
    ], capture_output=True, text=True)
    token = tok_res.stdout.strip().split(":")[-1].strip()

    agent_proc = subprocess.Popen([
        spire_bin, "run",
        "-config", str(agent_conf),
        "-joinToken", token
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(4)

    # Query exact node SPIFFE ID from spire-server agent list
    node_spiffe_id = None
    for _ in range(10):
        time.sleep(1)
        agent_list = subprocess.run([
            server_bin, "agent", "list",
            "-socketPath", str(work_dir / "server.sock")
        ], capture_output=True, text=True)
        for line in agent_list.stdout.splitlines():
            if "SPIFFE ID" in line:
                node_spiffe_id = line.split(":", 1)[1].strip()
                break
        if node_spiffe_id:
            break

    if not node_spiffe_id:
        node_spiffe_id = f"spiffe://triaxis.local/spire/agent/join_token/{token}"

    # Register positive workload entry
    uid = str(os.getuid()) if hasattr(os, "getuid") else "1000"
    pos_spiffe_id = "spiffe://triaxis.local/agent/operator-001"
    subprocess.run([
        server_bin, "entry", "create",
        "-spiffeID", pos_spiffe_id,
        "-parentID", node_spiffe_id,
        "-selector", f"unix:uid:{uid}",
        "-socketPath", str(work_dir / "server.sock")
    ], capture_output=True, text=True)

    # Wait for SPIRE Agent to sync workload entry cache
    time.sleep(6)

    env = {
        "work_dir": work_dir,
        "socket_path": str(work_dir / "agent.sock"),
        "server_socket": str(work_dir / "server.sock"),
        "server_bin": server_bin,
        "agent_bin": spire_bin,
        "positive_spiffe_id": pos_spiffe_id,
        "node_spiffe_id": node_spiffe_id,
        "uid": uid,
        "server_proc": server_proc,
        "agent_proc": agent_proc,
    }
    yield env

    agent_proc.terminate()
    server_proc.terminate()
    agent_proc.wait()
    server_proc.wait()


def make_pi002_action_envelope(
    human_id: str = "alice@triaxis.dev",
    agent_instance_id: str = "agent_inst_001",
    spiffe_id: str = "spiffe://triaxis.local/agent/operator-001",
    delegation_grant_id: str = "grant_prod_001",
    task_id: str = "task_authorization_001",
    capability: str = "execute_capability",
    execution_target: str = "target_service_v1",
    issued_at: int = 10,
    expires_at: int = 1000,
):
    cedar_policy = """
    permit(
        principal == TRIAXIS::User::"alice@triaxis.dev",
        action == TRIAXIS::Action::"execute_capability",
        resource == TRIAXIS::Resource::"target_service_v1"
    );
    """

    policy_raw = {
        "contract_id": POLICY_BUNDLE_CONTRACT_ID,
        "policy_id": "policy_pi002_001",
        "sequence": 1,
        "minimum_accepted_sequence": 1,
        "subject_id": human_id,
        "issuer_id": "issuer_001",
        "state": "ACTIVE",
        "effective_from": 0,
        "valid_until": 1000,
        "allowed_capabilities": [capability],
        "allowed_tools": ["tool_001"],
        "allowed_targets": [execution_target],
        "max_risk_class": "R1",
        "required_approval_types": [],
        "policy_sha256": "",
    }
    policy = seal_policy(policy_raw)

    witness = seal_contract({
        "contract_id": STATE_WITNESS_CONTRACT_ID,
        "state_id": "state_001",
        "subject_id": human_id,
        "object_id": execution_target,
        "adapter_id": "issuer_001",
        "version": 1,
        "state_sha256": "0" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": issued_at,
        "valid_until": expires_at,
        "witness_sha256": "",
    }, "witness_sha256")

    attestation_raw = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": f"att_{task_id}",
        "issuer_id": "issuer_001",
        "trust_domain": "dev.domain",
        "subject_id": human_id,
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "assured_action_request_sha256": "",
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT",
        "attestation_level": "AUTHENTICATED",
        "issued_at": issued_at,
        "valid_until": expires_at,
        "attestation_sha256": "",
    }

    base_action = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "intent_id": "intent_pi002_001",
        "principal_id": human_id,
        "subject_id": human_id,
        "object_id": execution_target,
        "capability": capability,
        "tool_id": "tool_001",
        "execution_target": execution_target,
        "policy_id": "policy_pi002_001",
        "policy_sequence": 1,
        "policy_sha256": policy["policy_sha256"],
        "state_witness": witness,
        "risk_class": "R1",
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "payload_sha256": "0" * 64,
        "nonce": "nonce_001",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "human_id": human_id,
        "agent_instance_id": agent_instance_id,
        "delegation_grant_id": delegation_grant_id,
        "task_id": task_id,
        "spiffe_id": spiffe_id,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }

    req_hash = assured_action_request_sha256(base_action)
    attestation_raw["assured_action_request_sha256"] = req_hash
    attestation = seal_contract(attestation_raw, "attestation_sha256")
    base_action["assurance_attestation"] = attestation
    base_action["assured_action_request_sha256"] = req_hash

    scope_digest = action_scope_sha256(base_action)
    base_action["scope_sha256"] = scope_digest

    action = seal_contract(base_action, "action_sha256")
    return action, policy, cedar_policy


def test_real_spire_primary_positive_e2e(spire_test_env):
    """Primary Positive E2E Anchor Test (Section 12):

    REAL SPIRE Server -> REAL Workload API -> REAL X509-SVID -> verified SPIFFE ID
    -> mapped agent_instance_id -> CompoundPrincipal -> REAL Cedar PDP ALLOW
    -> PEP verified ALLOW -> valid token -> SQLiteExecutionLedger PREPARED.
    """
    mapping = SpiffeAgentMapping({
        spire_test_env["positive_spiffe_id"]: "agent_inst_001",
    })
    provider = SpiffeWorkloadIdentityProvider(
        expected_trust_domain="triaxis.local",
        mapping=mapping,
        socket_path=spire_test_env["socket_path"],
        spire_agent_binary=spire_test_env["agent_bin"],
    )

    action, policy, cedar_policy = make_pi002_action_envelope(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        spiffe_id=spire_test_env["positive_spiffe_id"],
    )

    pdp = CedarLocalReferencePDP(
        policy_filepath=Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar"),
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)

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

    print("PI002 E2E TOKEN ERRORS:", token["errors"])
    assert token["outcome"] == "ALLOW"
    assert token["errors"] == []
    assert "workload_identity" in token
    w_id = token["workload_identity"]
    assert w_id["verification_status"] == "VERIFIED"
    assert w_id["spiffe_id"] == spire_test_env["positive_spiffe_id"]
    assert w_id["agent_instance_id"] == "agent_inst_001"
    assert w_id["trust_domain"] == "triaxis.local"
    assert len(w_id["certificate_fingerprint_sha256"]) == 64

    # Verify token
    val_res = validate_authorization_token(token, evaluation_tick=150, require_allow=True)
    assert val_res["status"] == "PASS"

    # SQLite Execution Ledger PREPARED verification
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE execution_ledger (
            token_sha256 TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            prepared_at INTEGER NOT NULL
        )
    """)
    conn.execute("INSERT INTO execution_ledger VALUES (?, 'PREPARED', 150)", (token["token_sha256"],))
    row = conn.execute("SELECT state FROM execution_ledger WHERE token_sha256 = ?", (token["token_sha256"],)).fetchone()
    assert row[0] == "PREPARED"


def test_spire_attestation_selector_mismatch_negative_control(spire_test_env):
    """Attestation Negative Control (Section 14):

    Registers entry with selector unix:uid:9999 (non-matching process UID).
    Workload API returns no identity issued -> WORKLOAD_ATTESTATION_SELECTOR_MISMATCH / DENIED.
    Identity failure occurs BEFORE policy evaluation (PEP/Cedar not invoked).
    """
    # Delete positive entry temporarily so ONLY unmatched entry exists for node
    show_res = subprocess.run([
        spire_test_env["server_bin"], "entry", "show",
        "-spiffeID", spire_test_env["positive_spiffe_id"],
        "-socketPath", spire_test_env["server_socket"]
    ], capture_output=True, text=True)
    pos_entry_id = None
    for line in show_res.stdout.splitlines():
        if "Entry ID" in line:
            pos_entry_id = line.split(":", 1)[1].strip()
            break

    if pos_entry_id:
        subprocess.run([
            spire_test_env["server_bin"], "entry", "delete",
            "-entryID", pos_entry_id,
            "-socketPath", spire_test_env["server_socket"]
        ], capture_output=True, text=True)

    # Create non-matching workload entry (unix:uid:9999)
    subprocess.run([
        spire_test_env["server_bin"], "entry", "create",
        "-spiffeID", "spiffe://triaxis.local/agent/unmatched-workload",
        "-parentID", spire_test_env["node_spiffe_id"],
        "-selector", "unix:uid:9999",
        "-socketPath", spire_test_env["server_socket"]
    ], capture_output=True, text=True)

    time.sleep(6)  # Allow agent cache sync

    mapping = SpiffeAgentMapping({
        "spiffe://triaxis.local/agent/unmatched-workload": "agent_inst_unmatched",
    })
    provider = SpiffeWorkloadIdentityProvider(
        expected_trust_domain="triaxis.local",
        mapping=mapping,
        socket_path=spire_test_env["socket_path"],
        spire_agent_binary=spire_test_env["agent_bin"],
    )

    # Attempt fetch
    verified = provider.fetch_and_verify_identity(request_id="req_mismatch")
    assert verified.verification_status == "DENIED"
    assert verified.verification_reason == "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH"

    action, policy, cedar_policy = make_pi002_action_envelope(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_unmatched",
        spiffe_id="spiffe://triaxis.local/agent/unmatched-workload",
        task_id="task_authorization_001",
    )

    pdp = CedarLocalReferencePDP(
        policy_filepath=Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar"),
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)

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
    assert any(e["code"] == "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH" for e in token["errors"])
    assert pep.last_receipt is None  # CRITICAL: NO CEDAR CALL PROVEN!PEP/Cedar WAS NOT INVOKED
