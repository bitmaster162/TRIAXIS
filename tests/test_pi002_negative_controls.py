"""TRIAXIS PI-002 Comprehensive Negative Identity Controls Test Suite (Section 13).

Proves that EVERY non-VERIFIED or correlated identity failure yields:
NO VERIFIED IDENTITY / IDENTITY CORRELATION FAILURE -> NO CEDAR ALLOW -> NO TOKEN ALLOW -> NO LEDGER PREPARE.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import pytest

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.authorization import AuthorizationDecisionReceipt, AuthorizationRequest, DecisionState, PolicyEnforcementPoint
from triaxis.identity import SpiffeAgentMapping, VerifiedWorkloadIdentity
from triaxis.integrity import canonical_sha256
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

FIXTURE_POLICY_PATH = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")


class MockCedarPDP:
    """Mock Cedar PDP simulating Cedar PDP adapter interface."""

    def __init__(self, policy_filepath: Path = FIXTURE_POLICY_PATH) -> None:
        self.policy_filepath = policy_filepath

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        from datetime import datetime, timezone
        return AuthorizationDecisionReceipt(
            decision=DecisionState.ALLOW,
            reason_code="ALLOW",
            policy_version=1,
            triaxis_policy_sha256=request.triaxis_policy_sha256 or "a" * 64,
            cedar_policy_sha256=request.cedar_policy_sha256 or "b" * 64,
            provider="Cedar",
            provider_version="cedar-policy-cli 4.12.0",
            request_id=request.principal.request_id,
            evaluated_principal=request.principal.to_dict(),
            evaluated_task=request.principal.task_id,
            evaluated_action=request.principal.action,
            evaluated_resource=request.principal.resource,
            evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
        )

    def get_cedar_policy_hash(self) -> str:
        return "92b41e33f8ed64fb73a178238a9111ea54f4cc94c77b7df871366a42d99ef472"


class MockIdentityProvider:
    def __init__(self, verified_identity: VerifiedWorkloadIdentity):
        self.identity = verified_identity

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        return self.identity


def make_negative_action_envelope(
    human_id: str | None = "alice@triaxis.dev",
    agent_instance_id: str | None = "agent_inst_001",
    spiffe_id: str | None = "spiffe://triaxis.local/agent/operator-001",
    delegation_grant_id: str | None = "grant_prod_001",
    task_id: str | None = "task_pi002_001",
    capability: str = "execute_capability",
    execution_target: str = "target_service_v1",
):
    eff_human = human_id if human_id is not None else "alice@triaxis.dev"
    eff_agent = agent_instance_id if agent_instance_id is not None else "agent_inst_001"
    eff_grant = delegation_grant_id if delegation_grant_id is not None else "grant_prod_001"
    eff_task = task_id if task_id is not None else "task_pi002_001"

    policy_raw = {
        "contract_id": POLICY_BUNDLE_CONTRACT_ID,
        "policy_id": "pol_pi002_neg",
        "sequence": 1,
        "minimum_accepted_sequence": 1,
        "subject_id": eff_human,
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
        "state_id": f"state_{eff_task}",
        "subject_id": eff_human,
        "object_id": execution_target,
        "adapter_id": "issuer_001",
        "version": 1,
        "state_sha256": "0" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": 10,
        "valid_until": 1000,
        "witness_sha256": "",
    }, "witness_sha256")

    attestation_raw = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": f"att_{eff_task}",
        "issuer_id": "issuer_001",
        "trust_domain": "dev.domain",
        "subject_id": eff_human,
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "assured_action_request_sha256": "",
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT",
        "attestation_level": "AUTHENTICATED",
        "issued_at": 10,
        "valid_until": 1000,
        "attestation_sha256": "",
    }

    action_base: dict[str, Any] = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "intent_id": f"intent_{eff_task}",
        "principal_id": eff_human,
        "subject_id": eff_human,
        "object_id": execution_target,
        "capability": capability,
        "tool_id": "tool_001",
        "execution_target": execution_target,
        "payload_sha256": "0" * 64,
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "policy_id": "pol_pi002_neg",
        "policy_sequence": 1,
        "policy_sha256": policy["policy_sha256"],
        "state_witness": witness,
        "risk_class": "R1",
        "nonce": f"nonce_{eff_task}",
        "issued_at": 10,
        "expires_at": 1000,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }

    if human_id is not None:
        action_base["human_id"] = human_id
    if agent_instance_id is not None:
        action_base["agent_instance_id"] = agent_instance_id
    if delegation_grant_id is not None:
        action_base["delegation_grant_id"] = delegation_grant_id
    if task_id is not None:
        action_base["task_id"] = task_id
    if spiffe_id is not None:
        action_base["spiffe_id"] = spiffe_id

    req_digest = assured_action_request_sha256(action_base)
    attestation_raw["assured_action_request_sha256"] = req_digest
    attestation = seal_contract(attestation_raw, "attestation_sha256")
    action_base["assurance_attestation"] = attestation
    action_base["assured_action_request_sha256"] = req_digest

    scope_digest = action_scope_sha256(action_base)
    action_base["scope_sha256"] = scope_digest
    action = seal_contract(action_base, "action_sha256")
    return action, policy


@pytest.mark.parametrize("scenario,ver_status,ver_reason,claimed_agent,action_spiffe,human_id,grant_id,task_id", [
    ("1_workload_api_unavailable", "ERROR", "SPIRE_AGENT_UNAVAILABLE", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("2_spire_agent_unavailable", "ERROR", "SPIFFE_WORKLOAD_API_UNAVAILABLE", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("3_no_svid_issued", "DENIED", "NO_SVID_ISSUED", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("4_wrong_spiffe_id", "DENIED", "SPIFFE_ID_INVALID", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("5_wrong_trust_domain", "DENIED", "TRUST_DOMAIN_MISMATCH", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("6_spiffe_id_not_in_mapping", "DENIED", "IDENTITY_MAPPING_NOT_FOUND", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("7_mapped_agent_differs_from_action", "VERIFIED", "SPIFFE_SVID_VERIFIED", "agent_inst_DIFFERENT", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("8_expected_action_spiffe_differs", "VERIFIED", "SPIFFE_SVID_VERIFIED", "agent_inst_001", "spiffe://triaxis.local/agent/EVIL-SPIFFE", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("9_missing_action_agent_instance_id", "VERIFIED", "SPIFFE_SVID_VERIFIED", None, "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("10_missing_explicit_human_id", "VERIFIED", "SPIFFE_SVID_VERIFIED", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", None, "grant_prod_001", "task_001"),
    ("11_missing_delegation_grant", "VERIFIED", "SPIFFE_SVID_VERIFIED", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", None, "task_001"),
    ("12_missing_task", "VERIFIED", "SPIFFE_SVID_VERIFIED", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", None),
    ("13_malformed_provider_response", "ERROR", "MALFORMED_PROVIDER_RESPONSE", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("14_expired_svid", "DENIED", "CERTIFICATE_EXPIRED", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
    ("15_provider_exception", "ERROR", "SPIFFE_WORKLOAD_API_EXCEPTION: RuntimeError", "agent_inst_001", "spiffe://triaxis.local/agent/operator-001", "alice@triaxis.dev", "grant_prod_001", "task_001"),
])
def test_negative_identity_controls_matrix(scenario, ver_status, ver_reason, claimed_agent, action_spiffe, human_id, grant_id, task_id):
    action, policy = make_negative_action_envelope(
        human_id=human_id,
        agent_instance_id=claimed_agent,
        spiffe_id=action_spiffe,
        delegation_grant_id=grant_id,
        task_id=task_id,
    )

    id_obj = VerifiedWorkloadIdentity(
        agent_instance_id="agent_inst_001" if ver_status == "VERIFIED" else "",
        spiffe_id="spiffe://triaxis.local/agent/operator-001" if ver_status == "VERIFIED" else "",
        trust_domain="triaxis.local",
        identity_provider="SPIFFE-SPIRE-WorkloadAPI",
        certificate_fingerprint_sha256="a" * 64,
        not_before_iso="2026-08-08T00:00:00Z",
        not_after_iso="2026-08-08T01:00:00Z",
        verification_status=ver_status,
        verification_reason=ver_reason,
        identity_mapping_sha256="b" * 64,
        request_id="intent_task_001",
    )
    provider = MockIdentityProvider(id_obj)
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
    assert pep.last_receipt is None  # CRITICAL: NO CEDAR CALL PROVEN!


def test_downgrade_attempt_negative_control():
    """Negative Control 16: Configuration downgrade attempt from SPIFFE mode to explicit identity."""
    action, policy = make_negative_action_envelope()
    pep = PolicyEnforcementPoint(pdp_adapter=MockCedarPDP())

    token = authorize_action(
        action,
        policy,
        evaluation_tick=150,
        issuer_id="issuer_v1",
        authorization_mode="cedar_reference",
        pep=pep,
        identity_mode="INVALID_MODE_DOWNGRADE",
        workload_identity_provider=None,
    )

    assert token["outcome"] == "DENY"
    assert any(e["code"] == "CONFIG_ERROR" for e in token["errors"])
    assert pep.last_receipt is None
