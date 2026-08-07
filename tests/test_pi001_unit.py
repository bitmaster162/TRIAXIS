"""TRIAXIS PI-001 Unit Test Suite."""

import pytest
from triaxis.authorization import (
    AuthorizationDecisionReceipt,
    AuthorizationMode,
    AuthorizationRequest,
    CedarLocalReferencePDP,
    CompoundPrincipal,
    DecisionState,
    PolicyEnforcementPoint,
)


def test_compound_principal_valid_construction():
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={"issuer": "spire-server"},
        request_id="req_001",
        spiffe_id="spiffe://triaxis.dev/agent/001",
    )
    d = principal.to_dict()
    assert d["human_id"] == "alice@triaxis.dev"
    assert d["spiffe_id"] == "spiffe://triaxis.dev/agent/001"

    rebuilt = CompoundPrincipal.from_dict(d)
    assert rebuilt == principal


def test_compound_principal_invalid_construction():
    with pytest.raises(ValueError, match="human_id must be a non-empty string"):
        CompoundPrincipal(
            human_id="",
            agent_instance_id="agent_inst_001",
            delegation_grant_id="grant_prod_001",
            task_id="task_001",
            action="execute_capability",
            resource="target_service_v1",
            identity_provenance={},
            request_id="req_001",
        )


def test_authzen_payload_formatting():
    principal = CompoundPrincipal(
        human_id="bob@triaxis.dev",
        agent_instance_id="agent_inst_002",
        delegation_grant_id="grant_prod_002",
        task_id="task_002",
        action="read_db",
        resource="db_production",
        identity_provenance={"auth": "local"},
        request_id="req_002",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001", risk_class="R2")
    payload = req.to_authzen_payload()

    assert payload["subject"]["id"] == "user:bob@triaxis.dev"
    assert payload["action"]["name"] == "read_db"
    assert payload["resource"]["id"] == "db_production"
    assert payload["context"]["agent_instance_id"] == "agent_inst_002"
    assert payload["context"]["risk_class"] == "R2"


def test_authorization_mode_parsing():
    assert AuthorizationMode.parse("legacy") == AuthorizationMode.LEGACY
    assert AuthorizationMode.parse("cedar_reference") == AuthorizationMode.CEDAR_REFERENCE
    with pytest.raises(ValueError, match="Invalid or unsupported AuthorizationMode"):
        AuthorizationMode.parse("unknown_mode")


def test_pep_unconfigured_pdp_fails_closed():
    pep = PolicyEnforcementPoint(pdp_adapter=None)
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_001",
        delegation_grant_id="grant_001",
        task_id="task_001",
        action="execute",
        resource="res_001",
        identity_provenance={},
        request_id="req_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code == "PEP_PDP_ADAPTER_UNCONFIGURED"
    assert not receipt.is_verified_allow
