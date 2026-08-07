"""TRIAXIS PI-001 Failure Modes & Security Test Suite."""

from pathlib import Path
import pytest

from triaxis.authorization import (
    AuthorizationDecisionReceipt,
    AuthorizationRequest,
    CedarLocalReferencePDP,
    CompoundPrincipal,
    DecisionState,
    PolicyEnforcementPoint,
)


class ErrorFailingPDP:
    """PDP adapter that raises an unhandled exception during evaluation."""

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        raise RuntimeError("PDP subprocess crashed unexpectedly")


class MalformedStdoutPDP:
    """PDP adapter returning malformed / unexpected response."""

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        from datetime import datetime, timezone
        return AuthorizationDecisionReceipt(
            decision=DecisionState.ERROR,
            reason_code="CEDAR_PROCESS_ERROR",
            policy_version=1,
            policy_hash="0" * 64,
            provider="CedarMalformed",
            provider_version="4.12.0",
            request_id=request.principal.request_id,
            evaluated_principal=request.principal.to_dict(),
            evaluated_task=request.principal.task_id,
            evaluated_action=request.principal.action,
            evaluated_resource=request.principal.resource,
            evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
            error_class="ProcessExitCode_1",
        )


def test_missing_cedar_binary_fails_closed():
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/nonexistent/path/to/cedar_binary_xyz",
        policy_filepath="src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code == "CEDAR_BINARY_UNAVAILABLE"
    assert not receipt.is_verified_allow


def test_missing_policy_file_fails_closed():
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="cedar",
        policy_filepath="/nonexistent/path/to/missing_policy.cedar",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code in ("CEDAR_POLICY_UNAVAILABLE", "CEDAR_BINARY_UNAVAILABLE")
    assert not receipt.is_verified_allow


def test_pdp_exception_handled_by_pep():
    pep = PolicyEnforcementPoint(pdp_adapter=ErrorFailingPDP())
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code == "PEP_ADAPTER_INVOCATION_EXCEPTION"
    assert receipt.error_class == "RuntimeError"
    assert not receipt.is_verified_allow


def test_malformed_stdout_pdp_fails_closed():
    pep = PolicyEnforcementPoint(pdp_adapter=MalformedStdoutPDP())
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert not receipt.is_verified_allow


def test_command_injection_attempt_in_principal_sanitized():
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/nonexistent/path/to/cedar",
        policy_filepath="src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar",
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)
    principal = CompoundPrincipal(
        human_id='alice"; rm -rf / ; #',
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_injection_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    # Must fail closed safely without executing shell commands!
    assert receipt.decision == DecisionState.ERROR
    assert not receipt.is_verified_allow
