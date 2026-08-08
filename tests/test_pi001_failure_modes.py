"""TRIAXIS PI-001 Real Failure Modes & Security Test Suite (PI-001 R2)."""

from pathlib import Path
import tempfile
import pytest

from triaxis.authorization import (
    AuthorizationDecisionReceipt,
    AuthorizationRequest,
    CedarLocalReferencePDP,
    CompoundPrincipal,
    DecisionState,
    PolicyEnforcementPoint,
)


class MockSubprocessPDP(CedarLocalReferencePDP):
    """Subclass allowing simulation of specific subprocess stdout/stderr/exit_code."""

    def __init__(self, exit_code: int, stdout: str, stderr: str, **kwargs):
        super().__init__(**kwargs)
        self.mock_exit_code = exit_code
        self.mock_stdout = stdout
        self.mock_stderr = stderr

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        # Override evaluate to use mocked subprocess run output
        from unittest.mock import MagicMock, patch
        mock_res = MagicMock(returncode=self.mock_exit_code, stdout=self.mock_stdout, stderr=self.mock_stderr)
        with patch("subprocess.run", return_value=mock_res):
            with patch.object(self, "_resolve_binary", return_value="/usr/bin/cedar"):
                self._cedar_ready = True
                return super().evaluate(request)


def test_failure_mode_missing_binary(monkeypatch):
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/nonexistent/cedar_binary_path_9999",
        policy_filepath="src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar",
    )
    monkeypatch.setattr(pdp, "_resolve_binary", lambda: None)
    monkeypatch.setattr(pdp, "_cedar_ready", False)
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


def test_failure_mode_timeout():
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/home/bit/.cargo/bin/cedar",
        policy_filepath="src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar",
        timeout_seconds=0.00001,
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
        request_id="req_timeout",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code in ("CEDAR_PROCESS_TIMEOUT", "CEDAR_BINARY_UNAVAILABLE")
    assert not receipt.is_verified_allow


def test_failure_mode_invalid_policy_syntax(tmp_path):
    bad_pol = tmp_path / "bad_policy.cedar"
    bad_pol.write_text("permit (invalid cedar syntax !!!);")

    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/home/bit/.cargo/bin/cedar",
        policy_filepath=bad_pol,
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
        request_id="req_syntax",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code == "CEDAR_PROCESS_ERROR"
    assert not receipt.is_verified_allow


@pytest.mark.parametrize(
    "exit_code,stdout,stderr,expected_decision,expected_reason",
    [
        (1, "", "Syntax error", DecisionState.ERROR, "CEDAR_PROCESS_ERROR"),
        (0, "", "", DecisionState.ERROR, "CEDAR_STDOUT_MALFORMED"),
        (0, "", "ALLOW", DecisionState.ERROR, "CEDAR_STDOUT_MALFORMED"),
        (0, "ALLOW_GARBAGE", "", DecisionState.ERROR, "CEDAR_STDOUT_MALFORMED"),
        (0, "NOTALLOW", "", DecisionState.ERROR, "CEDAR_STDOUT_MALFORMED"),
        (0, "ALLOW", "Warning: deprecated policy feature", DecisionState.ALLOW, "CEDAR_DECISION_ALLOW"),
        (0, "DENY", "", DecisionState.DENY, "CEDAR_DECISION_DENY"),
        (2, "DENY", "", DecisionState.DENY, "CEDAR_DECISION_DENY"),
    ],
)
def test_failure_mode_subprocess_variations(tmp_path, exit_code, stdout, stderr, expected_decision, expected_reason):
    pol = tmp_path / "policy.cedar"
    pol.write_text("permit(principal, action, resource);")

    pdp = MockSubprocessPDP(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        cedar_binary_path="/usr/bin/cedar",
        policy_filepath=pol,
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
        request_id="req_sub_var",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    assert receipt.decision == expected_decision
    assert receipt.reason_code == expected_reason


def test_failure_mode_argument_injection():
    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/home/bit/.cargo/bin/cedar",
        policy_filepath=policy_path,
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)
    principal = CompoundPrincipal(
        human_id='alice"; drop table; #',
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_inj_001",
    )
    req = AuthorizationRequest(principal=principal, policy_id="pol_001")
    receipt = pep.evaluate_request(req)

    # Shell-free execution ensures argument injection is treated as literal principal string and DENIED by Cedar
    assert receipt.decision in (DecisionState.DENY, DecisionState.ERROR)
    assert not receipt.is_verified_allow
