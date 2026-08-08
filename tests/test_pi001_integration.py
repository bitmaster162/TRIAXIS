"""TRIAXIS PI-001 Integration & Real Cedar E2E Test Suite (PI-001 R2)."""

from pathlib import Path
import pytest

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    SQLiteExecutionLedger,
    _is_sha256,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
    validate_action_envelope,
    validate_authorization_token,
)
from triaxis.authorization import (
    AuthorizationDecisionReceipt,
    AuthorizationMode,
    AuthorizationRequest,
    CedarLocalReferencePDP,
    CompoundPrincipal,
    DecisionState,
    PolicyEnforcementPoint,
)
from triaxis.crypto_trust import (
    PURPOSE_ACTION_APPROVAL,
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.integrity import canonical_sha256, seal_mapping
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


class MockCedarPDP:
    """Mock Cedar PDP simulating precise Cedar policy evaluation."""

    def __init__(self, policy_filepath: Path) -> None:
        self.policy_filepath = policy_filepath

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        from datetime import datetime, timezone
        p = request.principal
        now_iso = datetime.now(timezone.utc).isoformat()

        if (
            p.human_id == "alice@triaxis.dev"
            and p.agent_instance_id == "agent_inst_001"
            and p.delegation_grant_id == "grant_prod_001"
            and p.task_id == "task_authorization_001"
            and p.action == "execute_capability"
            and p.resource == "target_service_v1"
        ):
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ALLOW,
                reason_code="CEDAR_DECISION_ALLOW",
                policy_version=1,
                triaxis_policy_sha256=request.triaxis_policy_sha256 or ("0" * 64),
                cedar_policy_sha256=request.cedar_policy_sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                provider="Cedar",
                provider_version="4.12.0",
                request_id=p.request_id,
                evaluated_principal=p.to_dict(),
                evaluated_task=p.task_id,
                evaluated_action=p.action,
                evaluated_resource=p.resource,
                evaluation_timestamp_iso=now_iso,
            )
        else:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.DENY,
                reason_code="CEDAR_DECISION_DENY",
                policy_version=1,
                triaxis_policy_sha256=request.triaxis_policy_sha256 or ("0" * 64),
                cedar_policy_sha256=request.cedar_policy_sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                provider="Cedar",
                provider_version="4.12.0",
                request_id=p.request_id,
                evaluated_principal=p.to_dict(),
                evaluated_task=p.task_id,
                evaluated_action=p.action,
                evaluated_resource=p.resource,
                evaluation_timestamp_iso=now_iso,
            )


def make_valid_action_envelope(
    policy,
    human_id="alice@triaxis.dev",
    subject_id=None,
    agent_instance_id="agent_inst_001",
    delegation_grant_id="grant_prod_001",
    task_id="task_authorization_001",
    capability="execute_capability",
    execution_target="target_service_v1",
):
    eff_human = human_id if human_id is not None else "alice@triaxis.dev"
    eff_subject = subject_id if subject_id is not None else eff_human
    witness_raw = {
        "contract_id": STATE_WITNESS_CONTRACT_ID,
        "state_id": f"state_{task_id}",
        "subject_id": eff_subject,
        "object_id": execution_target,
        "adapter_id": "issuer_001",
        "version": 1,
        "state_sha256": "0" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": 10,
        "valid_until": 1000,
        "witness_sha256": "",
    }
    witness = seal_contract(witness_raw, "witness_sha256")

    attestation_raw = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": f"att_{task_id}",
        "issuer_id": "issuer_001",
        "trust_domain": "dev.domain",
        "subject_id": eff_subject,
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

    action_base = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "intent_id": f"intent_{task_id}",
        "principal_id": eff_human,
        "subject_id": eff_subject,
        "object_id": execution_target,
        "agent_instance_id": agent_instance_id,
        "delegation_grant_id": delegation_grant_id,
        "task_id": task_id,
        "capability": capability,
        "tool_id": "tool_001",
        "execution_target": execution_target,
        "payload_sha256": "0" * 64,
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "policy_id": "pol_001",
        "policy_sequence": 1,
        "policy_sha256": policy["policy_sha256"],
        "state_witness": witness,
        "risk_class": "R1",
        "nonce": f"nonce_{task_id}",
        "issued_at": 10,
        "expires_at": 1000,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }
    if human_id is not None:
        action_base["human_id"] = human_id

    req_digest = assured_action_request_sha256(action_base)
    attestation_raw["assured_action_request_sha256"] = req_digest
    attestation = seal_contract(attestation_raw, "attestation_sha256")
    action_base["assurance_attestation"] = attestation
    action_base["assured_action_request_sha256"] = req_digest

    scope_digest = action_scope_sha256(action_base)
    action_base["scope_sha256"] = scope_digest
    action = seal_contract(action_base, "action_sha256")
    return action


@pytest.fixture
def test_setup():
    policy_raw = {
        "contract_id": POLICY_BUNDLE_CONTRACT_ID,
        "policy_id": "pol_001",
        "sequence": 1,
        "minimum_accepted_sequence": 1,
        "subject_id": "alice@triaxis.dev",
        "issuer_id": "issuer_001",
        "state": "ACTIVE",
        "effective_from": 0,
        "valid_until": 1000,
        "allowed_capabilities": ["execute_capability"],
        "allowed_tools": ["tool_001"],
        "allowed_targets": ["target_service_v1"],
        "max_risk_class": "R1",
        "required_approval_types": [],
        "policy_sha256": "",
    }
    policy = seal_policy(policy_raw)

    action = make_valid_action_envelope(policy)

    return {
        "policy": policy,
        "action": action,
        "issuer_id": "issuer_001",
        "trusted_issuers": {"issuer_001": "dev.domain"},
    }


def test_positive_control_cedar_reference_mode(test_setup):
    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    mock_pdp = MockCedarPDP(policy_path)
    pep = PolicyEnforcementPoint(pdp_adapter=mock_pdp)

    token = authorize_action(
        test_setup["action"],
        test_setup["policy"],
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow


def test_legacy_mode_compatibility(test_setup):
    token = authorize_action(
        test_setup["action"],
        test_setup["policy"],
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="legacy",
    )
    assert token["outcome"] == "ALLOW"


def test_real_cedar_pdp_token_to_sqlite_ledger_prepared_runtime(test_setup, tmp_path):
    """Section 2: REAL CEDAR E2E TEST (No MockCedarPDP)."""
    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/home/bit/.cargo/bin/cedar",
        policy_filepath=policy_path,
    )
    assert pdp.cedar_ready, f"Cedar binary must be ready: {pdp.provider_version}"
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)

    token = authorize_action(
        test_setup["action"],
        test_setup["policy"],
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    # 1. Verify real token authorization output
    assert token["outcome"] == "ALLOW"
    assert token["contract_id"] == "TRIAXIS_SINGLE_USE_AUTHORIZATION_TOKEN_v3"
    assert _is_sha256(token["token_sha256"])
    assert _is_sha256(token["policy_decision_sha256"])
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow
    assert pep.last_receipt.provider == "Cedar"

    # 2. Validate token against contract rules
    validation = validate_authorization_token(token, evaluation_tick=50, require_allow=True)
    assert validation["status"] == "PASS"

    # 3. Feed valid token into SQLiteExecutionLedger -> PREPARED state
    db_path = tmp_path / "ledger.sqlite"
    ledger = SQLiteExecutionLedger(db_path)
    prep_result = ledger.prepare(
        token,
        observed_state_witness=test_setup["action"]["state_witness"],
        evaluation_tick=50,
    )

    assert prep_result["state"] == "PREPARED"
    assert prep_result["token_sha256"] == token["token_sha256"]


@pytest.mark.parametrize(
    "neg_param,bad_val",
    [
        ("human_id", "mallory@triaxis.dev"),
        ("agent_instance_id", "bad_agent_999"),
        ("delegation_grant_id", "bad_grant_999"),
        ("task_id", "bad_task_999"),
        ("capability", "unauthorized_capability"),
        ("execution_target", "bad_target_999"),
    ],
)
def test_negative_controls_rebuilt_from_scratch(test_setup, tmp_path, neg_param, bad_val):
    """Section 6: REBUILD NEGATIVE PRINCIPAL CONTROLS CORRECTLY."""
    kwargs = {
        "human_id": "alice@triaxis.dev",
        "agent_instance_id": "agent_inst_001",
        "delegation_grant_id": "grant_prod_001",
        "task_id": "task_authorization_001",
        "capability": "execute_capability",
        "execution_target": "target_service_v1",
    }
    kwargs[neg_param] = bad_val

    # Construct semantically valid action envelope from scratch
    rebuilt_action = make_valid_action_envelope(test_setup["policy"], **kwargs)

    # Prove pre-Cedar envelope validation passes
    val_res = validate_action_envelope(rebuilt_action, evaluation_tick=50)
    assert val_res["status"] == "PASS"

    # Execute real Cedar PDP
    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    pdp = CedarLocalReferencePDP(
        cedar_binary_path="/home/bit/.cargo/bin/cedar",
        policy_filepath=policy_path,
    )
    pep = PolicyEnforcementPoint(pdp_adapter=pdp)

    token = authorize_action(
        rebuilt_action,
        test_setup["policy"],
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    # Expected: DENY and NO LEDGER PREPARE
    assert token["outcome"] == "DENY"
    assert pep.last_receipt is not None
    assert pep.last_receipt.decision == DecisionState.DENY

    db_path = tmp_path / "ledger_neg.sqlite"
    ledger = SQLiteExecutionLedger(db_path)
    with pytest.raises(Exception):
        ledger.prepare(
            token,
            observed_state_witness=rebuilt_action["state_witness"],
            evaluation_tick=50,
        )


@pytest.mark.parametrize(
    "corrupt_field,fake_val",
    [
        ("request_id", "fake_req_id"),
        ("human_id", "fake_human"),
        ("agent_instance_id", "fake_agent"),
        ("task_id", "fake_task"),
        ("action", "fake_action"),
        ("resource", "fake_resource"),
        ("cedar_policy_sha256", "f" * 64),
    ],
)
def test_pep_receipt_correlation_failures(test_setup, corrupt_field, fake_val):
    """Section 4: PEP RECEIPT CORRELATION FAILURES."""
    principal = CompoundPrincipal(
        human_id="alice@triaxis.dev",
        agent_instance_id="agent_inst_001",
        delegation_grant_id="grant_prod_001",
        task_id="task_authorization_001",
        action="execute_capability",
        resource="target_service_v1",
        identity_provenance={},
        request_id="req_corr_001",
    )
    req = AuthorizationRequest(
        principal=principal,
        policy_id="pol_001",
        cedar_policy_sha256="0" * 64,
    )

    # Create mock adapter returning receipt with corrupted field
    class CorruptedReceiptPDP:
        def evaluate(self, request):
            from datetime import datetime, timezone
            p_dict = request.principal.to_dict()
            act = request.principal.action
            res = request.principal.resource
            req_id = request.principal.request_id
            c_hash = request.cedar_policy_sha256 or ("0" * 64)

            prov = "Cedar"
            if corrupt_field == "request_id":
                req_id = fake_val
            elif corrupt_field == "action":
                act = fake_val
                p_dict["action"] = fake_val
            elif corrupt_field == "resource":
                res = fake_val
                p_dict["resource"] = fake_val
            elif corrupt_field == "cedar_policy_sha256":
                c_hash = fake_val
            elif corrupt_field == "provider":
                prov = fake_val
            elif corrupt_field in p_dict:
                p_dict[corrupt_field] = fake_val

            return AuthorizationDecisionReceipt(
                decision=DecisionState.ALLOW,
                reason_code="CEDAR_DECISION_ALLOW",
                policy_version=1,
                triaxis_policy_sha256="0" * 64,
                cedar_policy_sha256=c_hash,
                provider=prov,
                provider_version="4.12.0",
                request_id=req_id,
                evaluated_principal=p_dict,
                evaluated_task=p_dict.get("task_id", ""),
                evaluated_action=act,
                evaluated_resource=res,
                evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
            )

    pep = PolicyEnforcementPoint(pdp_adapter=CorruptedReceiptPDP())
    receipt = pep.evaluate_request(req)

    # Must fail closed with correlation failure
    assert receipt.decision == DecisionState.ERROR
    assert receipt.reason_code == "PDP_RECEIPT_CORRELATION_FAILURE"
    assert not receipt.is_verified_allow


def test_missing_explicit_human_id_no_subject_id_inheritance(test_setup):
    """Section 1: Missing explicit human_id yields DENY without subject_id fallback."""
    policy = test_setup["policy"]
    action = make_valid_action_envelope(policy, human_id=None)

    # Prove pre-Cedar envelope validation passes
    val_res = validate_action_envelope(action, evaluation_tick=50)
    assert val_res["status"] == "PASS"

    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    mock_pdp = MockCedarPDP(policy_path)
    pep = PolicyEnforcementPoint(pdp_adapter=mock_pdp)

    token = authorize_action(
        action,
        policy,
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    assert token["outcome"] == "DENY"
    # Prove no PDP evaluation occurred
    assert pep.last_receipt is None
    # Prove specific error code emitted
    codes = [e["code"] for e in token.get("errors", [])]
    assert "MISSING_COMPOUND_PRINCIPAL_COMPONENT" in codes


def test_explicit_disagreement_human_id_and_subject_id(test_setup):
    """Section 1: Explicit disagreement between human_id and subject_id is processed explicitly."""
    policy = test_setup["policy"]
    action = make_valid_action_envelope(
        policy,
        human_id="alice@triaxis.dev",
        subject_id="bob_target_subject@triaxis.dev",
        execution_target="target_service_v1",
    )

    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    mock_pdp = MockCedarPDP(policy_path)
    pep = PolicyEnforcementPoint(pdp_adapter=mock_pdp)

    token = authorize_action(
        action,
        policy,
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.evaluated_principal["human_id"] == "alice@triaxis.dev"

