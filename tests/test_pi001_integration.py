"""TRIAXIS PI-001 Integration Test Suite."""

from pathlib import Path
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

        # Match exact policy rules:
        # human_id == "alice@triaxis.dev"
        # agent_instance_id == "agent_inst_001"
        # delegation_grant_id == "grant_prod_001"
        # task_id == "task_authorization_001"
        # action == "execute_capability"
        # resource == "target_service_v1"
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
                policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                provider="CedarMock",
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
                policy_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                provider="CedarMock",
                provider_version="4.12.0",
                request_id=p.request_id,
                evaluated_principal=p.to_dict(),
                evaluated_task=p.task_id,
                evaluated_action=p.action,
                evaluated_resource=p.resource,
                evaluation_timestamp_iso=now_iso,
            )


@pytest.fixture
def test_setup():
    registry = TrustKeyRegistry()
    keys = generate_ed25519_keypair()
    pub_b64 = keys["public_key_b64"]
    priv_b64 = keys["private_key_b64"]
    record = make_trust_key_record(
        key_id="k1",
        signer_id="issuer_001",
        trust_domain="dev.domain",
        public_key_b64=pub_b64,
        purposes=[
            PURPOSE_ASSURANCE_ATTESTATION,
            PURPOSE_STATE_WITNESS,
            PURPOSE_ACTION_APPROVAL,
            PURPOSE_POLICY_BUNDLE,
        ],
        valid_from=0,
        valid_until=1000,
    )
    registry.add(record)

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

    state_witness_raw = {
        "contract_id": STATE_WITNESS_CONTRACT_ID,
        "state_id": "state_001",
        "subject_id": "alice@triaxis.dev",
        "object_id": "target_service_v1",
        "adapter_id": "issuer_001",
        "version": 1,
        "state_sha256": "0" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": 10,
        "valid_until": 1000,
        "witness_sha256": "",
    }
    witness = seal_contract(state_witness_raw, "witness_sha256")

    attestation_raw = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "att_001",
        "subject_id": "alice@triaxis.dev",
        "issuer_id": "issuer_001",
        "trust_domain": "dev.domain",
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
        "principal_id": "alice@triaxis.dev",
        "human_id": "alice@triaxis.dev",
        "agent_instance_id": "agent_inst_001",
        "delegation_grant_id": "grant_prod_001",
        "task_id": "task_authorization_001",
        "intent_id": "intent_001",
        "subject_id": "alice@triaxis.dev",
        "object_id": "target_service_v1",
        "capability": "execute_capability",
        "tool_id": "tool_001",
        "execution_target": "target_service_v1",
        "payload_sha256": "0" * 64,
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "policy_id": "pol_001",
        "policy_sequence": 1,
        "policy_sha256": policy["policy_sha256"],
        "state_witness": witness,
        "risk_class": "R1",
        "nonce": "nonce_001",
        "issued_at": 10,
        "expires_at": 1000,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }

    req_digest = assured_action_request_sha256(action_base)
    attestation_raw["assured_action_request_sha256"] = req_digest
    attestation = seal_contract(attestation_raw, "attestation_sha256")
    action_base["assurance_attestation"] = attestation
    action_base["assured_action_request_sha256"] = req_digest

    scope_digest = action_scope_sha256(action_base)
    action_base["scope_sha256"] = scope_digest
    action = seal_contract(action_base, "action_sha256")

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


@pytest.mark.parametrize(
    "field_to_corrupt,bad_value",
    [
        ("human_id", "mallory@triaxis.dev"),
        ("agent_instance_id", "bad_agent"),
        ("delegation_grant_id", "bad_grant"),
        ("task_id", "bad_task"),
        ("capability", "unauthorized_action"),
        ("execution_target", "bad_target"),
    ],
)
def test_negative_controls_independent_dimensions(test_setup, field_to_corrupt, bad_value):
    policy_path = Path("src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar")
    mock_pdp = MockCedarPDP(policy_path)
    pep = PolicyEnforcementPoint(pdp_adapter=mock_pdp)

    corrupted_action = dict(test_setup["action"])
    corrupted_action[field_to_corrupt] = bad_value

    token = authorize_action(
        corrupted_action,
        test_setup["policy"],
        evaluation_tick=50,
        issuer_id=test_setup["issuer_id"],
        trusted_assurance_issuers=test_setup["trusted_issuers"],
        authorization_mode="cedar_reference",
        pep=pep,
    )

    assert token["outcome"] == "DENY"


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
