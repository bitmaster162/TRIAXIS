"""TRIAXIS RHE execution-boundary canary R1.

Purpose: exercise the real TRIAXIS identity -> PEP -> Cedar-compatible decision
-> single-use ledger boundary and STOP at PREPARED.  This test performs no
external provider, trading, capital, deployment, or execution effect.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.authorization import (
    AuthorizationDecisionReceipt,
    CedarLocalReferencePDP,
    DecisionState,
    PolicyEnforcementPoint,
)
from triaxis.identity import (
    TrustedWorkloadIdentityProviderRegistry,
    VerifiedWorkloadIdentity,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


VALID_HUMAN = "alice@triaxis.dev"
VALID_AGENT = "agent_inst_001"
VALID_SPIFFE = "spiffe://triaxis.local/agent/operator-001"
VALID_DELEGATION = "grant_prod_001"
VALID_TASK = "task_authorization_001"
VALID_CAPABILITY = "execute_capability"
VALID_TARGET = "target_service_v1"
PROVIDER_ID = "canary_spiffe_test"
MAPPING_SHA = "1" * 64
CERT_SHA = "2" * 64


class DeterministicWorkloadIdentityProvider:
    def __init__(self, identity: VerifiedWorkloadIdentity) -> None:
        self.identity = identity
        self.calls = 0

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        self.calls += 1
        return replace(self.identity, request_id=request_id)


class CanaryPDP:
    """Cedar-compatible deterministic decision adapter for the product PEP."""

    def __init__(self) -> None:
        self.calls = 0

    def evaluate(self, request):
        self.calls += 1
        p = request.principal
        allowed = (
            p.human_id == VALID_HUMAN
            and p.agent_instance_id == VALID_AGENT
            and p.delegation_grant_id == VALID_DELEGATION
            and p.task_id == VALID_TASK
            and p.action == VALID_CAPABILITY
            and p.resource == VALID_TARGET
        )
        return AuthorizationDecisionReceipt(
            decision=DecisionState.ALLOW if allowed else DecisionState.DENY,
            reason_code="CANARY_ALLOW" if allowed else "CANARY_DENY",
            policy_version=1,
            triaxis_policy_sha256=request.triaxis_policy_sha256 or ("0" * 64),
            cedar_policy_sha256=request.cedar_policy_sha256 or ("0" * 64),
            provider="Cedar",
            provider_version="canary-r1",
            request_id=p.request_id,
            evaluated_principal=p.to_dict(),
            evaluated_task=p.task_id,
            evaluated_action=p.action,
            evaluated_resource=p.resource,
            evaluation_timestamp_iso=datetime.now(timezone.utc).isoformat(),
        )


class ExplodingPDP:
    def evaluate(self, request):
        raise RuntimeError("canary PDP unavailable")


def verified_identity(
    *,
    agent_instance_id: str = VALID_AGENT,
    spiffe_id: str = VALID_SPIFFE,
    status: str = "VERIFIED",
    reason: str = "SPIFFE_SVID_VERIFIED",
) -> VerifiedWorkloadIdentity:
    return VerifiedWorkloadIdentity(
        agent_instance_id=agent_instance_id,
        spiffe_id=spiffe_id,
        trust_domain="triaxis.local",
        identity_provider="canary-local",
        certificate_fingerprint_sha256=CERT_SHA,
        not_before_iso="2026-08-27T00:00:00+00:00",
        not_after_iso="2026-08-28T00:00:00+00:00",
        verification_status=status,
        verification_reason=reason,
        identity_mapping_sha256=MAPPING_SHA,
    )


def policy_bundle():
    return seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy_rhe_canary_r1",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "subject_id": VALID_HUMAN,
            "issuer_id": "issuer_001",
            "state": "ACTIVE",
            "effective_from": 0,
            "valid_until": 1000,
            "allowed_capabilities": [VALID_CAPABILITY],
            "allowed_tools": ["tool_001"],
            "allowed_targets": [VALID_TARGET],
            "max_risk_class": "R1",
            "required_approval_types": [],
            "policy_sha256": "",
        }
    )


def action_envelope(
    policy,
    *,
    human_id: str = VALID_HUMAN,
    agent_instance_id: str = VALID_AGENT,
    spiffe_id: str = VALID_SPIFFE,
    delegation_grant_id: str = VALID_DELEGATION,
    task_id: str = VALID_TASK,
    capability: str = VALID_CAPABILITY,
    execution_target: str = VALID_TARGET,
    nonce: str = "nonce_rhe_canary_r1",
):
    witness = seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "state_rhe_canary_r1",
            "subject_id": human_id,
            "object_id": execution_target,
            "adapter_id": "issuer_001",
            "version": 1,
            "state_sha256": "0" * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 10,
            "valid_until": 1000,
            "witness_sha256": "",
        },
        "witness_sha256",
    )

    attestation_raw = {
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "att_rhe_canary_r1",
        "issuer_id": "issuer_001",
        "trust_domain": "dev.domain",
        "subject_id": human_id,
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

    action = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "intent_id": f"intent_{nonce}",
        "principal_id": human_id,
        "subject_id": human_id,
        "object_id": execution_target,
        "capability": capability,
        "tool_id": "tool_001",
        "execution_target": execution_target,
        "policy_id": policy["policy_id"],
        "policy_sequence": policy["sequence"],
        "policy_sha256": policy["policy_sha256"],
        "state_witness": witness,
        "risk_class": "R1",
        "decision_case_sha256": "0" * 64,
        "evidence_report_sha256": "0" * 64,
        "payload_sha256": "0" * 64,
        "nonce": nonce,
        "issued_at": 10,
        "expires_at": 1000,
        "human_id": human_id,
        "agent_instance_id": agent_instance_id,
        "delegation_grant_id": delegation_grant_id,
        "task_id": task_id,
        "spiffe_id": spiffe_id,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }

    req_hash = assured_action_request_sha256(action)
    attestation_raw["assured_action_request_sha256"] = req_hash
    action["assurance_attestation"] = seal_contract(
        attestation_raw, "attestation_sha256"
    )
    action["assured_action_request_sha256"] = req_hash
    action["scope_sha256"] = action_scope_sha256(action)
    return seal_contract(action, "action_sha256")


def registered_provider(identity=None):
    provider = DeterministicWorkloadIdentityProvider(identity or verified_identity())
    registry = TrustedWorkloadIdentityProviderRegistry(allow_test_mocks=True)
    registry.register_provider(
        PROVIDER_ID,
        provider,
        expected_trust_domain="triaxis.local",
        mapping_sha256=MAPPING_SHA,
    )
    return provider, registry


def authorize(action, policy, provider, registry, pdp=None):
    pep = PolicyEnforcementPoint(pdp_adapter=pdp or CanaryPDP())
    token = authorize_action(
        action,
        policy,
        evaluation_tick=50,
        issuer_id="issuer_001",
        trusted_assurance_issuers={"issuer_001": "dev.domain"},
        authorization_mode="cedar_reference",
        pep=pep,
        identity_mode="spiffe_workload",
        workload_identity_provider=provider,
        trusted_provider_registry=registry,
        provider_id=PROVIDER_ID,
    )
    return token, pep


def assert_denied_never_prepares(token, action, tmp_path):
    with SQLiteExecutionLedger(tmp_path / "denied.sqlite") as ledger:
        with pytest.raises(ExecutionLedgerError):
            ledger.prepare(
                token,
                observed_state_witness=action["state_witness"],
                evaluation_tick=50,
            )
        assert ledger.get(action["nonce"]) is None


def test_canary_positive_reaches_exactly_prepared_and_stops(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy)
    provider, registry = registered_provider()
    pdp = CanaryPDP()

    token, pep = authorize(action, policy, provider, registry, pdp)

    assert token["outcome"] == "ALLOW"
    assert token["errors"] == []
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow
    assert token["workload_identity"]["agent_instance_id"] == VALID_AGENT
    assert token["workload_identity"]["spiffe_id"] == VALID_SPIFFE

    with SQLiteExecutionLedger(tmp_path / "canary.sqlite") as ledger:
        current_identity = provider.fetch_and_verify_identity("prepare_canary_r1")
        row = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=50,
            current_workload_identity=current_identity,
            trusted_provider_registry=registry,
            provider_id=PROVIDER_ID,
            provider_instance=provider,
        )

        assert row["state"] == "PREPARED"
        assert row["token_sha256"] == token["token_sha256"]
        assert row["outcome_sha256"] is None
        assert row["effect_id"] is None
        assert row["receipt"] is None

        # Same-token/same-workload retry is idempotent: no second effect or row.
        retry = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=50,
            current_workload_identity=current_identity,
            trusted_provider_registry=registry,
            provider_id=PROVIDER_ID,
            provider_instance=provider,
        )
        assert retry == row
        assert ledger.get(action["nonce"]) == row

    assert pdp.calls == 1


def test_canary_real_cedar_reaches_prepared_when_local_binary_is_available(tmp_path):
    """Optional real-Cedar anchor; still performs zero external execution effect."""
    policy = policy_bundle()
    action = action_envelope(policy)
    provider, registry = registered_provider()

    pdp = CedarLocalReferencePDP(
        policy_filepath=Path(
            "src/triaxis/authorization/fixtures/cedar_pi001_policy.cedar"
        )
    )
    if not pdp.cedar_ready:
        pytest.skip(f"local Cedar binary unavailable: {pdp.provider_version}")

    token, pep = authorize(action, policy, provider, registry, pdp)

    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow
    assert pep.last_receipt.provider == "Cedar"

    with SQLiteExecutionLedger(tmp_path / "real_cedar_canary.sqlite") as ledger:
        current_identity = provider.fetch_and_verify_identity("real_cedar_prepare")
        row = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=50,
            current_workload_identity=current_identity,
            trusted_provider_registry=registry,
            provider_id=PROVIDER_ID,
            provider_instance=provider,
        )
        assert row["state"] == "PREPARED"
        assert row["outcome_sha256"] is None
        assert row["effect_id"] is None
        assert row["receipt"] is None


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("delegation_grant_id", "bad_grant"),
        ("task_id", "bad_task"),
        ("capability", "unauthorized_capability"),
        ("execution_target", "wrong_target"),
    ],
)
def test_canary_policy_dimension_negatives_fail_closed(tmp_path, field, bad_value):
    policy = policy_bundle()
    kwargs = {field: bad_value}
    action = action_envelope(policy, **kwargs)
    provider, registry = registered_provider()
    pdp = CanaryPDP()

    token, pep = authorize(action, policy, provider, registry, pdp)

    assert token["outcome"] == "DENY"
    assert pep.last_receipt is not None
    assert not pep.last_receipt.is_verified_allow
    assert_denied_never_prepares(token, action, tmp_path)


def test_canary_claimed_workload_identity_mismatch_fails_before_pep(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy, agent_instance_id="spoofed_agent")
    provider, registry = registered_provider()
    pdp = CanaryPDP()

    token, pep = authorize(action, policy, provider, registry, pdp)

    assert token["outcome"] == "DENY"
    assert any(e["code"] == "WORKLOAD_IDENTITY_MISMATCH" for e in token["errors"])
    assert pep.last_receipt is None
    assert pdp.calls == 0
    assert_denied_never_prepares(token, action, tmp_path)


def test_canary_unverified_workload_identity_fails_before_pep(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy)
    provider, registry = registered_provider(
        verified_identity(
            status="DENIED",
            reason="WORKLOAD_ATTESTATION_SELECTOR_MISMATCH",
        )
    )
    pdp = CanaryPDP()

    token, pep = authorize(action, policy, provider, registry, pdp)

    assert token["outcome"] == "DENY"
    assert any(
        e["code"] == "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH"
        for e in token["errors"]
    )
    assert pep.last_receipt is None
    assert pdp.calls == 0
    assert_denied_never_prepares(token, action, tmp_path)


def test_canary_pdp_exception_is_deny_and_never_prepares(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy)
    provider, registry = registered_provider()

    token, pep = authorize(action, policy, provider, registry, ExplodingPDP())

    assert token["outcome"] == "DENY"
    assert pep.last_receipt is not None
    assert pep.last_receipt.decision == DecisionState.ERROR
    assert pep.last_receipt.reason_code == "PEP_ADAPTER_INVOCATION_EXCEPTION"
    assert_denied_never_prepares(token, action, tmp_path)


def test_canary_cross_workload_replay_is_rejected(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy)
    provider, registry = registered_provider()
    token, _ = authorize(action, policy, provider, registry)

    assert token["outcome"] == "ALLOW"

    with SQLiteExecutionLedger(tmp_path / "replay.sqlite") as ledger:
        good_identity = provider.fetch_and_verify_identity("first_prepare")
        first = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=50,
            current_workload_identity=good_identity,
            trusted_provider_registry=registry,
            provider_id=PROVIDER_ID,
            provider_instance=provider,
        )
        assert first["state"] == "PREPARED"

        wrong_identity = verified_identity(
            agent_instance_id="other_agent",
            spiffe_id="spiffe://triaxis.local/agent/other",
        )
        with pytest.raises(
            ExecutionLedgerError,
            match="current workload identity .* does not match token authorized identity",
        ):
            ledger.prepare_for_workload(
                token_value=token,
                observed_state_witness=action["state_witness"],
                evaluation_tick=50,
                current_workload_identity=wrong_identity,
                trusted_provider_registry=registry,
                provider_id=PROVIDER_ID,
                provider_instance=provider,
            )

        # Rejected replay cannot mutate the already prepared record.
        assert ledger.get(action["nonce"]) == first
