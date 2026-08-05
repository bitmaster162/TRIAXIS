"""TRIAXIS v3.4 exact-action assurance attestation and durable execution ledger.

This module is a deterministic boundary around probabilistic reasoning.  It
binds a decision/evidence case to one exact capability, tool, target, payload,
policy version, state witness, nonce and expiry.  It does not execute external
side effects itself; callers must place the ledger at the real resource/API
boundary to obtain complete mediation.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import sqlite3
from pathlib import Path
from typing import Any

from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, evaluate_policy, validate_policy_bundle

ACTION_ENVELOPE_CONTRACT_ID = "TRIAXIS_ACTION_ASSURANCE_ENVELOPE_v3"
ASSURANCE_ATTESTATION_CONTRACT_ID = "TRIAXIS_ASSURANCE_PASS_ATTESTATION_v2"
STATE_WITNESS_CONTRACT_ID = "TRIAXIS_AUTHENTICATED_STATE_WITNESS_v1"
APPROVAL_CONTRACT_ID = "TRIAXIS_ACTION_APPROVAL_v1"
AUTHORIZATION_TOKEN_CONTRACT_ID = "TRIAXIS_SINGLE_USE_AUTHORIZATION_TOKEN_v2"
EXECUTION_RECEIPT_CONTRACT_ID = "TRIAXIS_EXECUTION_RECEIPT_v1"

RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")
STATE_ATTESTATIONS = frozenset({"AUTHENTICATED", "HARDWARE_ROOTED"})
ASSURANCE_ATTESTATION_LEVELS = frozenset({"AUTHENTICATED", "HARDWARE_ROOTED"})
ASSURANCE_DECISIONS = frozenset({"ACCEPT", "ACCEPT_WITH_CONTROLS"})
TOKEN_OUTCOMES = frozenset({"ALLOW", "DENY"})
LEDGER_STATES = frozenset({"PREPARED", "COMPLETED", "UNKNOWN", "RECONCILED_DENY", "RECONCILED_COMPLETE"})


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def seal_contract(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return seal_mapping(value, digest_field)


def _sealed(value: Any, contract_id: str, digest_field: str, path: str, errors: list[dict[str, str]]) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(_error("invalid_type", path, "object required"))
        return None
    obj = dict(value)
    if obj.get("contract_id") != contract_id:
        errors.append(_error("invalid_contract_id", f"{path}.contract_id", f"expected {contract_id}"))
    if not verify_sealed_mapping(obj, digest_field):
        errors.append(_error("digest_mismatch", f"{path}.{digest_field}", "canonical digest mismatch"))
    return obj


def validate_state_witness(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    witness = _sealed(value, STATE_WITNESS_CONTRACT_ID, "witness_sha256", "state_witness", errors)
    if witness is None:
        return {"status": "BLOCK", "errors": errors}
    for field in ("state_id", "subject_id", "object_id", "adapter_id"):
        if not isinstance(witness.get(field), str) or not witness.get(field):
            errors.append(_error("missing_required", f"state_witness.{field}", f"{field} required"))
    if type(witness.get("version")) is not int or witness.get("version", -1) < 0:
        errors.append(_error("invalid_state_version", "state_witness.version", "integer >= 0 required"))
    if not _is_sha256(witness.get("state_sha256")):
        errors.append(_error("invalid_state_digest", "state_witness.state_sha256", "lowercase SHA-256 required"))
    if witness.get("attestation_level") not in STATE_ATTESTATIONS:
        errors.append(_error("invalid_state_attestation", "state_witness.attestation_level", "authenticated attestation required"))
    observed_at = witness.get("observed_at")
    valid_until = witness.get("valid_until")
    if type(observed_at) is not int or observed_at < 0:
        errors.append(_error("invalid_observed_at", "state_witness.observed_at", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "state_witness.valid_until", "integer >= 0 required"))
    elif type(observed_at) is int and valid_until <= observed_at:
        errors.append(_error("invalid_state_window", "state_witness.valid_until", "must be after observed_at"))
    if evaluation_tick is not None:
        if type(observed_at) is int and observed_at > evaluation_tick:
            errors.append(_error("future_state_witness", "state_witness.observed_at", "witness from the future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("stale_state_witness", "state_witness.valid_until", "witness expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "witness": witness}


def validate_assurance_attestation(
    value: Any,
    evaluation_tick: int,
    *,
    expected_subject_id: str | None = None,
    expected_decision_case_sha256: str | None = None,
    expected_evidence_report_sha256: str | None = None,
    expected_assured_action_request_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a PASS attestation for one exact assurance subject and artifact pair.

    The canonical digest proves integrity, not issuer authenticity. Issuer trust is
    checked separately by :func:`authorize_action`, where the caller supplies an
    out-of-band trusted issuer registry.
    """

    errors: list[dict[str, str]] = []
    attestation = _sealed(
        value,
        ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_sha256",
        "action.assurance_attestation",
        errors,
    )
    if attestation is None:
        return {"status": "BLOCK", "errors": errors}
    for field in ("attestation_id", "issuer_id", "trust_domain", "subject_id"):
        if not isinstance(attestation.get(field), str) or not attestation.get(field):
            errors.append(_error("missing_required", f"action.assurance_attestation.{field}", f"{field} required"))
    for field in ("decision_case_sha256", "evidence_report_sha256", "assured_action_request_sha256"):
        if not _is_sha256(attestation.get(field)):
            errors.append(_error("invalid_digest", f"action.assurance_attestation.{field}", "lowercase SHA-256 required"))
    if attestation.get("assurance_status") != "PASS":
        errors.append(_error("assurance_not_pass", "action.assurance_attestation.assurance_status", "PASS required"))
    if attestation.get("synthesis_decision") not in ASSURANCE_DECISIONS:
        errors.append(_error("invalid_synthesis_decision", "action.assurance_attestation.synthesis_decision", "ACCEPT or ACCEPT_WITH_CONTROLS required"))
    if attestation.get("attestation_level") not in ASSURANCE_ATTESTATION_LEVELS:
        errors.append(_error("invalid_assurance_attestation", "action.assurance_attestation.attestation_level", "authenticated attestation required"))
    issued_at = attestation.get("issued_at")
    valid_until = attestation.get("valid_until")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_assurance_time", "action.assurance_attestation.issued_at", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_assurance_time", "action.assurance_attestation.valid_until", "integer >= 0 required"))
    elif type(issued_at) is int and valid_until <= issued_at:
        errors.append(_error("invalid_assurance_window", "action.assurance_attestation.valid_until", "must be after issued_at"))
    if type(issued_at) is int and issued_at > evaluation_tick:
        errors.append(_error("future_assurance_attestation", "action.assurance_attestation.issued_at", "attestation from the future"))
    if type(valid_until) is int and evaluation_tick >= valid_until:
        errors.append(_error("stale_assurance_attestation", "action.assurance_attestation.valid_until", "attestation expired"))
    if expected_subject_id is not None and attestation.get("subject_id") != expected_subject_id:
        errors.append(_error("assurance_subject_mismatch", "action.assurance_attestation.subject_id", "subject mismatch"))
    if expected_decision_case_sha256 is not None and attestation.get("decision_case_sha256") != expected_decision_case_sha256:
        errors.append(_error("assurance_decision_mismatch", "action.assurance_attestation.decision_case_sha256", "decision case mismatch"))
    if expected_evidence_report_sha256 is not None and attestation.get("evidence_report_sha256") != expected_evidence_report_sha256:
        errors.append(_error("assurance_evidence_mismatch", "action.assurance_attestation.evidence_report_sha256", "evidence report mismatch"))
    if expected_assured_action_request_sha256 is not None and attestation.get("assured_action_request_sha256") != expected_assured_action_request_sha256:
        errors.append(_error("assured_action_request_mismatch", "action.assurance_attestation.assured_action_request_sha256", "assured action request mismatch"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "attestation": attestation}


def _trusted_assurance_issuer(
    attestation: Mapping[str, Any],
    trusted_issuers: Mapping[str, str] | None,
) -> bool:
    if not isinstance(trusted_issuers, Mapping):
        return False
    issuer_id = attestation.get("issuer_id")
    trust_domain = attestation.get("trust_domain")
    return isinstance(issuer_id, str) and issuer_id in trusted_issuers and trusted_issuers.get(issuer_id) == trust_domain


def _validate_approval(value: Any, index: int, evaluation_tick: int, expected_scope_sha256: str) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    path = f"action.approvals[{index}]"
    approval = _sealed(value, APPROVAL_CONTRACT_ID, "approval_sha256", path, errors)
    if approval is None:
        return None, errors
    for field in ("approval_id", "principal_id", "trust_domain", "approval_type"):
        if not isinstance(approval.get(field), str) or not approval.get(field):
            errors.append(_error("missing_required", f"{path}.{field}", f"{field} required"))
    if approval.get("scope_sha256") != expected_scope_sha256:
        errors.append(_error("approval_scope_mismatch", f"{path}.scope_sha256", "approval not bound to action scope"))
    issued_at, expires_at = approval.get("issued_at"), approval.get("expires_at")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_approval_time", f"{path}.issued_at", "integer >= 0 required"))
    if type(expires_at) is not int or expires_at < 0:
        errors.append(_error("invalid_approval_time", f"{path}.expires_at", "integer >= 0 required"))
    if type(issued_at) is int and issued_at > evaluation_tick:
        errors.append(_error("future_approval", f"{path}.issued_at", "approval from the future"))
    if type(expires_at) is int and evaluation_tick >= expires_at:
        errors.append(_error("expired_approval", f"{path}.expires_at", "approval expired"))
    return approval, errors


def assured_action_request_sha256(value: Mapping[str, Any]) -> str:
    """Digest the action semantics that the assurance process reviewed.

    The digest deliberately excludes the assurance attestation itself, approvals,
    authorization nonce and gate timestamps. It binds the actor intent and exact
    side-effect semantics, policy/state preconditions and risk class.
    """
    material = {
        "principal_id": value.get("principal_id"),
        "intent_id": value.get("intent_id"),
        "subject_id": value.get("subject_id"),
        "object_id": value.get("object_id"),
        "capability": value.get("capability"),
        "tool_id": value.get("tool_id"),
        "execution_target": value.get("execution_target"),
        "payload_sha256": value.get("payload_sha256"),
        "policy_id": value.get("policy_id"),
        "policy_sequence": value.get("policy_sequence"),
        "policy_sha256": value.get("policy_sha256"),
        "state_witness_sha256": (
            value.get("state_witness", {}).get("witness_sha256")
            if isinstance(value.get("state_witness"), Mapping)
            else None
        ),
        "risk_class": value.get("risk_class"),
    }
    from .integrity import canonical_sha256

    return canonical_sha256(material)


def action_scope_sha256(value: Mapping[str, Any]) -> str:
    """Return the digest to which approvals must be bound."""
    material = {
        "principal_id": value.get("principal_id"),
        "intent_id": value.get("intent_id"),
        "decision_case_sha256": value.get("decision_case_sha256"),
        "evidence_report_sha256": value.get("evidence_report_sha256"),
        "assured_action_request_sha256": value.get("assured_action_request_sha256"),
        "assurance_attestation_sha256": (
            value.get("assurance_attestation", {}).get("attestation_sha256")
            if isinstance(value.get("assurance_attestation"), Mapping)
            else None
        ),
        "subject_id": value.get("subject_id"),
        "object_id": value.get("object_id"),
        "capability": value.get("capability"),
        "tool_id": value.get("tool_id"),
        "execution_target": value.get("execution_target"),
        "payload_sha256": value.get("payload_sha256"),
        "policy_id": value.get("policy_id"),
        "policy_sequence": value.get("policy_sequence"),
        "policy_sha256": value.get("policy_sha256"),
        "state_witness_sha256": (
            value.get("state_witness", {}).get("witness_sha256")
            if isinstance(value.get("state_witness"), Mapping)
            else None
        ),
        "risk_class": value.get("risk_class"),
        "nonce": value.get("nonce"),
    }
    from .integrity import canonical_sha256

    return canonical_sha256(material)


def validate_action_envelope(value: Any, evaluation_tick: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "action", "mapping required")]}
    try:
        action = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "action", type(exc).__name__)]}
    if not isinstance(action, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "action", "object required")]}
    errors: list[dict[str, str]] = []
    if action.get("contract_id") != ACTION_ENVELOPE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "action.contract_id", "unexpected action contract"))
    if not verify_sealed_mapping(action, "action_sha256"):
        errors.append(_error("digest_mismatch", "action.action_sha256", "canonical digest mismatch"))
    for field in (
        "principal_id",
        "intent_id",
        "subject_id",
        "object_id",
        "capability",
        "tool_id",
        "execution_target",
        "policy_id",
        "nonce",
    ):
        if not isinstance(action.get(field), str) or not action.get(field):
            errors.append(_error("missing_required", f"action.{field}", f"{field} required"))
    for field in ("decision_case_sha256", "evidence_report_sha256", "payload_sha256", "policy_sha256", "assured_action_request_sha256"):
        if not _is_sha256(action.get(field)):
            errors.append(_error("invalid_digest", f"action.{field}", "lowercase SHA-256 required"))

    expected_assured_action_request_sha256 = assured_action_request_sha256(action)
    if action.get("assured_action_request_sha256") != expected_assured_action_request_sha256:
        errors.append(_error("assured_action_digest_mismatch", "action.assured_action_request_sha256", "action semantics digest mismatch"))

    assurance_result = validate_assurance_attestation(
        action.get("assurance_attestation"),
        evaluation_tick,
        expected_subject_id=action.get("subject_id") if isinstance(action.get("subject_id"), str) else None,
        expected_decision_case_sha256=action.get("decision_case_sha256") if _is_sha256(action.get("decision_case_sha256")) else None,
        expected_evidence_report_sha256=action.get("evidence_report_sha256") if _is_sha256(action.get("evidence_report_sha256")) else None,
        expected_assured_action_request_sha256=(
            action.get("assured_action_request_sha256")
            if _is_sha256(action.get("assured_action_request_sha256"))
            else None
        ),
    )
    errors.extend(assurance_result["errors"])
    assurance_attestation = assurance_result.get("attestation")

    if type(action.get("policy_sequence")) is not int or action.get("policy_sequence", -1) < 1:
        errors.append(_error("invalid_policy_sequence", "action.policy_sequence", "integer >= 1 required"))
    if action.get("risk_class") not in RISK_CLASSES:
        errors.append(_error("invalid_risk_class", "action.risk_class", "R0-R4 required"))
    issued_at, expires_at = action.get("issued_at"), action.get("expires_at")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_issued_at", "action.issued_at", "integer >= 0 required"))
    if type(expires_at) is not int or expires_at < 0:
        errors.append(_error("invalid_expires_at", "action.expires_at", "integer >= 0 required"))
    if type(issued_at) is int and issued_at > evaluation_tick:
        errors.append(_error("future_action", "action.issued_at", "action issued in future"))
    if type(expires_at) is int and evaluation_tick >= expires_at:
        errors.append(_error("expired_action", "action.expires_at", "action expired"))

    state_result = validate_state_witness(action.get("state_witness"), evaluation_tick)
    errors.extend(state_result["errors"])
    witness = state_result.get("witness")
    if witness:
        if witness.get("subject_id") != action.get("subject_id"):
            errors.append(_error("state_subject_mismatch", "action.state_witness.subject_id", "subject mismatch"))
        if witness.get("object_id") != action.get("object_id"):
            errors.append(_error("state_object_mismatch", "action.state_witness.object_id", "object mismatch"))

    expected_scope = action_scope_sha256(action)
    if action.get("scope_sha256") != expected_scope:
        errors.append(_error("scope_digest_mismatch", "action.scope_sha256", "scope digest mismatch"))

    approvals: list[dict[str, Any]] = []
    raw_approvals = action.get("approvals")
    if not isinstance(raw_approvals, list):
        errors.append(_error("invalid_type", "action.approvals", "array required"))
    else:
        approval_ids: set[str] = set()
        for index, raw in enumerate(raw_approvals):
            approval, approval_errors = _validate_approval(raw, index, evaluation_tick, expected_scope)
            errors.extend(approval_errors)
            if approval is not None:
                approval_id = approval.get("approval_id")
                if isinstance(approval_id, str) and approval_id in approval_ids:
                    errors.append(_error("duplicate_approval", f"action.approvals[{index}].approval_id", approval_id))
                elif isinstance(approval_id, str):
                    approval_ids.add(approval_id)
                approvals.append(approval)

    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "action": action,
        "state_witness": witness,
        "assurance_attestation": assurance_attestation,
        "approvals": approvals,
    }


def authorize_action(
    action_value: Mapping[str, Any],
    policy_value: Mapping[str, Any],
    evaluation_tick: int,
    issuer_id: str,
    trusted_assurance_issuers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Produce an exact, single-use authorization token or a sealed DENY token."""

    action_result = validate_action_envelope(action_value, evaluation_tick)
    policy_result = validate_policy_bundle(policy_value)
    errors = list(action_result.get("errors", [])) + list(policy_result.get("errors", []))
    action = action_result.get("action")
    policy = policy_result.get("policy")
    policy_decision: dict[str, Any] | None = None
    assurance_attestation = action_result.get("assurance_attestation")
    if action_result["status"] == "PASS" and assurance_attestation is not None:
        if not _trusted_assurance_issuer(assurance_attestation, trusted_assurance_issuers):
            errors.append(_error("untrusted_assurance_issuer", "action.assurance_attestation.issuer_id", "issuer/trust-domain not in external trust registry"))
    if action_result["status"] == "PASS" and policy_result["status"] == "PASS" and action and policy:
        if action.get("policy_sha256") != policy.get("policy_sha256"):
            errors.append(_error("policy_digest_mismatch", "action.policy_sha256", "action not bound to exact policy bundle"))
    if action_result["status"] == "PASS" and policy_result["status"] == "PASS" and action and policy and not errors:
        approval_types = sorted({str(item.get("approval_type")) for item in action_result["approvals"]})
        policy_request = {
            "policy_id": action["policy_id"],
            "policy_sequence": action["policy_sequence"],
            "subject_id": action["subject_id"],
            "capability": action["capability"],
            "tool_id": action["tool_id"],
            "execution_target": action["execution_target"],
            "risk_class": action["risk_class"],
            "approval_types": approval_types,
        }
        policy_decision = evaluate_policy(policy, policy_request, evaluation_tick)
        if policy_decision["outcome"] != "ALLOW":
            errors.extend(policy_decision["errors"])

        # Independent approval threshold is enforced here rather than delegated
        # to LLM reasoning. R3/R4 require two different trust domains; R4 must
        # include a HUMAN approval.
        risk_index = RISK_CLASSES.index(action["risk_class"])
        domains = {str(item.get("trust_domain")) for item in action_result["approvals"]}
        if risk_index >= RISK_CLASSES.index("R3") and len(domains) < 2:
            errors.append(_error("independent_approval_required", "action.approvals", "R3/R4 require two trust domains"))
        if action["risk_class"] == "R4" and not any(item.get("approval_type") == "HUMAN" for item in action_result["approvals"]):
            errors.append(_error("human_approval_required", "action.approvals", "R4 requires HUMAN approval"))

    outcome = "ALLOW" if not errors and action and policy and policy_decision else "DENY"
    token = {
        "contract_id": AUTHORIZATION_TOKEN_CONTRACT_ID,
        "issuer_id": issuer_id,
        "outcome": outcome,
        "action_sha256": action.get("action_sha256") if action else None,
        "scope_sha256": action.get("scope_sha256") if action else None,
        "decision_case_sha256": action.get("decision_case_sha256") if action else None,
        "evidence_report_sha256": action.get("evidence_report_sha256") if action else None,
        "assured_action_request_sha256": action.get("assured_action_request_sha256") if action else None,
        "assurance_attestation_sha256": (
            assurance_attestation.get("attestation_sha256")
            if isinstance(assurance_attestation, Mapping)
            else None
        ),
        "assurance_issuer_id": (
            assurance_attestation.get("issuer_id")
            if isinstance(assurance_attestation, Mapping)
            else None
        ),
        "subject_id": action.get("subject_id") if action else None,
        "object_id": action.get("object_id") if action else None,
        "capability": action.get("capability") if action else None,
        "tool_id": action.get("tool_id") if action else None,
        "execution_target": action.get("execution_target") if action else None,
        "payload_sha256": action.get("payload_sha256") if action else None,
        "policy_id": action.get("policy_id") if action else None,
        "policy_sequence": action.get("policy_sequence") if action else None,
        "policy_sha256": policy.get("policy_sha256") if policy else None,
        "policy_decision_sha256": policy_decision.get("decision_sha256") if policy_decision else None,
        "state_witness_sha256": (
            action.get("state_witness", {}).get("witness_sha256")
            if action and isinstance(action.get("state_witness"), Mapping)
            else None
        ),
        "state_version": (
            action.get("state_witness", {}).get("version")
            if action and isinstance(action.get("state_witness"), Mapping)
            else None
        ),
        "risk_class": action.get("risk_class") if action else None,
        "nonce": action.get("nonce") if action else None,
        "issued_at": evaluation_tick,
        "expires_at": action.get("expires_at") if action else evaluation_tick,
        "errors": errors,
        "token_sha256": "",
    }
    return seal_mapping(token, "token_sha256")


def validate_authorization_token(value: Any, evaluation_tick: int, require_allow: bool = True) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    token = _sealed(value, AUTHORIZATION_TOKEN_CONTRACT_ID, "token_sha256", "token", errors)
    if token is None:
        return {"status": "BLOCK", "errors": errors}
    if token.get("outcome") not in TOKEN_OUTCOMES:
        errors.append(_error("invalid_token_outcome", "token.outcome", "ALLOW or DENY required"))
    if require_allow and token.get("outcome") != "ALLOW":
        errors.append(_error("token_not_allow", "token.outcome", "ALLOW token required"))
    for field in (
        "action_sha256",
        "scope_sha256",
        "decision_case_sha256",
        "evidence_report_sha256",
        "assured_action_request_sha256",
        "assurance_attestation_sha256",
        "payload_sha256",
        "policy_sha256",
        "policy_decision_sha256",
        "state_witness_sha256",
    ):
        if not _is_sha256(token.get(field)):
            errors.append(_error("invalid_digest", f"token.{field}", "lowercase SHA-256 required"))
    for field in ("issuer_id", "assurance_issuer_id", "subject_id", "object_id", "capability", "tool_id", "execution_target", "policy_id", "nonce"):
        if not isinstance(token.get(field), str) or not token.get(field):
            errors.append(_error("missing_required", f"token.{field}", f"{field} required"))
    if type(token.get("policy_sequence")) is not int or token.get("policy_sequence", -1) < 1:
        errors.append(_error("invalid_policy_sequence", "token.policy_sequence", "integer >= 1 required"))
    if type(token.get("state_version")) is not int or token.get("state_version", -1) < 0:
        errors.append(_error("invalid_state_version", "token.state_version", "integer >= 0 required"))
    if token.get("risk_class") not in RISK_CLASSES:
        errors.append(_error("invalid_risk_class", "token.risk_class", "R0-R4 required"))
    expires_at = token.get("expires_at")
    if type(expires_at) is not int or expires_at < 0:
        errors.append(_error("invalid_expiry", "token.expires_at", "integer >= 0 required"))
    elif evaluation_tick >= expires_at:
        errors.append(_error("expired_token", "token.expires_at", "authorization expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "token": token}


class ExecutionLedgerError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteExecutionLedger:
    """Durable single-use token ledger with explicit unknown-outcome recovery."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS execution_ledger (
                nonce TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL,
                token_json TEXT NOT NULL,
                state TEXT NOT NULL,
                prepared_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                outcome_sha256 TEXT,
                effect_id TEXT,
                receipt_json TEXT
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteExecutionLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _row(self, nonce: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT nonce, token_sha256, token_json, state, prepared_at, updated_at, outcome_sha256, effect_id, receipt_json "
            "FROM execution_ledger WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if row is None:
            return None
        return {
            "nonce": row[0],
            "token_sha256": row[1],
            "token": json.loads(row[2]),
            "state": row[3],
            "prepared_at": row[4],
            "updated_at": row[5],
            "outcome_sha256": row[6],
            "effect_id": row[7],
            "receipt": None if row[8] is None else json.loads(row[8]),
        }

    def get(self, nonce: str) -> dict[str, Any] | None:
        return self._row(nonce)

    def prepare(self, token_value: Mapping[str, Any], observed_state_witness: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        token_result = validate_authorization_token(token_value, evaluation_tick, require_allow=True)
        if token_result["status"] != "PASS":
            raise ExecutionLedgerError("invalid_authorization_token", str(token_result["errors"]))
        token = token_result["token"]
        witness_result = validate_state_witness(observed_state_witness, evaluation_tick)
        if witness_result["status"] != "PASS":
            raise ExecutionLedgerError("invalid_observed_state", str(witness_result["errors"]))
        witness = witness_result["witness"]
        if witness["witness_sha256"] != token["state_witness_sha256"] or witness["version"] != token["state_version"]:
            raise ExecutionLedgerError("state_changed_since_authorization", "state witness does not match token")
        if witness["subject_id"] != token["subject_id"] or witness["object_id"] != token["object_id"]:
            raise ExecutionLedgerError("state_scope_mismatch", "state subject/object does not match token")

        nonce = token["nonce"]
        token_json = json.dumps(materialize_json(token), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(nonce)
            if current is not None:
                if current["token_sha256"] != token["token_sha256"]:
                    raise ExecutionLedgerError("nonce_replay_conflict", "nonce already bound to another token")
                self._conn.execute("COMMIT")
                return current
            self._conn.execute(
                "INSERT INTO execution_ledger(nonce, token_sha256, token_json, state, prepared_at, updated_at) VALUES(?,?,?,?,?,?)",
                (nonce, token["token_sha256"], token_json, "PREPARED", evaluation_tick, evaluation_tick),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(nonce)
        assert result is not None
        return result

    def complete(self, nonce: str, token_sha256: str, outcome_sha256: str, effect_id: str, completed_at: int) -> dict[str, Any]:
        if not _is_sha256(outcome_sha256):
            raise ExecutionLedgerError("invalid_outcome_digest", "outcome SHA-256 required")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(nonce)
            if current is None:
                raise ExecutionLedgerError("unknown_nonce", nonce)
            if current["token_sha256"] != token_sha256:
                raise ExecutionLedgerError("token_mismatch", "token digest mismatch")
            if current["state"] in {"COMPLETED", "RECONCILED_COMPLETE"}:
                if current["outcome_sha256"] == outcome_sha256 and current["effect_id"] == effect_id:
                    self._conn.execute("COMMIT")
                    return current
                raise ExecutionLedgerError("completion_conflict", "completed nonce has different outcome")
            if current["state"] not in {"PREPARED", "UNKNOWN"}:
                raise ExecutionLedgerError("invalid_ledger_state", current["state"])
            receipt = {
                "contract_id": EXECUTION_RECEIPT_CONTRACT_ID,
                "nonce": nonce,
                "token_sha256": token_sha256,
                "outcome_sha256": outcome_sha256,
                "effect_id": effect_id,
                "completed_at": completed_at,
                "resolution": "DIRECT" if current["state"] == "PREPARED" else "RECONCILED",
                "receipt_sha256": "",
            }
            receipt = seal_mapping(receipt, "receipt_sha256")
            new_state = "COMPLETED" if current["state"] == "PREPARED" else "RECONCILED_COMPLETE"
            self._conn.execute(
                "UPDATE execution_ledger SET state=?, updated_at=?, outcome_sha256=?, effect_id=?, receipt_json=? WHERE nonce=?",
                (
                    new_state,
                    completed_at,
                    outcome_sha256,
                    effect_id,
                    json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                    nonce,
                ),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(nonce)
        assert result is not None
        return result

    def mark_unknown(self, nonce: str, token_sha256: str, observed_at: int) -> dict[str, Any]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(nonce)
            if current is None:
                raise ExecutionLedgerError("unknown_nonce", nonce)
            if current["token_sha256"] != token_sha256:
                raise ExecutionLedgerError("token_mismatch", "token digest mismatch")
            if current["state"] in {"COMPLETED", "RECONCILED_COMPLETE"}:
                self._conn.execute("COMMIT")
                return current
            if current["state"] not in {"PREPARED", "UNKNOWN"}:
                raise ExecutionLedgerError("invalid_ledger_state", current["state"])
            self._conn.execute(
                "UPDATE execution_ledger SET state='UNKNOWN', updated_at=? WHERE nonce=?",
                (observed_at, nonce),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(nonce)
        assert result is not None
        return result

    def reconcile_denied(self, nonce: str, token_sha256: str, reason: str, reconciled_at: int) -> dict[str, Any]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(nonce)
            if current is None:
                raise ExecutionLedgerError("unknown_nonce", nonce)
            if current["token_sha256"] != token_sha256:
                raise ExecutionLedgerError("token_mismatch", "token digest mismatch")
            if current["state"] != "UNKNOWN":
                raise ExecutionLedgerError("reconciliation_requires_unknown", current["state"])
            receipt = {
                "contract_id": EXECUTION_RECEIPT_CONTRACT_ID,
                "nonce": nonce,
                "token_sha256": token_sha256,
                "outcome_sha256": None,
                "effect_id": None,
                "completed_at": reconciled_at,
                "resolution": "NO_EFFECT_CONFIRMED",
                "reason": reason,
                "receipt_sha256": "",
            }
            receipt = seal_mapping(receipt, "receipt_sha256")
            self._conn.execute(
                "UPDATE execution_ledger SET state='RECONCILED_DENY', updated_at=?, receipt_json=? WHERE nonce=?",
                (reconciled_at, json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False), nonce),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(nonce)
        assert result is not None
        return result


__all__ = [
    "ACTION_ENVELOPE_CONTRACT_ID",
    "APPROVAL_CONTRACT_ID",
    "ASSURANCE_ATTESTATION_CONTRACT_ID",
    "AUTHORIZATION_TOKEN_CONTRACT_ID",
    "EXECUTION_RECEIPT_CONTRACT_ID",
    "STATE_WITNESS_CONTRACT_ID",
    "ExecutionLedgerError",
    "SQLiteExecutionLedger",
    "action_scope_sha256",
    "assured_action_request_sha256",
    "authorize_action",
    "seal_contract",
    "validate_action_envelope",
    "validate_assurance_attestation",
    "validate_authorization_token",
    "validate_state_witness",
]
