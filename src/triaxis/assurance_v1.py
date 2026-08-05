"""Research-integrated Decision Assurance Case contract for TRIAXIS v3.0.

This module does not decide whether a natural-language claim is true.  It
validates whether a decision case preserves separation of duties, evidence
provenance, defeaters, falsification, authority monotonicity, and the boundary
between probabilistic reasoning and deterministic execution.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

ASSURANCE_CASE_CONTRACT_ID = "TRIAXIS_DECISION_ASSURANCE_CASE_v1"
INTAKE_CONTRACT_ID = "TRIAXIS_AUTHORITY_ENVELOPE_v1"
BRANCH_CONTRACT_ID = "TRIAXIS_EPISTEMIC_BRANCH_v1"
EVIDENCE_CONTRACT_ID = "TRIAXIS_EVIDENCE_RECORD_v1"
DEFEATER_CONTRACT_ID = "TRIAXIS_DEFEATER_v1"
FALSIFICATION_CONTRACT_ID = "TRIAXIS_FALSIFICATION_CONTRACT_v1"
SYNTHESIS_CONTRACT_ID = "TRIAXIS_ASSURANCE_SYNTHESIS_v1"
GATE_REQUEST_CONTRACT_ID = "TRIAXIS_GATE_REQUEST_v1"

_PASS_TYPES = frozenset({"PRIMARY", "SELF_AUDIT", "DEVIL", "ANGEL", "FALSIFIER", "INDEPENDENT_REVIEW"})
_RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")
_DECISIONS = frozenset({"ACCEPT", "ACCEPT_WITH_CONTROLS", "REJECT", "ESCALATE", "INSUFFICIENT_EVIDENCE", "POLICY_UNDECIDABLE"})
_DEFEATER_STATUS = frozenset({"OPEN", "MITIGATED", "REBUTTED", "ACCEPTED", "RESOLVED"})
_DEFEATER_SEVERITY = frozenset({"MINOR", "MATERIAL", "DECISION_BLOCKING"})
_VERIFIER_MODES = frozenset({"DETERMINISTIC_CHECK", "SYMBOLIC_SOLVER", "EXECUTABLE_TEST", "EXTERNAL_OBSERVATION"})


def seal_contract(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return seal_mapping(value, digest_field)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _result(status: str, reason: str, errors: list[dict[str, str]], **extra: Any) -> dict[str, Any]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in errors:
        key = (item["code"], item["path"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return {
        "status": status,
        "primary_reason": reason,
        "errors": unique,
        "error_count": len(unique),
        **extra,
    }


def _sealed(obj: Any, contract_id: str, digest_field: str, path: str, errors: list[dict[str, str]]) -> dict[str, Any] | None:
    if not isinstance(obj, Mapping):
        errors.append(_error("invalid_type", path, "object required"))
        return None
    value = dict(obj)
    if value.get("contract_id") != contract_id:
        errors.append(_error("invalid_contract_id", f"{path}.contract_id", f"expected {contract_id}"))
    if not verify_sealed_mapping(value, digest_field):
        errors.append(_error("digest_mismatch", f"{path}.{digest_field}", "canonical digest mismatch"))
    return value


def _risk_index(value: Any) -> int | None:
    try:
        return _RISK_CLASSES.index(value)
    except ValueError:
        return None


def _branch_independence(branch: Mapping[str, Any], primary: Mapping[str, Any] | None) -> str:
    if branch.get("verification_mode") in _VERIFIER_MODES:
        return "I3_EXTERNAL_VERIFIER"
    if primary is None or branch.get("pass_type") == "PRIMARY":
        return "I0_NOT_APPLICABLE"
    same_provider = branch.get("provider") == primary.get("provider")
    same_model = branch.get("model_family") == primary.get("model_family")
    same_context = branch.get("context_id") == primary.get("context_id")
    same_retrieval = branch.get("retrieval_set_id") == primary.get("retrieval_set_id")
    if same_provider and same_model and same_context and same_retrieval:
        return "I0_ROLE_PLAY_ONLY"
    if not same_context or not same_retrieval:
        if same_provider and same_model:
            return "I1_PROCEDURAL_ISOLATION"
    if not same_provider and not same_model and not same_retrieval:
        return "I2_HETEROGENEOUS_REVIEW"
    return "I1_PARTIAL_DECOUPLING"


def validate_assurance_case(value: Any) -> dict[str, Any]:
    """Validate a Decision Assurance Case and return a deterministic gate state."""

    if not isinstance(value, Mapping):
        return _result("BLOCK", "BLOCKED_BY_ASSURANCE_CONTRACT", [_error("invalid_type", "case", "mapping required")])
    try:
        case = materialize_json(value)
    except Exception as exc:
        return _result("BLOCK", "BLOCKED_BY_ASSURANCE_CONTRACT", [_error("materialization_failed", "case", type(exc).__name__)])
    if not isinstance(case, dict):
        return _result("BLOCK", "BLOCKED_BY_ASSURANCE_CONTRACT", [_error("invalid_type", "case", "object required")])

    errors: list[dict[str, str]] = []
    required = {"contract_id", "control_profile", "intake", "branches", "evidence", "defeaters", "falsification", "synthesis", "gate_request", "case_sha256"}
    for name in sorted(required - case.keys()):
        errors.append(_error("missing_required", f"case.{name}", f"{name} is required"))
    if case.get("contract_id") != ASSURANCE_CASE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "case.contract_id", "unexpected case contract"))
    if not verify_sealed_mapping(case, "case_sha256"):
        errors.append(_error("digest_mismatch", "case.case_sha256", "case digest mismatch"))
    profile = case.get("control_profile")
    if profile not in {"A0", "A1", "A2", "A3"}:
        errors.append(_error("invalid_control_profile", "case.control_profile", "A0-A3 required"))

    intake = _sealed(case.get("intake"), INTAKE_CONTRACT_ID, "intake_sha256", "case.intake", errors)
    initial_caps: set[str] = set()
    max_risk = None
    if intake:
        caps = intake.get("capabilities")
        if not isinstance(caps, list) or not all(isinstance(x, str) and x for x in caps):
            errors.append(_error("invalid_capabilities", "case.intake.capabilities", "array of capability strings required"))
        else:
            initial_caps = set(caps)
        max_risk = _risk_index(intake.get("max_risk_class"))
        if max_risk is None:
            errors.append(_error("invalid_risk_class", "case.intake.max_risk_class", "R0-R4 required"))
        for field in ("principal_id", "goal", "intent_id"):
            if not isinstance(intake.get(field), str) or not intake.get(field):
                errors.append(_error("missing_required", f"case.intake.{field}", f"{field} required"))

    raw_branches = case.get("branches")
    branches: list[dict[str, Any]] = []
    branch_ids: set[str] = set()
    pass_types: set[str] = set()
    if not isinstance(raw_branches, list):
        errors.append(_error("invalid_type", "case.branches", "array required"))
    else:
        for i, raw in enumerate(raw_branches):
            path = f"case.branches[{i}]"
            branch = _sealed(raw, BRANCH_CONTRACT_ID, "branch_sha256", path, errors)
            if not branch:
                continue
            branches.append(branch)
            bid = branch.get("branch_id")
            ptype = branch.get("pass_type")
            if not isinstance(bid, str) or not bid:
                errors.append(_error("missing_required", f"{path}.branch_id", "branch_id required"))
            elif bid in branch_ids:
                errors.append(_error("duplicate_branch_id", f"{path}.branch_id", "branch_id must be unique"))
            else:
                branch_ids.add(bid)
            if ptype not in _PASS_TYPES:
                errors.append(_error("invalid_pass_type", f"{path}.pass_type", "unknown pass type"))
            else:
                pass_types.add(ptype)
            for field in ("provider", "model_family", "context_id", "retrieval_set_id"):
                if not isinstance(branch.get(field), str) or not branch.get(field):
                    errors.append(_error("missing_required", f"{path}.{field}", f"{field} required"))
            if not isinstance(branch.get("claims"), list):
                errors.append(_error("invalid_type", f"{path}.claims", "claims array required"))
    if "PRIMARY" not in pass_types:
        errors.append(_error("missing_primary", "case.branches", "PRIMARY branch required"))
    if profile in {"A2", "A3"} and "FALSIFIER" not in pass_types:
        errors.append(_error("missing_falsifier", "case.branches", "FALSIFIER required for A2/A3"))

    primary = next((b for b in branches if b.get("pass_type") == "PRIMARY"), None)
    independence = {str(b.get("branch_id")): _branch_independence(b, primary) for b in branches if b.get("branch_id")}

    raw_evidence = case.get("evidence")
    evidence_ids: set[str] = set()
    source_groups: dict[str, set[str]] = {}
    if not isinstance(raw_evidence, list):
        errors.append(_error("invalid_type", "case.evidence", "array required"))
    else:
        for i, raw in enumerate(raw_evidence):
            path = f"case.evidence[{i}]"
            record = _sealed(raw, EVIDENCE_CONTRACT_ID, "evidence_sha256", path, errors)
            if not record:
                continue
            eid = record.get("evidence_id")
            if not isinstance(eid, str) or not eid:
                errors.append(_error("missing_required", f"{path}.evidence_id", "evidence_id required"))
                continue
            if eid in evidence_ids:
                errors.append(_error("duplicate_evidence_id", f"{path}.evidence_id", "evidence_id must be unique"))
            evidence_ids.add(eid)
            group = record.get("source_group")
            if not isinstance(group, str) or not group:
                errors.append(_error("missing_required", f"{path}.source_group", "source_group required"))
            else:
                source_groups.setdefault(group, set()).add(eid)
            digest = record.get("content_sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                errors.append(_error("invalid_content_digest", f"{path}.content_sha256", "64-char digest required"))

    claim_ids: set[str] = set()
    load_bearing_without_evidence: list[str] = []
    for bi, branch in enumerate(branches):
        for ci, claim in enumerate(branch.get("claims", [])):
            path = f"case.branches[{bi}].claims[{ci}]"
            if not isinstance(claim, Mapping):
                errors.append(_error("invalid_type", path, "claim object required"))
                continue
            cid = claim.get("claim_id")
            if not isinstance(cid, str) or not cid:
                errors.append(_error("missing_required", f"{path}.claim_id", "claim_id required"))
                continue
            if cid in claim_ids:
                errors.append(_error("duplicate_claim_id", f"{path}.claim_id", "claim_id must be unique"))
            claim_ids.add(cid)
            refs = claim.get("evidence_ids")
            classification = claim.get("classification")
            if not isinstance(refs, list) or not all(isinstance(x, str) for x in refs):
                errors.append(_error("invalid_evidence_refs", f"{path}.evidence_ids", "array required"))
                refs = []
            for ref in refs:
                if ref not in evidence_ids:
                    errors.append(_error("unknown_evidence", f"{path}.evidence_ids", ref))
            if claim.get("load_bearing") is True and not refs and classification != "UNVERIFIED_ASSUMPTION":
                load_bearing_without_evidence.append(cid)
    for cid in load_bearing_without_evidence:
        errors.append(_error("unsupported_load_bearing_claim", "case.branches", cid))

    blocking_defeaters: list[str] = []
    raw_defeaters = case.get("defeaters")
    if not isinstance(raw_defeaters, list):
        errors.append(_error("invalid_type", "case.defeaters", "array required"))
    else:
        for i, raw in enumerate(raw_defeaters):
            path = f"case.defeaters[{i}]"
            d = _sealed(raw, DEFEATER_CONTRACT_ID, "defeater_sha256", path, errors)
            if not d:
                continue
            severity, status = d.get("severity"), d.get("status")
            if severity not in _DEFEATER_SEVERITY:
                errors.append(_error("invalid_defeater_severity", f"{path}.severity", "invalid severity"))
            if status not in _DEFEATER_STATUS:
                errors.append(_error("invalid_defeater_status", f"{path}.status", "invalid status"))
            if severity == "DECISION_BLOCKING" and status in {"OPEN", "ACCEPTED"}:
                blocking_defeaters.append(str(d.get("defeater_id", i)))
            if status in {"MITIGATED", "REBUTTED", "RESOLVED"}:
                refs = d.get("resolution_evidence_ids")
                if not isinstance(refs, list) or not refs:
                    errors.append(_error("missing_resolution_evidence", f"{path}.resolution_evidence_ids", "resolution evidence required"))
                elif any(ref not in evidence_ids for ref in refs):
                    errors.append(_error("unknown_evidence", f"{path}.resolution_evidence_ids", "unknown resolution evidence"))

    falsifier = _sealed(case.get("falsification"), FALSIFICATION_CONTRACT_ID, "falsification_sha256", "case.falsification", errors)
    if falsifier and profile in {"A2", "A3"}:
        for field in ("hypothesis", "competing_hypothesis", "observable_variable", "measurement", "threshold", "time_window", "decision_update_rule"):
            if falsifier.get(field) in (None, "", []):
                errors.append(_error("decorative_falsifier", f"case.falsification.{field}", "measurable falsification field required"))

    synthesis = _sealed(case.get("synthesis"), SYNTHESIS_CONTRACT_ID, "synthesis_sha256", "case.synthesis", errors)
    requested_caps: set[str] = set()
    requested_risk = None
    decision = None
    if synthesis:
        decision = synthesis.get("decision")
        if decision not in _DECISIONS:
            errors.append(_error("invalid_decision", "case.synthesis.decision", "invalid decision"))
        if "permission_status" in synthesis:
            errors.append(_error("synthesis_self_authorization", "case.synthesis.permission_status", "synthesis may request but never grant authority"))
        request = synthesis.get("authority_request")
        if not isinstance(request, Mapping):
            errors.append(_error("invalid_type", "case.synthesis.authority_request", "authority_request required"))
        else:
            caps = request.get("capabilities")
            if not isinstance(caps, list) or not all(isinstance(x, str) for x in caps):
                errors.append(_error("invalid_capabilities", "case.synthesis.authority_request.capabilities", "array required"))
            else:
                requested_caps = set(caps)
                if not requested_caps.issubset(initial_caps):
                    errors.append(_error("authority_expansion", "case.synthesis.authority_request.capabilities", "reasoning may only narrow initial authority"))
            requested_risk = _risk_index(request.get("risk_class"))
            if requested_risk is None:
                errors.append(_error("invalid_risk_class", "case.synthesis.authority_request.risk_class", "R0-R4 required"))
            elif max_risk is not None and requested_risk > max_risk:
                errors.append(_error("risk_expansion", "case.synthesis.authority_request.risk_class", "requested risk exceeds intake envelope"))

    gate = _sealed(case.get("gate_request"), GATE_REQUEST_CONTRACT_ID, "gate_request_sha256", "case.gate_request", errors)
    if gate:
        for field in ("policy_version", "state_snapshot_ref", "action_payload_sha256", "execution_target", "nonce", "expires_at"):
            if gate.get(field) in (None, ""):
                errors.append(_error("missing_required", f"case.gate_request.{field}", f"{field} required"))
        if gate.get("gate_outcome") in {"ALLOW", "DENY"}:
            errors.append(_error("gate_request_contains_outcome", "case.gate_request.gate_outcome", "request cannot mint its own gate outcome"))

    independent_review_ok = any(
        b.get("pass_type") == "INDEPENDENT_REVIEW" and independence.get(str(b.get("branch_id"))) in {"I2_HETEROGENEOUS_REVIEW", "I3_EXTERNAL_VERIFIER"}
        for b in branches
    )
    external_verifier_ok = any(level == "I3_EXTERNAL_VERIFIER" for level in independence.values())
    if requested_risk is not None and requested_risk >= _RISK_CLASSES.index("R3") and not independent_review_ok:
        errors.append(_error("independent_review_required", "case.branches", "R3/R4 requires heterogeneous independent review"))
    if requested_risk == _RISK_CLASSES.index("R4"):
        approvals = intake.get("approvals") if intake else None
        if not isinstance(approvals, list) or not any(isinstance(x, Mapping) and x.get("type") == "HUMAN" for x in approvals):
            errors.append(_error("human_approval_required", "case.intake.approvals", "R4 requires explicit human approval"))
    if profile == "A3" and not external_verifier_ok:
        errors.append(_error("external_verifier_required", "case.branches", "A3 requires a verifier with a distinct failure mode"))

    if errors:
        return _result(
            "BLOCK",
            "BLOCKED_BY_ASSURANCE_CONTRACT",
            errors,
            independence=independence,
            blocking_defeaters=blocking_defeaters,
        )
    if blocking_defeaters or decision in {"ESCALATE", "INSUFFICIENT_EVIDENCE", "POLICY_UNDECIDABLE"}:
        return _result(
            "ESCALATE",
            "ASSURANCE_REQUIRES_ESCALATION",
            [],
            independence=independence,
            blocking_defeaters=blocking_defeaters,
            requested_capabilities=sorted(requested_caps),
        )
    return _result(
        "PASS",
        "ASSURANCE_CASE_VALID",
        [],
        independence=independence,
        blocking_defeaters=[],
        requested_capabilities=sorted(requested_caps),
        verified_scope="STRUCTURE_PROVENANCE_SEPARATION_FALSIFICATION_AND_AUTHORITY_MONOTONICITY",
    )


__all__ = [
    "ASSURANCE_CASE_CONTRACT_ID",
    "BRANCH_CONTRACT_ID",
    "DEFEATER_CONTRACT_ID",
    "EVIDENCE_CONTRACT_ID",
    "FALSIFICATION_CONTRACT_ID",
    "GATE_REQUEST_CONTRACT_ID",
    "INTAKE_CONTRACT_ID",
    "SYNTHESIS_CONTRACT_ID",
    "seal_contract",
    "validate_assurance_case",
]
