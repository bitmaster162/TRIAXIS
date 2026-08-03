"""Versioned deterministic projections of TRIAXIS governance gates.

The projection is intentionally narrower than the natural-language
specification. A PASS here means only that the explicit deterministic gates
produce the expected status for a structured scenario.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, Mapping

from .input_contract import (
    INPUT_CONTRACT_ID,
    INPUT_CONTRACT_V1_ID,
    INPUT_CONTRACT_V2_ID,
    validate_scenario,
)
from .semantic_ingress import SEMANTIC_INGRESS_CONTRACT_ID, validate_ingress

Decision = Dict[str, Any]
Scenario = Mapping[str, Any]


_VERSION_FEATURES: dict[str, frozenset[str]] = {
    "2.3-RC1": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "authority_receipt",
            "principal_authentication",
            "target_digest_binding",
            "capability_gate",
            "data_gate",
            "budget_gate",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "toctou_target_binding",
            "idempotency_key",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
        }
    ),
    "2.4-RC1": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
        }
    ),
    "2.5-RC1": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "evidence_origin_graph",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
        }
    ),
    "2.6-RC1": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "evidence_origin_graph",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
            "release_integrity",
        }
    ),
    "2.6-RC2": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "evidence_origin_graph",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
            "release_integrity",
        }
    ),
    "2.7-RC1": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "evidence_origin_graph",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
            "release_integrity",
            "contradiction_all_x",
            "cross_axis_integrity",
            "decision_severity_lattice",
        }
    ),
    "2.7-RC2": frozenset(
        {
            "task_graph",
            "e_x_routing",
            "policy_gate",
            "policy_integrity",
            "authority_receipt",
            "principal_authentication",
            "authority_composition",
            "delegation_validation",
            "target_digest_binding",
            "capability_gate",
            "toolchain_integrity",
            "capability_evidence_trust",
            "data_gate",
            "data_lineage",
            "trace_secrecy",
            "budget_gate",
            "atomic_budget_reservation",
            "verification_gate",
            "contradiction_gate_x3",
            "independence_gate_critical",
            "evidence_origin_graph",
            "reliance_gate",
            "toctou_target_binding",
            "atomic_compare_and_commit",
            "idempotency_key",
            "idempotency_payload_binding",
            "unknown_outcome",
            "dynamic_revalidation",
            "partial_execution_ledger",
            "resume_integrity",
            "ledger_integrity",
            "release_integrity",
            "contradiction_all_x",
            "cross_axis_integrity",
            "decision_severity_lattice",
        }
    ),
}

# v2.8 preserves v2.7 governance semantics and adds a strict fail-closed
# structured-input contract before any Router or governance gate executes.
_VERSION_FEATURES["2.8-RC1"] = _VERSION_FEATURES["2.7-RC2"] | frozenset({"input_contract_gate"})
_VERSION_FEATURES["2.8-RC2"] = _VERSION_FEATURES["2.8-RC1"]

# v2.9 preserves structured governance semantics and adds a source-bound
# semantic-ingress contract before structured scenarios are trusted.
_VERSION_FEATURES["2.9-RC1"] = _VERSION_FEATURES["2.8-RC2"] | frozenset(
    {
        "semantic_ingress_gate",
        "input_contract_v2",
        "x0_decision_gate_closure",
        "limit_accumulator",
    }
)
_VERSION_FEATURES["2.9-RC2"] = _VERSION_FEATURES["2.9-RC1"]


def supported_versions() -> tuple[str, ...]:
    return tuple(sorted(_VERSION_FEATURES))


def _block(reason: str, controls: Iterable[str], *, status: str = "BLOCK") -> Decision:
    return {
        "status": status,
        "primary_reason": reason,
        "reasons": [reason],
        "controls": sorted(set(controls)),
    }


def _allow(controls: Iterable[str], *, limited: bool = False, notes: Iterable[str] = ()) -> Decision:
    return {
        "status": "ALLOW_WITH_LIMITS" if limited else "ALLOW",
        "primary_reason": "CONDITIONS_SATISFIED",
        "reasons": list(notes),
        "controls": sorted(set(controls)),
    }


def _final_allow(
    controls: Iterable[str],
    *,
    limit_reasons: Iterable[str] = (),
    degraded_capability: bool = False,
) -> Decision:
    reasons = list(dict.fromkeys(limit_reasons))
    if degraded_capability:
        reasons.append("CAPABILITY_DEGRADED")
        reasons = list(dict.fromkeys(reasons))
    decision = _allow(controls, limited=bool(reasons), notes=reasons)
    if reasons:
        decision["primary_reason"] = reasons[0]
    return decision


def evaluate_candidate(version: str, scenario: Scenario) -> Decision:
    """Evaluate one structured scenario under a frozen TRIAXIS projection."""

    if version not in _VERSION_FEATURES:
        raise ValueError(f"Unsupported TRIAXIS projection: {version}")

    features = _VERSION_FEATURES[version]
    input_contract = INPUT_CONTRACT_V2_ID if "input_contract_v2" in features else INPUT_CONTRACT_V1_ID
    if "input_contract_gate" in features:
        input_errors = validate_scenario(scenario, input_contract)
        if input_errors:
            return {
                "status": "BLOCK",
                "primary_reason": "BLOCKED_BY_INPUT_CONTRACT",
                "reasons": ["BLOCKED_BY_INPUT_CONTRACT"],
                "controls": ["INPUT_CONTRACT_GATE"],
                "input_status": "INVALID",
                "input_contract": input_contract,
                "input_errors": input_errors,
            }

    s = deepcopy(dict(scenario))
    controls: list[str] = ["INPUT_CONTRACT_GATE", "ROUTER"] if "input_contract_gate" in features else ["ROUTER"]
    e_level = int(s.get("e_level", 0))
    x_level = int(s.get("x_level", 0))
    limit_reasons: list[str] = []
    if "limit_accumulator" in features and s.get("policy_status") == "ALLOW_WITH_LIMITS":
        limit_reasons.append("POLICY_LIMITS_APPLY")

    if s.get("hard_prohibition", False) or s.get("policy_status") == "DENY":
        controls.append("POLICY_GATE")
        return _block("BLOCKED_BY_POLICY", controls)

    if "policy_integrity" in features:
        controls.append("POLICY_INTEGRITY")
        if s.get("policy_conflict_open", False):
            return _block("POLICY_CONFLICT_OPEN", controls, status="HUMAN_DECISION_REQUIRED")
        if s.get("policy_binding_required", False) and not s.get("policy_digest_match", False):
            return _block("BLOCKED_BY_STALE_POLICY", controls)

    contradiction_applies = x_level == 3 or "contradiction_all_x" in features
    if contradiction_applies and s.get("material_contradiction_open", False) and s.get("contradiction_material_to_decision", True):
        controls.extend(["WITNESS", "CONTRADICTION_REGISTER"])
        return _block("BLOCKED_BY_VERIFICATION", controls)

    if (e_level == 3 or x_level == 3) and s.get("critical_claim", False):
        controls.append("INDEPENDENCE_GATE")
        if not s.get("independent_basis_present", False):
            return _block("BLOCKED_BY_VERIFICATION", controls)
        if "evidence_origin_graph" in features and s.get("source_independence_required", False) and not s.get("source_independence_established", False):
            controls.append("EVIDENCE_ORIGIN_GRAPH")
            return _block("BLOCKED_BY_CORRELATED_EVIDENCE", controls)

    # Legacy pre-v2.7 reliance behavior is preserved for historical projections.
    if (
        "reliance_gate" in features
        and "decision_severity_lattice" not in features
        and "limit_accumulator" not in features
        and x_level == 0
        and s.get("downstream_reliance_material", False)
    ):
        controls.append("RELIANCE_GATE")
        if not s.get("reliance_conditions_satisfied", False):
            return _allow(controls, limited=True, notes=["RELIANCE_RESTRICTIONS_REQUIRED"]) | {"primary_reason": "RELIANCE_RESTRICTIONS_REQUIRED"}

    if "cross_axis_integrity" in features:
        if s.get("uses_tool_output", False) and s.get("tool_binding_required", False) and not s.get("tool_digest_match", False):
            controls.append("TOOLCHAIN_INTEGRITY")
            return _block("BLOCKED_BY_TOOLCHAIN_INTEGRITY", controls)
        if s.get("uses_tool_output", False) and s.get("capability_evidence_trust_required", False) and not s.get("capability_evidence_trusted", False):
            controls.append("CAPABILITY_EVIDENCE")
            return _block("BLOCKED_BY_CAPABILITY_EVIDENCE", controls)
        if s.get("resumed_state_used", False) and s.get("resume_integrity_required", False) and not s.get("resume_checkpoint_valid", False):
            controls.append("CONTINUITY_INTEGRITY")
            return _block("BLOCKED_BY_RESUME_INTEGRITY", controls)
        if s.get("ledger_state_used", False) and s.get("ledger_integrity_required", False) and not s.get("ledger_integrity_valid", False):
            controls.append("LEDGER_INTEGRITY")
            return _block("BLOCKED_BY_LEDGER_INTEGRITY", controls)

    # Data Gate applies even at X0 when the response discloses data.
    if s.get("data_gate_required", False):
        controls.append("DATA_GATE")
        if "data_lineage" in features and s.get("derived_data_lineage_required", False) and not s.get("data_lineage_preserved", False):
            return _block("BLOCKED_BY_DATA_LINEAGE", controls)
        if "trace_secrecy" in features and s.get("trace_contains_sensitive_data", False):
            return _block("BLOCKED_BY_TRACE_DISCLOSURE", controls)
        data_status = s.get("data_status", "NOT_REQUIRED")
        if data_status == "DENY":
            return _block("BLOCKED_BY_DATA", controls)
        if data_status == "ALLOW_WITH_REDACTION" and not s.get("redaction_applied", False):
            return _block("BLOCKED_BY_DATA", controls)

    if "release_integrity" in features and s.get("release_gate_required", False):
        controls.append("RELEASE_INTEGRITY")
        if not s.get("release_manifest_valid", False):
            return _block("BLOCKED_BY_RELEASE_INTEGRITY", controls)

    if "decision_severity_lattice" in features and "reliance_gate" in features and x_level == 0 and s.get("downstream_reliance_material", False):
        controls.append("RELIANCE_GATE")
        if not s.get("reliance_conditions_satisfied", False):
            if "limit_accumulator" in features:
                limit_reasons.append("RELIANCE_RESTRICTIONS_REQUIRED")
            else:
                return _allow(controls, limited=True, notes=["RELIANCE_RESTRICTIONS_REQUIRED"]) | {"primary_reason": "RELIANCE_RESTRICTIONS_REQUIRED"}

    # v2.9 closes explicitly activated decision gates for X0 instead of
    # returning before their evidence is inspected.
    if x_level == 0:
        if "x0_decision_gate_closure" in features:
            if s.get("target_binding_required", False) and not s.get("target_digest_match", False):
                controls.append("TOCTOU_GUARD")
                return _block("BLOCKED_BY_STALE_BINDING", controls)
            if s.get("object_binding_required", False) and not s.get("object_binding_current", False):
                controls.append("TOCTOU_GUARD")
                return _block("BLOCKED_BY_STALE_BINDING", controls)
            if s.get("preconditions_required", False) and not s.get("preconditions_pass", False):
                controls.append("PRECONDITION_GATE")
                return _block("BLOCKED_BY_PRECONDITION", controls)
            if s.get("budget_gate_required", False):
                controls.append("BUDGET_GATE")
                if s.get("budget_status") not in {"WITHIN_LIMIT", "NOT_REQUIRED"}:
                    return _block("BLOCKED_BY_BUDGET", controls)
                if "atomic_budget_reservation" in features and s.get("concurrent_budget_reservation", False) and not s.get("atomic_budget_reservation", False):
                    controls.append("BUDGET_RESERVATION")
                    return _block("BLOCKED_BY_BUDGET_RACE", controls)
            if s.get("verification_required", False):
                controls.append("VERIFICATION_GATE")
                if s.get("verification_status") != "VERIFIED_WITHIN_SCOPE" or not s.get("verified_scope_adequate", True):
                    return _block("BLOCKED_BY_VERIFICATION", controls)
            return _final_allow(controls, limit_reasons=limit_reasons)
        return _allow(controls)

    controls.extend(["POLICY_GATE", "AUTHORITY_GATE", "CAPABILITY_GATE"])

    if s.get("authority_status") != "VALID":
        reason = "HUMAN_DECISION_REQUIRED" if s.get("authority_status") == "AMBIGUOUS" else "BLOCKED_BY_AUTHORITY"
        return _block(reason, controls, status="HUMAN_DECISION_REQUIRED" if reason == "HUMAN_DECISION_REQUIRED" else "BLOCK")
    if not s.get("principal_authenticated", False):
        return _block("BLOCKED_BY_AUTHORITY", controls)
    if s.get("authority_revoked", False) or s.get("authority_expired", False):
        return _block("BLOCKED_BY_AUTHORITY", controls)
    if not s.get("authority_scope_match", True):
        return _block("BLOCKED_BY_AUTHORITY", controls)
    if "authority_composition" in features and s.get("multi_principal_required", False) and not s.get("approval_quorum_met", False):
        controls.append("AUTHORITY_COMPOSITION")
        return _block("BLOCKED_BY_AUTHORITY_QUORUM", controls)
    if "delegation_validation" in features and s.get("delegation_validation_required", False) and not s.get("delegation_chain_valid", False):
        controls.append("DELEGATION_GATE")
        return _block("BLOCKED_BY_DELEGATION", controls)
    if not s.get("target_digest_match", True):
        return _block("BLOCKED_BY_STALE_BINDING", controls)

    capability = s.get("capability_status", "AVAILABLE")
    if capability in {"UNAVAILABLE", "UNKNOWN"}:
        return _block("BLOCKED_BY_CAPABILITY", controls)
    if capability == "DEGRADED" and not s.get("degraded_capability_adequate", False):
        return _block("BLOCKED_BY_CAPABILITY", controls)
    if "toolchain_integrity" in features and s.get("tool_binding_required", False) and not s.get("tool_digest_match", False):
        controls.append("TOOLCHAIN_INTEGRITY")
        return _block("BLOCKED_BY_TOOLCHAIN_INTEGRITY", controls)
    if "capability_evidence_trust" in features and s.get("capability_evidence_trust_required", False) and not s.get("capability_evidence_trusted", False):
        controls.append("CAPABILITY_EVIDENCE")
        return _block("BLOCKED_BY_CAPABILITY_EVIDENCE", controls)

    if s.get("data_gate_required", False):
        data_status = s.get("data_status", "NOT_REQUIRED")
        if data_status == "DENY":
            return _block("BLOCKED_BY_DATA", controls)
        if data_status == "ALLOW_WITH_REDACTION" and not s.get("redaction_applied", False):
            return _block("BLOCKED_BY_DATA", controls)

    if s.get("budget_gate_required", False):
        controls.append("BUDGET_GATE")
        if s.get("budget_status") not in {"WITHIN_LIMIT", "NOT_REQUIRED"}:
            return _block("BLOCKED_BY_BUDGET", controls)
        if "atomic_budget_reservation" in features and s.get("concurrent_budget_reservation", False) and not s.get("atomic_budget_reservation", False):
            controls.append("BUDGET_RESERVATION")
            return _block("BLOCKED_BY_BUDGET_RACE", controls)

    if not s.get("object_binding_current", True):
        controls.append("TOCTOU_GUARD")
        return _block("BLOCKED_BY_STALE_BINDING", controls)
    if "atomic_compare_and_commit" in features and s.get("transactional_commit_required", False) and not s.get("atomic_compare_and_commit", False):
        controls.append("CONCURRENCY_GATE")
        return _block("BLOCKED_BY_COMMIT_RACE", controls)

    if not s.get("preconditions_pass", True):
        controls.append("PRECONDITION_GATE")
        return _block("BLOCKED_BY_PRECONDITION", controls)

    if s.get("verification_required", False):
        controls.append("VERIFICATION_GATE")
        if s.get("verification_status") != "VERIFIED_WITHIN_SCOPE":
            return _block("BLOCKED_BY_VERIFICATION", controls)
        if not s.get("verified_scope_adequate", True):
            return _block("BLOCKED_BY_VERIFICATION", controls)

    if "idempotency_payload_binding" in features and s.get("idempotency_payload_binding_required", False) and not s.get("idempotency_payload_match", False):
        controls.append("IDEMPOTENCY_PAYLOAD_BINDING")
        return _block("BLOCKED_BY_IDEMPOTENCY_COLLISION", controls)

    if "resume_integrity" in features and s.get("resume_integrity_required", False) and not s.get("resume_checkpoint_valid", False):
        controls.append("CONTINUITY_INTEGRITY")
        return _block("BLOCKED_BY_RESUME_INTEGRITY", controls)

    if "ledger_integrity" in features and s.get("ledger_integrity_required", False) and not s.get("ledger_integrity_valid", False):
        controls.append("LEDGER_INTEGRITY")
        return _block("BLOCKED_BY_LEDGER_INTEGRITY", controls)

    if s.get("possible_commit_timeout", False):
        controls.extend(["IDEMPOTENCY", "OUTCOME_RECONCILIATION"])
        return {
            "status": "HOLD",
            "primary_reason": "UNKNOWN_OUTCOME",
            "reasons": ["UNKNOWN_OUTCOME", "RECONCILIATION_REQUIRED"],
            "controls": sorted(set(controls)),
        }

    if "limit_accumulator" in features:
        return _final_allow(
            controls,
            limit_reasons=limit_reasons,
            degraded_capability=capability == "DEGRADED",
        )
    limited = s.get("policy_status") == "ALLOW_WITH_LIMITS" or capability == "DEGRADED"
    return _allow(controls, limited=limited)


_INGRESS_SEVERITY = {
    "ALLOW": 0,
    "ALLOW_WITH_LIMITS": 1,
    "HOLD": 2,
    "HUMAN_DECISION_REQUIRED": 2,
    "BLOCK": 3,
}


def evaluate_ingress(version: str, record: Mapping[str, Any]) -> Decision:
    """Evaluate a source-bound semantic-ingress record.

    The ingress gate validates provenance and conservative explicit-action
    coverage before delegating each structured action node to
    :func:`evaluate_candidate`.
    """

    if version not in _VERSION_FEATURES:
        raise ValueError(f"Unsupported TRIAXIS projection: {version}")
    if "semantic_ingress_gate" not in _VERSION_FEATURES[version]:
        raise ValueError(f"TRIAXIS {version} does not implement semantic ingress")

    ingress_errors = validate_ingress(record)
    if ingress_errors:
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_SEMANTIC_INGRESS",
            "reasons": ["BLOCKED_BY_SEMANTIC_INGRESS"],
            "controls": ["CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE"],
            "ingress_status": "INVALID",
            "ingress_contract": SEMANTIC_INGRESS_CONTRACT_ID,
            "ingress_errors": ingress_errors,
        }

    data = deepcopy(dict(record))
    extraction_status = data["extraction_status"]
    if extraction_status == "NEEDS_CLARIFICATION":
        return {
            "status": "HUMAN_DECISION_REQUIRED",
            "primary_reason": "SEMANTIC_INGRESS_AMBIGUOUS",
            "reasons": ["SEMANTIC_INGRESS_AMBIGUOUS"],
            "controls": ["CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE"],
            "ingress_status": extraction_status,
            "ingress_contract": SEMANTIC_INGRESS_CONTRACT_ID,
        }
    if extraction_status == "INVALID":
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_SEMANTIC_INGRESS",
            "reasons": ["BLOCKED_BY_SEMANTIC_INGRESS"],
            "controls": ["CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE"],
            "ingress_status": extraction_status,
            "ingress_contract": SEMANTIC_INGRESS_CONTRACT_ID,
        }

    node_decisions: list[dict[str, Any]] = []
    for node in data["nodes"]:
        decision = evaluate_candidate(version, node["scenario"])
        node_decisions.append({"node_id": node["node_id"], "depends_on": list(node["depends_on"]), "decision": decision})

    if len(node_decisions) == 1:
        result = deepcopy(node_decisions[0]["decision"])
        result["controls"] = sorted(set(result.get("controls", [])) | {"CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE"})
        result["ingress_status"] = "VALID"
        result["ingress_contract"] = SEMANTIC_INGRESS_CONTRACT_ID
        result["node_decisions"] = node_decisions
        return result

    completion_mode = data["completion_mode"]
    by_id = {row["node_id"]: row for row in node_decisions}
    executable: set[str] = set()
    dependency_blocked: list[str] = []
    for row in node_decisions:
        decision = row["decision"]
        allowed = decision.get("status") in {"ALLOW", "ALLOW_WITH_LIMITS"}
        dependencies_ok = all(dep in executable for dep in row["depends_on"])
        if allowed and dependencies_ok:
            executable.add(row["node_id"])
        elif allowed and not dependencies_ok:
            dependency_blocked.append(row["node_id"])
            row["decision"] = {
                "status": "BLOCK",
                "primary_reason": "BLOCKED_BY_DEPENDENCY",
                "reasons": ["BLOCKED_BY_DEPENDENCY"],
                "controls": ["TASK_GRAPH"],
            }

    decisions = [row["decision"] for row in node_decisions]
    non_allow = [d for d in decisions if d.get("status") not in {"ALLOW", "ALLOW_WITH_LIMITS"}]
    allowed = [d for d in decisions if d.get("status") in {"ALLOW", "ALLOW_WITH_LIMITS"}]

    if completion_mode in {"SAFE_PARTIAL", "BEST_EFFORT"} and allowed and non_allow:
        result: Decision = {
            "status": "ALLOW_WITH_LIMITS",
            "primary_reason": "SAFE_PARTIAL",
            "reasons": ["SAFE_PARTIAL"],
            "controls": ["CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE", "TASK_GRAPH"],
        }
    else:
        worst = max(decisions, key=lambda d: _INGRESS_SEVERITY.get(str(d.get("status")), 99))
        result = deepcopy(worst)
        result["controls"] = sorted(set(result.get("controls", [])) | {"CONTROL_SURFACE_SCANNER", "SEMANTIC_INGRESS_GATE", "TASK_GRAPH"})

    result["ingress_status"] = "VALID"
    result["ingress_contract"] = SEMANTIC_INGRESS_CONTRACT_ID
    result["node_decisions"] = node_decisions
    if dependency_blocked:
        result["dependency_blocked_nodes"] = sorted(dependency_blocked)
    return result
