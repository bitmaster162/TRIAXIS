"""Versioned deterministic projections of TRIAXIS governance gates.

The projection is intentionally narrower than the natural-language
specification. A PASS here means only that the explicit deterministic gates
produce the expected status for a structured scenario.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, Mapping

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
}


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


def evaluate_candidate(version: str, scenario: Scenario) -> Decision:
    """Evaluate one structured scenario under a frozen TRIAXIS projection."""

    if version not in _VERSION_FEATURES:
        raise ValueError(f"Unsupported TRIAXIS projection: {version}")

    s = deepcopy(dict(scenario))
    features = _VERSION_FEATURES[version]
    controls: list[str] = ["ROUTER"]
    e_level = int(s.get("e_level", 0))
    x_level = int(s.get("x_level", 0))

    if s.get("hard_prohibition", False) or s.get("policy_status") == "DENY":
        controls.append("POLICY_GATE")
        return _block("BLOCKED_BY_POLICY", controls)

    if "policy_integrity" in features:
        controls.append("POLICY_INTEGRITY")
        if s.get("policy_conflict_open", False):
            return _block("POLICY_CONFLICT_OPEN", controls, status="HUMAN_DECISION_REQUIRED")
        if s.get("policy_binding_required", False) and not s.get("policy_digest_match", False):
            return _block("BLOCKED_BY_STALE_POLICY", controls)

    # v2.3 explicitly blocks material open contradictions only for X3.
    if x_level == 3 and s.get("material_contradiction_open", False):
        controls.extend(["WITNESS", "CONTRADICTION_REGISTER"])
        return _block("BLOCKED_BY_VERIFICATION", controls)

    # v2.3 requires an independent basis for critical E3/X3 claims.
    if (e_level == 3 or x_level == 3) and s.get("critical_claim", False):
        controls.append("INDEPENDENCE_GATE")
        if not s.get("independent_basis_present", False):
            return _block("BLOCKED_BY_VERIFICATION", controls)
        if "evidence_origin_graph" in features and s.get("source_independence_required", False) and not s.get("source_independence_established", False):
            controls.append("EVIDENCE_ORIGIN_GRAPH")
            return _block("BLOCKED_BY_CORRELATED_EVIDENCE", controls)

    if "reliance_gate" in features and x_level == 0 and s.get("downstream_reliance_material", False):
        controls.append("RELIANCE_GATE")
        if not s.get("reliance_conditions_satisfied", False):
            return _allow(controls, limited=True, notes=["RELIANCE_RESTRICTIONS_REQUIRED"]) | {"primary_reason": "RELIANCE_RESTRICTIONS_REQUIRED"}

    # Data Gate can apply even at X0 when the response discloses data.
    if s.get("data_gate_required", False):
        controls.append("DATA_GATE")
        if "data_lineage" in features and s.get("derived_data_lineage_required", False) and not s.get("data_lineage_preserved", False):
            return _block("BLOCKED_BY_DATA_LINEAGE", controls)
        if "trace_secrecy" in features and s.get("trace_contains_sensitive_data", False):
            return _block("BLOCKED_BY_TRACE_DISCLOSURE", controls)
        data_status = s.get("data_status", "NOT_REQUIRED")
        if data_status == "DENY":
            return _block("BLOCKED_BY_DATA", controls)
        if data_status == "ALLOW_WITH_REDACTION":
            if not s.get("redaction_applied", False):
                return _block("BLOCKED_BY_DATA", controls)

    # Pure advisory output has no Authority/Capability Action Gate in v2.3.
    if x_level == 0:
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

    limited = s.get("policy_status") == "ALLOW_WITH_LIMITS" or capability == "DEGRADED"
    return _allow(controls, limited=limited)
