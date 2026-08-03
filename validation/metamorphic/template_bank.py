"""Metamorphic relation templates for a frozen TRIAXIS candidate."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from validation.framework.case_bank import base_case


def _base(**changes: Any) -> Dict[str, Any]:
    item = base_case()
    item.update(changes)
    return item


def _instance(name: str, family: str, base: Dict[str, Any], mutant: Dict[str, Any], relation: str, *, reason: str | None = None) -> Dict[str, Any]:
    return {
        "template_name": name,
        "family": family,
        "base": deepcopy(base),
        "mutant": deepcopy(mutant),
        "relation": relation,
        "expected_reason": reason,
    }


def templates() -> List[Dict[str, Any]]:
    valid_x1 = _base(x_level=1)
    valid_x2 = _base(x_level=2)
    valid_x3 = _base(x_level=3, critical_claim=True, independent_basis_present=True)
    valid_x0 = _base(x_level=0)

    rows: List[Dict[str, Any]] = []

    # Material contradictions must constrain any decision that depends on them.
    for x in range(4):
        base = _base(x_level=x, e_level=2)
        if x == 3:
            base.update(critical_claim=True, independent_basis_present=True)
        mutant = deepcopy(base)
        mutant.update(material_contradiction_open=True, contradiction_material_to_decision=True)
        rows.append(_instance(f"material_contradiction_x{x}", "contradiction_scope", base, mutant, "MUST_BLOCK", reason="BLOCKED_BY_VERIFICATION"))

    # Reliance limits must not mask stronger data/release blockers.
    reliance = _base(
        e_level=3,
        x_level=0,
        downstream_reliance_material=True,
        reliance_conditions_satisfied=False,
    )
    trace_block = deepcopy(reliance)
    trace_block.update(data_gate_required=True, data_status="ALLOW", trace_contains_sensitive_data=True)
    rows.append(_instance("reliance_plus_secret_trace", "blocker_precedence", reliance, trace_block, "MUST_BLOCK", reason="BLOCKED_BY_TRACE_DISCLOSURE"))

    lineage_block = deepcopy(reliance)
    lineage_block.update(data_gate_required=True, data_status="ALLOW", derived_data_lineage_required=True, data_lineage_preserved=False)
    rows.append(_instance("reliance_plus_broken_lineage", "blocker_precedence", reliance, lineage_block, "MUST_BLOCK", reason="BLOCKED_BY_DATA_LINEAGE"))

    release_block = deepcopy(reliance)
    release_block.update(release_gate_required=True, release_manifest_valid=False)
    rows.append(_instance("reliance_plus_invalid_release", "blocker_precedence", reliance, release_block, "MUST_BLOCK", reason="BLOCKED_BY_RELEASE_INTEGRITY"))

    # Integrity dependencies can exist at X0.
    tool_x0 = _base(e_level=2, x_level=0, uses_tool_output=True, tool_binding_required=True, tool_digest_match=False)
    rows.append(_instance("toolchain_mismatch_x0", "cross_axis_integrity", valid_x0, tool_x0, "MUST_BLOCK", reason="BLOCKED_BY_TOOLCHAIN_INTEGRITY"))

    cap_x0 = _base(e_level=2, x_level=0, uses_tool_output=True, capability_evidence_trust_required=True, capability_evidence_trusted=False)
    rows.append(_instance("untrusted_tool_receipt_x0", "cross_axis_integrity", valid_x0, cap_x0, "MUST_BLOCK", reason="BLOCKED_BY_CAPABILITY_EVIDENCE"))

    resume_x0 = _base(e_level=2, x_level=0, resumed_state_used=True, resume_integrity_required=True, resume_checkpoint_valid=False)
    rows.append(_instance("invalid_resume_x0", "cross_axis_integrity", valid_x0, resume_x0, "MUST_BLOCK", reason="BLOCKED_BY_RESUME_INTEGRITY"))

    ledger_x0 = _base(e_level=2, x_level=0, ledger_state_used=True, ledger_integrity_required=True, ledger_integrity_valid=False)
    rows.append(_instance("tampered_ledger_x0", "cross_axis_integrity", valid_x0, ledger_x0, "MUST_BLOCK", reason="BLOCKED_BY_LEDGER_INTEGRITY"))

    # Standard blocker dominance under combinations.
    blockers = [
        ("policy_deny", {"policy_status": "DENY"}, "BLOCKED_BY_POLICY"),
        ("authority_revoked", {"x_level": 2, "authority_revoked": True}, "BLOCKED_BY_AUTHORITY"),
        ("capability_unavailable", {"x_level": 2, "capability_status": "UNAVAILABLE"}, "BLOCKED_BY_CAPABILITY"),
        ("data_denied", {"x_level": 2, "data_gate_required": True, "data_status": "DENY"}, "BLOCKED_BY_DATA"),
        ("budget_exhausted", {"x_level": 2, "budget_gate_required": True, "budget_status": "EXHAUSTED"}, "BLOCKED_BY_BUDGET"),
        ("stale_target", {"x_level": 2, "target_digest_match": False}, "BLOCKED_BY_STALE_BINDING"),
        ("verification_failed", {"x_level": 2, "verification_required": True, "verification_status": "FAILED"}, "BLOCKED_BY_VERIFICATION"),
        ("policy_stale", {"x_level": 2, "policy_binding_required": True, "policy_digest_match": False}, "BLOCKED_BY_STALE_POLICY"),
        ("quorum_missing", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "multi_principal_required": True, "approval_quorum_met": False}, "BLOCKED_BY_AUTHORITY_QUORUM"),
        ("delegation_invalid", {"x_level": 2, "delegation_validation_required": True, "delegation_chain_valid": False}, "BLOCKED_BY_DELEGATION"),
        ("budget_race", {"x_level": 2, "budget_gate_required": True, "budget_status": "WITHIN_LIMIT", "concurrent_budget_reservation": True, "atomic_budget_reservation": False}, "BLOCKED_BY_BUDGET_RACE"),
        ("commit_race", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "transactional_commit_required": True, "atomic_compare_and_commit": False}, "BLOCKED_BY_COMMIT_RACE"),
        ("idempotency_collision", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "idempotency_payload_binding_required": True, "idempotency_payload_match": False}, "BLOCKED_BY_IDEMPOTENCY_COLLISION"),
        ("correlated_evidence", {"e_level": 3, "x_level": 0, "critical_claim": True, "independent_basis_present": True, "source_independence_required": True, "source_independence_established": False}, "BLOCKED_BY_CORRELATED_EVIDENCE"),
        ("invalid_release", {"x_level": 1, "release_gate_required": True, "release_manifest_valid": False}, "BLOCKED_BY_RELEASE_INTEGRITY"),
    ]
    for name, changes, reason in blockers:
        base = valid_x2 if changes.get("x_level", 2) > 0 else valid_x0
        mutant = deepcopy(base)
        mutant.update(changes)
        mutant["soft_preference_present"] = True
        rows.append(_instance(f"dominance_{name}", "hard_blocker_dominance", base, mutant, "MUST_BLOCK", reason=reason))

    # Irrelevant presentation changes must not alter decisions.
    for i in range(6):
        base = deepcopy(valid_x2)
        mutant = deepcopy(base)
        mutant.update(
            nonce=10_000 + i,
            target_alias=f"alias-{i}",
            environment_alias=f"display-{i}",
            prose_hint=f"irrelevant-{i}",
        )
        rows.append(_instance(f"irrelevant_mutation_{i}", "invariance", base, mutant, "SAME_DECISION"))

    # Positive repair/liveness pairs.
    repair_pairs = [
        ("repair_policy_binding", {"x_level": 2, "policy_binding_required": True, "policy_digest_match": False}, {"policy_digest_match": True}),
        ("repair_tool_binding", {"x_level": 2, "tool_binding_required": True, "tool_digest_match": False}, {"tool_digest_match": True}),
        ("repair_quorum", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "multi_principal_required": True, "approval_quorum_met": False}, {"approval_quorum_met": True}),
        ("repair_release", {"x_level": 1, "release_gate_required": True, "release_manifest_valid": False}, {"release_manifest_valid": True}),
    ]
    for name, broken_changes, repair in repair_pairs:
        broken = _base(**broken_changes)
        fixed = deepcopy(broken)
        fixed.update(repair)
        rows.append(_instance(name, "positive_liveness", broken, fixed, "MUTANT_MUST_ALLOW"))

    return rows
