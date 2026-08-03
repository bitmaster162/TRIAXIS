"""Parametric case bank for commit-sealed holdout generation."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


def base_case() -> Dict[str, Any]:
    return {
        "e_level": 1,
        "x_level": 1,
        "policy_status": "ALLOW",
        "hard_prohibition": False,
        "authority_status": "VALID",
        "principal_authenticated": True,
        "authority_revoked": False,
        "authority_expired": False,
        "authority_scope_match": True,
        "target_digest_match": True,
        "capability_status": "AVAILABLE",
        "degraded_capability_adequate": False,
        "data_gate_required": False,
        "data_status": "NOT_REQUIRED",
        "redaction_applied": False,
        "budget_gate_required": False,
        "budget_status": "NOT_REQUIRED",
        "object_binding_current": True,
        "preconditions_pass": True,
        "verification_required": False,
        "verification_status": "NOT_APPLICABLE",
        "verified_scope_adequate": True,
        "possible_commit_timeout": False,
        "critical_claim": False,
        "independent_basis_present": False,
        "material_contradiction_open": False,
        "contradiction_material_to_decision": True,
    }


def _case(name: str, family: str, changes: Dict[str, Any]) -> Dict[str, Any]:
    item = base_case()
    item.update(changes)
    item["template_name"] = name
    item["family"] = family
    return item


def templates() -> List[Dict[str, Any]]:
    return [
        # Legacy controls expected to pass under v2.3.
        _case("revoked_authority", "legacy", {"x_level": 2, "authority_revoked": True}),
        _case("scope_mismatch", "legacy", {"x_level": 2, "authority_scope_match": False}),
        _case("target_digest_changed", "legacy", {"x_level": 3, "target_digest_match": False, "critical_claim": True, "independent_basis_present": True}),
        _case("capability_missing", "legacy", {"x_level": 2, "capability_status": "UNAVAILABLE"}),
        _case("budget_undefined", "legacy", {"x_level": 2, "budget_gate_required": True, "budget_status": "UNDEFINED"}),
        _case("data_denied", "legacy", {"x_level": 2, "data_gate_required": True, "data_status": "DENY"}),
        _case("verification_failed", "legacy", {"x_level": 2, "verification_required": True, "verification_status": "FAILED"}),
        _case("unknown_outcome", "legacy", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "possible_commit_timeout": True}),
        _case("exact_bounded_action", "legacy", {"x_level": 2, "verification_required": True, "verification_status": "VERIFIED_WITHIN_SCOPE"}),
        _case("degraded_but_adequate", "legacy", {"x_level": 2, "capability_status": "DEGRADED", "degraded_capability_adequate": True}),
        # New holdout families not explicitly closed by v2.3.
        _case("open_policy_conflict", "policy_integrity", {"x_level": 2, "policy_conflict_open": True}),
        _case("stale_policy_binding", "policy_integrity", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "policy_binding_required": True, "policy_digest_match": False}),
        _case("approval_quorum_missing", "authority_composition", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "multi_principal_required": True, "approval_quorum_met": False}),
        _case("delegation_scope_escalation", "authority_composition", {"x_level": 2, "delegation_validation_required": True, "delegation_chain_valid": False}),
        _case("tool_version_changed", "toolchain_integrity", {"x_level": 2, "tool_binding_required": True, "tool_digest_match": False}),
        _case("untrusted_capability_receipt", "toolchain_integrity", {"x_level": 2, "capability_evidence_trust_required": True, "capability_evidence_trusted": False}),
        _case("correlated_independent_sources", "evidence_independence", {"e_level": 3, "x_level": 0, "critical_claim": True, "independent_basis_present": True, "source_independence_required": True, "source_independence_established": False}),
        _case("material_downstream_reliance", "reliance", {"e_level": 3, "x_level": 0, "critical_claim": False, "downstream_reliance_material": True, "reliance_conditions_satisfied": False}),
        _case("derived_confidential_data_loses_label", "data_lineage", {"x_level": 0, "data_gate_required": True, "data_status": "ALLOW", "derived_data_lineage_required": True, "data_lineage_preserved": False}),
        _case("secret_in_control_trace", "data_lineage", {"x_level": 1, "data_gate_required": True, "data_status": "ALLOW", "trace_contains_sensitive_data": True}),
        _case("concurrent_budget_oversubscription", "concurrency", {"x_level": 2, "budget_gate_required": True, "budget_status": "WITHIN_LIMIT", "concurrent_budget_reservation": True, "atomic_budget_reservation": False}),
        _case("check_then_commit_race", "concurrency", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "transactional_commit_required": True, "atomic_compare_and_commit": False}),
        _case("idempotency_key_payload_collision", "idempotency", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "idempotency_payload_binding_required": True, "idempotency_payload_match": False}),
        _case("resume_from_untrusted_checkpoint", "continuity", {"x_level": 2, "resume_integrity_required": True, "resume_checkpoint_valid": False}),
        _case("tampered_execution_ledger", "continuity", {"x_level": 2, "ledger_integrity_required": True, "ledger_integrity_valid": False}),
        _case("release_manifest_mismatch", "release_integrity", {"x_level": 1, "release_gate_required": True, "release_manifest_valid": False}),
        # Positive controls for the new families.
        _case("valid_policy_binding", "positive_new", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "policy_binding_required": True, "policy_digest_match": True}),
        _case("approval_quorum_met", "positive_new", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "multi_principal_required": True, "approval_quorum_met": True}),
        _case("tool_binding_current", "positive_new", {"x_level": 2, "tool_binding_required": True, "tool_digest_match": True}),
        _case("atomic_budget_reservation", "positive_new", {"x_level": 2, "budget_gate_required": True, "budget_status": "WITHIN_LIMIT", "concurrent_budget_reservation": True, "atomic_budget_reservation": True}),
        _case("valid_resume_checkpoint", "positive_new", {"x_level": 2, "resume_integrity_required": True, "resume_checkpoint_valid": True}),
        _case("release_manifest_valid", "positive_new", {"x_level": 1, "release_gate_required": True, "release_manifest_valid": True}),
    ]
