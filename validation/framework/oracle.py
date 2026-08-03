"""Independent validation oracle for commit-sealed TRIAXIS holdouts.

The oracle is intentionally implemented separately from the candidate
projection. It encodes the validation contract used to score structured
scenarios; it is not imported by candidate code.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

Scenario = Mapping[str, Any]
Decision = Dict[str, Any]


def _result(status: str, reason: str) -> Decision:
    return {"status": status, "primary_reason": reason}


def evaluate_oracle(s: Scenario) -> Decision:
    e_level = int(s.get("e_level", 0))
    x_level = int(s.get("x_level", 0))

    if s.get("hard_prohibition", False) or s.get("policy_status") == "DENY":
        return _result("BLOCK", "BLOCKED_BY_POLICY")

    if s.get("policy_conflict_open", False):
        return _result("HUMAN_DECISION_REQUIRED", "POLICY_CONFLICT_OPEN")
    if s.get("policy_binding_required", False) and not s.get("policy_digest_match", False):
        return _result("BLOCK", "BLOCKED_BY_STALE_POLICY")

    if s.get("material_contradiction_open", False) and s.get("contradiction_material_to_decision", True):
        return _result("BLOCK", "BLOCKED_BY_VERIFICATION")

    if s.get("critical_claim", False):
        if not s.get("independent_basis_present", False):
            return _result("BLOCK", "BLOCKED_BY_VERIFICATION")
        if s.get("source_independence_required", False) and not s.get("source_independence_established", False):
            return _result("BLOCK", "BLOCKED_BY_CORRELATED_EVIDENCE")

    if x_level == 0 and s.get("downstream_reliance_material", False):
        if not s.get("reliance_conditions_satisfied", False):
            return _result("ALLOW_WITH_LIMITS", "RELIANCE_RESTRICTIONS_REQUIRED")

    if s.get("data_gate_required", False):
        if s.get("derived_data_lineage_required", False) and not s.get("data_lineage_preserved", False):
            return _result("BLOCK", "BLOCKED_BY_DATA_LINEAGE")
        if s.get("trace_contains_sensitive_data", False):
            return _result("BLOCK", "BLOCKED_BY_TRACE_DISCLOSURE")
        data_status = s.get("data_status", "NOT_REQUIRED")
        if data_status == "DENY":
            return _result("BLOCK", "BLOCKED_BY_DATA")
        if data_status == "ALLOW_WITH_REDACTION" and not s.get("redaction_applied", False):
            return _result("BLOCK", "BLOCKED_BY_DATA")

    if s.get("release_gate_required", False) and not s.get("release_manifest_valid", False):
        return _result("BLOCK", "BLOCKED_BY_RELEASE_INTEGRITY")

    if x_level == 0:
        return _result("ALLOW", "CONDITIONS_SATISFIED")

    if s.get("authority_status") != "VALID":
        if s.get("authority_status") == "AMBIGUOUS":
            return _result("HUMAN_DECISION_REQUIRED", "HUMAN_DECISION_REQUIRED")
        return _result("BLOCK", "BLOCKED_BY_AUTHORITY")
    if not s.get("principal_authenticated", False):
        return _result("BLOCK", "BLOCKED_BY_AUTHORITY")
    if s.get("authority_revoked", False) or s.get("authority_expired", False):
        return _result("BLOCK", "BLOCKED_BY_AUTHORITY")
    if not s.get("authority_scope_match", True):
        return _result("BLOCK", "BLOCKED_BY_AUTHORITY")
    if s.get("multi_principal_required", False) and not s.get("approval_quorum_met", False):
        return _result("BLOCK", "BLOCKED_BY_AUTHORITY_QUORUM")
    if s.get("delegation_validation_required", False) and not s.get("delegation_chain_valid", False):
        return _result("BLOCK", "BLOCKED_BY_DELEGATION")
    if not s.get("target_digest_match", True):
        return _result("BLOCK", "BLOCKED_BY_STALE_BINDING")

    capability = s.get("capability_status", "AVAILABLE")
    if capability in {"UNAVAILABLE", "UNKNOWN"}:
        return _result("BLOCK", "BLOCKED_BY_CAPABILITY")
    if capability == "DEGRADED" and not s.get("degraded_capability_adequate", False):
        return _result("BLOCK", "BLOCKED_BY_CAPABILITY")
    if s.get("tool_binding_required", False) and not s.get("tool_digest_match", False):
        return _result("BLOCK", "BLOCKED_BY_TOOLCHAIN_INTEGRITY")
    if s.get("capability_evidence_trust_required", False) and not s.get("capability_evidence_trusted", False):
        return _result("BLOCK", "BLOCKED_BY_CAPABILITY_EVIDENCE")

    if s.get("budget_gate_required", False):
        if s.get("budget_status") not in {"WITHIN_LIMIT", "NOT_REQUIRED"}:
            return _result("BLOCK", "BLOCKED_BY_BUDGET")
        if s.get("concurrent_budget_reservation", False) and not s.get("atomic_budget_reservation", False):
            return _result("BLOCK", "BLOCKED_BY_BUDGET_RACE")

    if not s.get("object_binding_current", True):
        return _result("BLOCK", "BLOCKED_BY_STALE_BINDING")
    if s.get("transactional_commit_required", False) and not s.get("atomic_compare_and_commit", False):
        return _result("BLOCK", "BLOCKED_BY_COMMIT_RACE")

    if not s.get("preconditions_pass", True):
        return _result("BLOCK", "BLOCKED_BY_PRECONDITION")

    if s.get("verification_required", False):
        if s.get("verification_status") != "VERIFIED_WITHIN_SCOPE" or not s.get("verified_scope_adequate", True):
            return _result("BLOCK", "BLOCKED_BY_VERIFICATION")

    if s.get("idempotency_payload_binding_required", False) and not s.get("idempotency_payload_match", False):
        return _result("BLOCK", "BLOCKED_BY_IDEMPOTENCY_COLLISION")

    if s.get("resume_integrity_required", False) and not s.get("resume_checkpoint_valid", False):
        return _result("BLOCK", "BLOCKED_BY_RESUME_INTEGRITY")

    if s.get("ledger_integrity_required", False) and not s.get("ledger_integrity_valid", False):
        return _result("BLOCK", "BLOCKED_BY_LEDGER_INTEGRITY")

    if s.get("possible_commit_timeout", False):
        return _result("HOLD", "UNKNOWN_OUTCOME")

    limited = s.get("policy_status") == "ALLOW_WITH_LIMITS" or capability == "DEGRADED"
    return _result("ALLOW_WITH_LIMITS" if limited else "ALLOW", "CONDITIONS_SATISFIED")
