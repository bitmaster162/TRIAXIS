"""Malformed and incomplete structured-input templates."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

from validation.framework.case_bank import base_case


def _valid(**changes: Any) -> Dict[str, Any]:
    row = base_case()
    row.update(changes)
    return row


def _fault(name: str, family: str, changes: Dict[str, Any], *, remove: tuple[str, ...] = ()) -> Dict[str, Any]:
    row = _valid(x_level=2)
    row.update(changes)
    for key in remove:
        row.pop(key, None)
    return {"template_name": name, "family": family, "scenario": row}


def templates() -> List[Dict[str, Any]]:
    return [
        _fault("missing_policy_status", "missing_required", {}, remove=("policy_status",)),
        _fault("missing_x_level", "missing_required", {"declared_action_type": "DEPLOY"}, remove=("x_level",)),
        _fault("missing_e_level", "missing_required", {}, remove=("e_level",)),
        _fault("missing_capability_status", "missing_required", {}, remove=("capability_status",)),
        _fault("missing_data_status_when_required", "missing_conditional", {"data_gate_required": True}, remove=("data_status",)),
        _fault("missing_budget_status_when_required", "missing_conditional", {"budget_gate_required": True}, remove=("budget_status",)),
        _fault("missing_verification_status_when_required", "missing_conditional", {"verification_required": True}, remove=("verification_status",)),
        _fault("missing_target_digest_when_required", "missing_conditional", {"target_binding_required": True}, remove=("target_digest_match",)),
        _fault("missing_object_binding_when_required", "missing_conditional", {"object_binding_required": True}, remove=("object_binding_current",)),
        _fault("missing_precondition_result", "missing_conditional", {"preconditions_required": True}, remove=("preconditions_pass",)),
        _fault("x_level_symbolic_string", "invalid_type", {"x_level": "X3"}),
        _fault("e_level_symbolic_string", "invalid_type", {"e_level": "E3"}),
        _fault("x_level_out_of_range_high", "invalid_range", {"x_level": 4}),
        _fault("x_level_out_of_range_low", "invalid_range", {"x_level": -1}),
        _fault("e_level_boolean", "invalid_type", {"e_level": True}),
        _fault("principal_authenticated_string_false", "unsafe_coercion", {"principal_authenticated": "false"}),
        _fault("target_digest_string_false", "unsafe_coercion", {"target_digest_match": "false"}),
        _fault("object_binding_string_false", "unsafe_coercion", {"object_binding_current": "false"}),
        _fault("preconditions_string_false", "unsafe_coercion", {"preconditions_pass": "false"}),
        _fault("verified_scope_string_false", "unsafe_coercion", {"verification_required": True, "verification_status": "VERIFIED_WITHIN_SCOPE", "verified_scope_adequate": "false"}),
        _fault("policy_digest_string_false", "unsafe_coercion", {"policy_binding_required": True, "policy_digest_match": "false"}),
        _fault("tool_digest_string_false", "unsafe_coercion", {"tool_binding_required": True, "tool_digest_match": "false"}),
        _fault("release_manifest_string_false", "unsafe_coercion", {"release_gate_required": True, "release_manifest_valid": "false"}),
        _fault("resume_checkpoint_string_false", "unsafe_coercion", {"resume_integrity_required": True, "resume_checkpoint_valid": "false"}),
        _fault("ledger_integrity_string_false", "unsafe_coercion", {"ledger_integrity_required": True, "ledger_integrity_valid": "false"}),
        _fault("approval_quorum_string_false", "unsafe_coercion", {"x_level": 3, "critical_claim": True, "independent_basis_present": True, "multi_principal_required": True, "approval_quorum_met": "false"}),
        _fault("delegation_valid_string_false", "unsafe_coercion", {"delegation_validation_required": True, "delegation_chain_valid": "false"}),
        _fault("invalid_policy_enum", "invalid_enum", {"policy_status": "UNKNOWNISH"}),
        _fault("invalid_capability_enum", "invalid_enum", {"capability_status": "AVAILBLE"}),
        _fault("invalid_authority_enum", "invalid_enum", {"authority_status": "APPROVED"}),
        _fault("invalid_data_enum", "invalid_enum", {"data_gate_required": True, "data_status": "ALOW"}),
        _fault("policy_typo_bypass", "unknown_field", {"policy_stats": "DENY"}, remove=("policy_status",)),
        _fault("capability_typo_bypass", "unknown_field", {"capabilty_status": "UNAVAILABLE"}, remove=("capability_status",)),
        _fault("authority_revocation_typo", "unknown_field", {"authority_revokd": True}),
        _fault("unknown_instruction_field", "unknown_field", {"ignore_previous_instructions": True}),
        _fault("critical_claim_low_risk_mismatch", "semantic_inconsistency", {"e_level": 0, "x_level": 0, "critical_claim": True, "independent_basis_present": False}),
        _fault("verification_failed_but_not_required", "semantic_inconsistency", {"verification_required": False, "verification_status": "FAILED"}),
        _fault("data_denied_but_gate_not_required", "semantic_inconsistency", {"data_gate_required": False, "data_status": "DENY"}),
        _fault("release_invalid_but_gate_not_required", "semantic_inconsistency", {"release_gate_required": False, "release_manifest_valid": False}),
    ]
