"""Versioned, strict, fail-closed input contracts for TRIAXIS scenarios.

The contracts validate structured scenarios before any governance gate executes.
They reject unsafe coercion, missing required fields, unknown fields, invalid enum
values, and selected semantic contradictions. Natural-language extraction into
this structure is handled separately by :mod:`triaxis.semantic_ingress`.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

INPUT_CONTRACT_V1_ID = "TRIAXIS_STRUCTURED_SCENARIO_v1"
INPUT_CONTRACT_V2_ID = "TRIAXIS_STRUCTURED_SCENARIO_v2"
INPUT_CONTRACT_ID = INPUT_CONTRACT_V2_ID

# Conservative lower bounds frozen by Routing Semantics Protocol v1.0.  The
# mapping is intentionally deterministic; project-specific controls may raise a
# route, but no caller may route an action below this floor.
ACTION_MINIMUM_X: dict[str, int] = {
    "ANALYZE": 0,
    "READ": 0,
    "WRITE": 1,
    "EXECUTE": 1,
    "DELETE": 1,
    "SEND": 2,
    "PUBLISH": 2,
    "DEPLOY": 2,
    "SPEND": 3,
    "TRADE": 3,
    "MODIFY_ACCESS": 3,
    "HANDLE_SECRETS": 3,
}

_REQUIRED_FIELDS_V1 = frozenset(
    {
        "e_level",
        "x_level",
        "policy_status",
        "hard_prohibition",
        "authority_status",
        "principal_authenticated",
        "authority_revoked",
        "authority_expired",
        "authority_scope_match",
        "target_digest_match",
        "capability_status",
        "degraded_capability_adequate",
        "data_gate_required",
        "data_status",
        "redaction_applied",
        "budget_gate_required",
        "budget_status",
        "object_binding_current",
        "preconditions_pass",
        "verification_required",
        "verification_status",
        "verified_scope_adequate",
        "possible_commit_timeout",
        "critical_claim",
        "independent_basis_present",
        "material_contradiction_open",
        "contradiction_material_to_decision",
    }
)
_REQUIRED_FIELDS_V2 = _REQUIRED_FIELDS_V1 | frozenset({"declared_action_type"})

_BOOL_FIELDS = frozenset(
    {
        # Required core fields.
        "hard_prohibition",
        "principal_authenticated",
        "authority_revoked",
        "authority_expired",
        "authority_scope_match",
        "target_digest_match",
        "degraded_capability_adequate",
        "data_gate_required",
        "redaction_applied",
        "budget_gate_required",
        "object_binding_current",
        "preconditions_pass",
        "verification_required",
        "verified_scope_adequate",
        "possible_commit_timeout",
        "critical_claim",
        "independent_basis_present",
        "material_contradiction_open",
        "contradiction_material_to_decision",
        # Optional activation and evidence fields.
        "policy_conflict_open",
        "policy_binding_required",
        "policy_digest_match",
        "multi_principal_required",
        "approval_quorum_met",
        "delegation_validation_required",
        "delegation_chain_valid",
        "target_binding_required",
        "tool_binding_required",
        "tool_digest_match",
        "capability_evidence_trust_required",
        "capability_evidence_trusted",
        "uses_tool_output",
        "derived_data_lineage_required",
        "data_lineage_preserved",
        "trace_contains_sensitive_data",
        "release_gate_required",
        "release_manifest_valid",
        "concurrent_budget_reservation",
        "atomic_budget_reservation",
        "transactional_commit_required",
        "atomic_compare_and_commit",
        "idempotency_payload_binding_required",
        "idempotency_payload_match",
        "resume_integrity_required",
        "resume_checkpoint_valid",
        "resumed_state_used",
        "ledger_integrity_required",
        "ledger_integrity_valid",
        "ledger_state_used",
        "source_independence_required",
        "source_independence_established",
        "downstream_reliance_material",
        "reliance_conditions_satisfied",
        "object_binding_required",
        "preconditions_required",
        # Non-normative validation metadata.
        "soft_preference_present",
    }
)

_ENUM_FIELDS: dict[str, frozenset[str]] = {
    "policy_status": frozenset({"ALLOW", "ALLOW_WITH_LIMITS", "DENY"}),
    "authority_status": frozenset({"VALID", "INVALID", "AMBIGUOUS", "NOT_REQUIRED"}),
    "capability_status": frozenset({"AVAILABLE", "DEGRADED", "UNAVAILABLE", "UNKNOWN", "NOT_REQUIRED"}),
    "data_status": frozenset({"ALLOW", "ALLOW_WITH_REDACTION", "DENY", "NOT_REQUIRED"}),
    "budget_status": frozenset({"WITHIN_LIMIT", "EXHAUSTED", "UNDEFINED", "NOT_REQUIRED"}),
    "verification_status": frozenset(
        {"NOT_RUN", "VERIFIED_WITHIN_SCOPE", "FAILED", "INCONCLUSIVE", "NOT_APPLICABLE"}
    ),
    "declared_action_type": frozenset(ACTION_MINIMUM_X),
}

_STRING_FIELDS = frozenset(
    {
        "case_id",
        "template_name",
        "family",
        "target_alias",
        "environment_alias",
        "prose_hint",
    }
)
_INT_FIELDS = frozenset({"e_level", "x_level", "nonce"})

_ALLOWED_FIELDS = frozenset(
    set(_REQUIRED_FIELDS_V2)
    | set(_BOOL_FIELDS)
    | set(_ENUM_FIELDS)
    | set(_STRING_FIELDS)
    | set(_INT_FIELDS)
    | {"extensions"}
)

_CONDITIONAL_REQUIRED: tuple[tuple[str, str], ...] = (
    ("policy_binding_required", "policy_digest_match"),
    ("multi_principal_required", "approval_quorum_met"),
    ("delegation_validation_required", "delegation_chain_valid"),
    ("target_binding_required", "target_digest_match"),
    ("object_binding_required", "object_binding_current"),
    ("preconditions_required", "preconditions_pass"),
    ("tool_binding_required", "tool_digest_match"),
    ("capability_evidence_trust_required", "capability_evidence_trusted"),
    ("derived_data_lineage_required", "data_lineage_preserved"),
    ("release_gate_required", "release_manifest_valid"),
    ("concurrent_budget_reservation", "atomic_budget_reservation"),
    ("transactional_commit_required", "atomic_compare_and_commit"),
    ("idempotency_payload_binding_required", "idempotency_payload_match"),
    ("resume_integrity_required", "resume_checkpoint_valid"),
    ("ledger_integrity_required", "ledger_integrity_valid"),
    ("source_independence_required", "source_independence_established"),
)

_EXCLUSIVE_DEPENDENCIES: tuple[tuple[str, str], ...] = (
    ("release_gate_required", "release_manifest_valid"),
    ("policy_binding_required", "policy_digest_match"),
    ("multi_principal_required", "approval_quorum_met"),
    ("delegation_validation_required", "delegation_chain_valid"),
    ("tool_binding_required", "tool_digest_match"),
    ("capability_evidence_trust_required", "capability_evidence_trusted"),
    ("derived_data_lineage_required", "data_lineage_preserved"),
    ("concurrent_budget_reservation", "atomic_budget_reservation"),
    ("transactional_commit_required", "atomic_compare_and_commit"),
    ("idempotency_payload_binding_required", "idempotency_payload_match"),
    ("resume_integrity_required", "resume_checkpoint_valid"),
    ("ledger_integrity_required", "ledger_integrity_valid"),
    ("source_independence_required", "source_independence_established"),
)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _required_fields(contract_id: str) -> frozenset[str]:
    if contract_id == INPUT_CONTRACT_V1_ID:
        return _REQUIRED_FIELDS_V1
    if contract_id == INPUT_CONTRACT_V2_ID:
        return _REQUIRED_FIELDS_V2
    raise ValueError(f"unsupported TRIAXIS input contract: {contract_id}")


def validate_scenario(
    scenario: Any,
    contract_id: str = INPUT_CONTRACT_ID,
) -> list[dict[str, str]]:
    """Return deterministic validation errors; an empty list means valid.

    Values are never coerced. In particular, ``bool`` is rejected for integer
    fields and strings such as ``"false"`` are rejected for boolean fields.
    """

    required_fields = _required_fields(contract_id)
    if not isinstance(scenario, Mapping):
        return [_error("invalid_type", "$", "scenario must be an object")]

    s = dict(scenario)
    errors: list[dict[str, str]] = []

    for key in sorted(set(s) - set(_ALLOWED_FIELDS)):
        errors.append(_error("unknown_field", key, "field is not defined by the active input contract"))
    for key in sorted(required_fields - set(s)):
        errors.append(_error("missing_required", key, "required field is missing"))

    for key in sorted(set(s) & set(_BOOL_FIELDS)):
        if type(s[key]) is not bool:  # noqa: E721 - exact type is intentional
            errors.append(_error("invalid_type", key, "expected boolean without coercion"))

    for key in sorted(set(s) & set(_INT_FIELDS)):
        value = s[key]
        if type(value) is not int:  # bool is intentionally rejected
            errors.append(_error("invalid_type", key, "expected integer without coercion"))
        elif key in {"e_level", "x_level"} and not 0 <= value <= 3:
            errors.append(_error("invalid_range", key, "expected integer in range 0..3"))
        elif key == "nonce" and value < 0:
            errors.append(_error("invalid_range", key, "nonce must be non-negative"))

    for key in sorted(set(s) & set(_STRING_FIELDS)):
        if type(s[key]) is not str:  # noqa: E721
            errors.append(_error("invalid_type", key, "expected string"))

    for key, allowed in sorted(_ENUM_FIELDS.items()):
        if key not in s:
            continue
        value = s[key]
        if type(value) is not str:  # noqa: E721
            errors.append(_error("invalid_type", key, "expected enum string"))
        elif value not in allowed:
            errors.append(_error("invalid_enum", key, f"unsupported value; expected one of {sorted(allowed)}"))

    if "extensions" in s and not isinstance(s["extensions"], Mapping):
        errors.append(_error("invalid_type", "extensions", "extensions must be an object"))

    invalid_paths = {
        item["path"]
        for item in errors
        if item["code"] in {"invalid_type", "invalid_enum", "invalid_range"}
    }

    for trigger, dependent in _CONDITIONAL_REQUIRED:
        if s.get(trigger) is True and dependent not in s:
            errors.append(_error("missing_conditional", dependent, f"required when {trigger}=true"))

    if "data_gate_required" not in invalid_paths and "data_status" not in invalid_paths:
        if s.get("data_gate_required") is True and s.get("data_status") == "NOT_REQUIRED":
            errors.append(_error("semantic_inconsistency", "data_status", "data gate is active but status is NOT_REQUIRED"))
        if s.get("data_gate_required") is False and s.get("data_status") != "NOT_REQUIRED":
            errors.append(_error("semantic_inconsistency", "data_status", "data gate is inactive but status is material"))
    if "budget_gate_required" not in invalid_paths and "budget_status" not in invalid_paths:
        if s.get("budget_gate_required") is True and s.get("budget_status") == "NOT_REQUIRED":
            errors.append(_error("semantic_inconsistency", "budget_status", "budget gate is active but status is NOT_REQUIRED"))
        if s.get("budget_gate_required") is False and s.get("budget_status") != "NOT_REQUIRED":
            errors.append(_error("semantic_inconsistency", "budget_status", "budget gate is inactive but status is material"))

    if "verification_required" not in invalid_paths and "verification_status" not in invalid_paths:
        if s.get("verification_required") is True and s.get("verification_status") == "NOT_APPLICABLE":
            errors.append(_error("semantic_inconsistency", "verification_status", "verification is required but marked NOT_APPLICABLE"))
        if s.get("verification_required") is False and s.get("verification_status") not in {"NOT_RUN", "NOT_APPLICABLE"}:
            errors.append(_error("semantic_inconsistency", "verification_status", "verification result supplied while gate is inactive"))

    if not ({"e_level", "x_level", "critical_claim"} & invalid_paths):
        if s.get("critical_claim") is True and max(s.get("e_level", -1), s.get("x_level", -1)) < 3:
            errors.append(_error("semantic_inconsistency", "critical_claim", "critical claim requires E3 or X3"))

    if "x_level" not in invalid_paths:
        x_level = s.get("x_level")
        if isinstance(x_level, int) and not isinstance(x_level, bool):
            if x_level > 0 and s.get("authority_status") == "NOT_REQUIRED":
                errors.append(_error("semantic_inconsistency", "authority_status", "authority cannot be NOT_REQUIRED when X>0"))
            if x_level > 0 and s.get("capability_status") == "NOT_REQUIRED":
                errors.append(_error("semantic_inconsistency", "capability_status", "capability cannot be NOT_REQUIRED when X>0"))
            if x_level == 0 and s.get("possible_commit_timeout") is True:
                errors.append(_error("semantic_inconsistency", "possible_commit_timeout", "commit timeout is incompatible with X0"))

    if contract_id == INPUT_CONTRACT_V2_ID and not ({"declared_action_type", "x_level"} & invalid_paths):
        action = s.get("declared_action_type")
        x_level = s.get("x_level")
        if action in ACTION_MINIMUM_X and type(x_level) is int and x_level < ACTION_MINIMUM_X[action]:
            errors.append(
                _error(
                    "risk_underclassification",
                    "x_level",
                    f"{action} requires X{ACTION_MINIMUM_X[action]} or higher",
                )
            )

    if s.get("data_gate_required") is False:
        if s.get("derived_data_lineage_required") is True:
            errors.append(_error("semantic_inconsistency", "derived_data_lineage_required", "data lineage requires an active data gate"))
        if s.get("trace_contains_sensitive_data") is True:
            errors.append(_error("semantic_inconsistency", "trace_contains_sensitive_data", "sensitive trace requires an active data gate"))

    if s.get("budget_gate_required") is False and s.get("concurrent_budget_reservation") is True:
        errors.append(_error("semantic_inconsistency", "concurrent_budget_reservation", "budget concurrency requires an active budget gate"))

    if s.get("x_level") == 0:
        if s.get("tool_binding_required") is True and s.get("uses_tool_output") is not True:
            errors.append(_error("semantic_inconsistency", "tool_binding_required", "X0 tool integrity requires a declared tool-output dependency"))
        if s.get("capability_evidence_trust_required") is True and s.get("uses_tool_output") is not True:
            errors.append(_error("semantic_inconsistency", "capability_evidence_trust_required", "X0 capability evidence requires a declared tool-output dependency"))
        if s.get("resume_integrity_required") is True and s.get("resumed_state_used") is not True:
            errors.append(_error("semantic_inconsistency", "resume_integrity_required", "X0 resume integrity requires a resumed-state dependency"))
        if s.get("ledger_integrity_required") is True and s.get("ledger_state_used") is not True:
            errors.append(_error("semantic_inconsistency", "ledger_integrity_required", "X0 ledger integrity requires a ledger-state dependency"))

    for trigger, dependent in _EXCLUSIVE_DEPENDENCIES:
        if dependent in s and s.get(trigger) is not True:
            errors.append(_error("semantic_inconsistency", dependent, f"field is present while {trigger} is not true"))

    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in errors:
        unique[(item["code"], item["path"], item["message"])] = item
    return [unique[key] for key in sorted(unique)]


def schema_document(contract_id: str = INPUT_CONTRACT_ID) -> dict[str, Any]:
    """Return a machine-readable JSON Schema projection of a contract."""

    required_fields = _required_fields(contract_id)
    properties: dict[str, Any] = {}
    for key in sorted(_BOOL_FIELDS):
        properties[key] = {"type": "boolean"}
    for key in sorted(_STRING_FIELDS):
        properties[key] = {"type": "string"}
    for key in sorted(_INT_FIELDS):
        if key in {"e_level", "x_level"}:
            properties[key] = {"type": "integer", "minimum": 0, "maximum": 3}
        else:
            properties[key] = {"type": "integer", "minimum": 0}
    for key, values in sorted(_ENUM_FIELDS.items()):
        properties[key] = {"type": "string", "enum": sorted(values)}
    properties["extensions"] = {"type": "object"}

    version = "v1" if contract_id == INPUT_CONTRACT_V1_ID else "v2"
    comment = (
        "Cross-field conditional and semantic rules are enforced by "
        "triaxis.input_contract.validate_scenario."
        if contract_id == INPUT_CONTRACT_V1_ID
        else "Cross-field conditional, semantic, and action-risk rules are enforced by "
        "triaxis.input_contract.validate_scenario."
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://local.invalid/triaxis/structured-scenario-{version}.schema.json",
        "title": f"TRIAXIS Structured Scenario Input Contract {version}",
        "type": "object",
        "required": sorted(required_fields),
        "properties": properties,
        "additionalProperties": False,
        "$comment": comment,
    }


def validate_scenario_v1(scenario: Any) -> list[dict[str, str]]:
    return validate_scenario(scenario, INPUT_CONTRACT_V1_ID)


def validate_scenario_v2(scenario: Any) -> list[dict[str, str]]:
    return validate_scenario(scenario, INPUT_CONTRACT_V2_ID)


def schema_document_v1() -> dict[str, Any]:
    return schema_document(INPUT_CONTRACT_V1_ID)


def schema_document_v2() -> dict[str, Any]:
    return schema_document(INPUT_CONTRACT_V2_ID)


def migrate_v1_to_v2(scenario: Mapping[str, Any], declared_action_type: str) -> dict[str, Any]:
    """Return an explicit v2 copy; no action type is inferred from X level."""

    if declared_action_type not in ACTION_MINIMUM_X:
        raise ValueError(f"unsupported declared action type: {declared_action_type}")
    migrated = deepcopy(dict(scenario))
    migrated["declared_action_type"] = declared_action_type
    return migrated


__all__ = [
    "ACTION_MINIMUM_X",
    "INPUT_CONTRACT_ID",
    "INPUT_CONTRACT_V1_ID",
    "INPUT_CONTRACT_V2_ID",
    "migrate_v1_to_v2",
    "schema_document",
    "schema_document_v1",
    "schema_document_v2",
    "validate_scenario",
    "validate_scenario_v1",
    "validate_scenario_v2",
]
