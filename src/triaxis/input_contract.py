"""Strict fail-closed input contract for TRIAXIS deterministic scenarios.

The contract validates structured scenarios before any governance gate executes.
It deliberately rejects unsafe coercion, missing required fields, unknown fields,
invalid enum values, and selected semantic contradictions. Natural-language
extraction into this structure is outside this module's scope.
"""

from __future__ import annotations

from typing import Any, Mapping

INPUT_CONTRACT_ID = "TRIAXIS_STRUCTURED_SCENARIO_v1"

_REQUIRED_FIELDS = frozenset(
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
    "declared_action_type": frozenset(
        {
            "ANALYZE",
            "READ",
            "WRITE",
            "EXECUTE",
            "SEND",
            "PUBLISH",
            "DEPLOY",
            "DELETE",
            "SPEND",
            "TRADE",
            "MODIFY_ACCESS",
            "HANDLE_SECRETS",
        }
    ),
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
    set(_REQUIRED_FIELDS)
    | set(_BOOL_FIELDS)
    | set(_ENUM_FIELDS)
    | set(_STRING_FIELDS)
    | set(_INT_FIELDS)
    | {"extensions"}
)

# A dependent evidence field is mandatory whenever its activation flag is true.
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

# For these optional gates, evidence without an active gate is ambiguous and
# therefore rejected instead of silently ignored.
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


def validate_scenario(scenario: Any) -> list[dict[str, str]]:
    """Return deterministic validation errors; an empty list means valid.

    Values are never coerced. In particular, ``bool`` is rejected for integer
    fields and strings such as ``"false"`` are rejected for boolean fields.
    """

    if not isinstance(scenario, Mapping):
        return [_error("invalid_type", "$", "scenario must be an object")]

    s = dict(scenario)
    errors: list[dict[str, str]] = []

    for key in sorted(set(s) - set(_ALLOWED_FIELDS)):
        errors.append(_error("unknown_field", key, "field is not defined by the active input contract"))

    for key in sorted(_REQUIRED_FIELDS - set(s)):
        errors.append(_error("missing_required", key, "required field is missing"))

    # Type checks are strict and occur before all semantic checks.
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

    # Do not run semantic checks on fields whose exact types are already invalid.
    invalid_paths = {item["path"] for item in errors if item["code"] in {"invalid_type", "invalid_enum", "invalid_range"}}

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

    # A false release receipt with an explicitly inactive gate was the observed
    # Q1 bypass; the generic exclusive-dependency rule above closes it.

    # Stable deterministic ordering and de-duplication.
    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in errors:
        unique[(item["code"], item["path"], item["message"])] = item
    return [unique[key] for key in sorted(unique)]


def schema_document() -> dict[str, Any]:
    """Return a machine-readable JSON Schema projection of the contract.

    Cross-field semantic rules remain normative in :func:`validate_scenario`;
    the schema covers field closure, required properties, exact primitive types,
    ranges and enums.
    """

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

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://local.invalid/triaxis/structured-scenario-v1.schema.json",
        "title": "TRIAXIS Structured Scenario Input Contract v1",
        "type": "object",
        "required": sorted(_REQUIRED_FIELDS),
        "properties": properties,
        "additionalProperties": False,
        "$comment": "Cross-field conditional and semantic rules are enforced by triaxis.input_contract.validate_scenario.",
    }


__all__ = ["INPUT_CONTRACT_ID", "schema_document", "validate_scenario"]
