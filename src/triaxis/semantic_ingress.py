"""Fail-closed semantic-ingress contract for TRIAXIS v2.9.

The gate does not claim general natural-language understanding. It validates a
source-bound extraction receipt and applies a conservative explicit control-
surface scanner before structured governance gates trust the embedded nodes.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from copy import deepcopy
from typing import Any, Iterable, Mapping

from .input_contract import ACTION_MINIMUM_X, INPUT_CONTRACT_V2_ID, schema_document

SEMANTIC_INGRESS_CONTRACT_ID = "TRIAXIS_SEMANTIC_INGRESS_v1"

_ROOT_REQUIRED = frozenset(
    {
        "contract_id",
        "source_text",
        "source_sha256",
        "extraction_status",
        "completion_mode",
        "spans",
        "nodes",
    }
)
_ROOT_ALLOWED = _ROOT_REQUIRED

_SPAN_REQUIRED = frozenset({"span_id", "start", "end", "sha256", "role", "modality", "polarity"})
_SPAN_ALLOWED = _SPAN_REQUIRED
_SPAN_ROLES = frozenset({"USER_CONTROL", "QUOTED_DATA", "EXTERNAL_CONTENT", "SYSTEM_CONTEXT"})
_MODALITIES = frozenset({"DIRECTIVE", "PROHIBITION", "CONDITIONAL", "QUESTION", "HYPOTHETICAL", "ASSERTION"})
_POLARITIES = frozenset({"POSITIVE", "NEGATIVE"})
_EXTRACTION_STATUSES = frozenset({"VALID", "NEEDS_CLARIFICATION", "INVALID"})
_COMPLETION_MODES = frozenset({"ALL_OR_NOTHING", "SAFE_PARTIAL", "BEST_EFFORT", "ORDERED_COMMIT"})

_NODE_REQUIRED = frozenset(
    {
        "node_id",
        "action_type",
        "target_status",
        "target_ref",
        "condition_status",
        "authority_basis",
        "authority_receipt_ref",
        "depends_on",
        "support_span_ids",
        "unresolved_fields",
        "scenario",
        "field_bindings",
    }
)
_NODE_ALLOWED = _NODE_REQUIRED
_TARGET_STATUSES = frozenset({"EXACT", "AMBIGUOUS", "MISSING", "NOT_APPLICABLE"})
_CONDITION_STATUSES = frozenset({"SATISFIED", "UNSATISFIED", "UNKNOWN", "NOT_APPLICABLE"})
_AUTHORITY_BASES = frozenset({"CURRENT_USER_DIRECTIVE", "PRIOR_RECEIPT", "NONE", "EXTERNAL_TEXT"})
_ACTION_TYPES = frozenset(ACTION_MINIMUM_X)

_BINDING_REQUIRED = frozenset({"path", "value", "origin", "support_span_ids"})
_BINDING_OPTIONAL = frozenset({"rule_id", "evidence_ref"})
_BINDING_ALLOWED = _BINDING_REQUIRED | _BINDING_OPTIONAL
_BINDING_ORIGINS = frozenset({"USER_TEXT", "DERIVED_RULE", "SYSTEM_CONTEXT", "AUTHORITY_STORE", "TOOL_OUTPUT"})

_SCENARIO_FIELDS = frozenset(schema_document(INPUT_CONTRACT_V2_ID)["properties"])
_SCENARIO_METADATA = frozenset({"template_name", "family", "case_id", "nonce", "prose_hint"})

# Conservative scanner. It is intentionally bounded and only rejects when an
# explicit control surface is visible but absent or contradicted in the receipt.
_ACTION_PATTERNS: dict[str, tuple[str, ...]] = {
    "ANALYZE": (r"\banaly[sz]e\b", r"\bassess\b", r"\binspect\b"),
    "READ": (r"\bread\b", r"\bopen\b", r"\bview\b"),
    "WRITE": (r"\bwrite\b", r"\bdraft\b", r"\bedit\b", r"\bsave\b", r"\bcreate\b"),
    "EXECUTE": (r"\bexecute\b", r"\brun\b"),
    "SEND": (r"\bsend\b", r"\bemail\b", r"\bforward\b", r"\bmessage\b"),
    "PUBLISH": (r"\bpublish\b", r"\bpost\b"),
    "DEPLOY": (r"\bdeploy(?:ment)?\b", r"\broll\s*out\b"),
    "DELETE": (r"\bdelete\b", r"\berase\b", r"\bremove\b"),
    "SPEND": (r"\bspend\b", r"\bpay\b", r"\bpurchase\b"),
    "TRADE": (r"\btrade\b", r"\bbuy\b", r"\bsell\b", r"\border\b"),
    "MODIFY_ACCESS": (r"\bgrant\s+access\b", r"\brevoke\s+access\b", r"\bpermissions?\b"),
    # Russian backstop for the primary operating language.
    "ANALYZE_RU": (r"\bпроанализир", r"\bпроверь"),
    "WRITE_RU": (r"\bнапиш", r"\bсоздай", r"\bсохрани"),
    "SEND_RU": (r"\bотправ",),
    "PUBLISH_RU": (r"\bопублику", r"\bвылож"),
    "DEPLOY_RU": (r"\bзадепло", r"\bразверн"),
    "DELETE_RU": (r"\bудал",),
    "SPEND_RU": (r"\bоплат", r"\bпотрат"),
    "TRADE_RU": (r"\bторгу", r"\bкупи", r"\bпродай"),
}
_RU_ACTION_MAP = {
    "ANALYZE_RU": "ANALYZE",
    "WRITE_RU": "WRITE",
    "SEND_RU": "SEND",
    "PUBLISH_RU": "PUBLISH",
    "DEPLOY_RU": "DEPLOY",
    "DELETE_RU": "DELETE",
    "SPEND_RU": "SPEND",
    "TRADE_RU": "TRADE",
}

_SENSITIVE_PATTERNS = (
    r"\bapi[ _-]?key\b",
    r"\bsecret\b",
    r"\bpassword\b",
    r"\bprivate[ _-]?key\b",
    r"\bseed phrase\b",
    r"\bcredentials?\b",
    r"\bтокен доступа\b",
    r"\bпарол",
    r"\bприватн(?:ый|ого) ключ",
    r"\bсид[- ]?фраз",
)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _same_value(left: Any, right: Any) -> bool:
    return type(left) is type(right) and left == right


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_exact_str(value: Any) -> bool:
    return type(value) is str


def _is_exact_int(value: Any) -> bool:
    return type(value) is int


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(type(item) is str for item in value)


def _detected_actions(text: str) -> set[str]:
    lowered = text.lower()
    detected: set[str] = set()
    for name, patterns in _ACTION_PATTERNS.items():
        if any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in patterns):
            detected.add(_RU_ACTION_MAP.get(name, name))

    # Generic EXECUTE is not a second action when it merely introduces a more
    # specific deployment command ("execute the approved deployment").
    if "DEPLOY" in detected and "EXECUTE" in detected:
        detected.remove("EXECUTE")
    return detected


def _contains_sensitive_surface(text: str) -> bool:
    lowered = text.lower()
    return any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in _SENSITIVE_PATTERNS)


def _has_cycle(graph: dict[str, list[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for dep in graph.get(node, []):
            if visit(dep):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def validate_ingress_record(record: Any) -> list[dict[str, str]]:
    """Return deterministic semantic-ingress errors; empty means valid."""

    if not isinstance(record, Mapping):
        return [_error("invalid_type", "$", "semantic ingress record must be an object")]

    r = dict(record)
    errors: list[dict[str, str]] = []

    for key in sorted(set(r) - set(_ROOT_ALLOWED)):
        errors.append(_error("unknown_field", key, "field is not defined by the semantic ingress contract"))
    for key in sorted(_ROOT_REQUIRED - set(r)):
        errors.append(_error("missing_required", key, "required field is missing"))

    if r.get("contract_id") != SEMANTIC_INGRESS_CONTRACT_ID:
        errors.append(_error("invalid_contract", "contract_id", "unsupported semantic ingress contract"))

    source_text = r.get("source_text")
    if not _is_exact_str(source_text):
        errors.append(_error("invalid_type", "source_text", "expected string"))
        source_text = ""
    source_sha = r.get("source_sha256")
    if not _is_exact_str(source_sha):
        errors.append(_error("invalid_type", "source_sha256", "expected SHA-256 string"))
    elif source_sha != _sha256_text(source_text):
        errors.append(_error("digest_mismatch", "source_sha256", "source digest does not match source_text"))

    extraction_status = r.get("extraction_status")
    if extraction_status not in _EXTRACTION_STATUSES:
        errors.append(_error("invalid_enum", "extraction_status", "unsupported extraction status"))
    completion_mode = r.get("completion_mode")
    if completion_mode not in _COMPLETION_MODES:
        errors.append(_error("invalid_enum", "completion_mode", "unsupported completion mode"))

    spans = r.get("spans")
    if not isinstance(spans, list) or not spans:
        errors.append(_error("invalid_type", "spans", "expected non-empty array"))
        spans = []
    span_by_id: dict[str, dict[str, Any]] = {}
    span_ids: list[str] = []
    for index, raw_span in enumerate(spans):
        path = f"spans[{index}]"
        if not isinstance(raw_span, Mapping):
            errors.append(_error("invalid_type", path, "span must be an object"))
            continue
        span = dict(raw_span)
        for key in sorted(set(span) - set(_SPAN_ALLOWED)):
            errors.append(_error("unknown_field", f"{path}.{key}", "unknown span field"))
        for key in sorted(_SPAN_REQUIRED - set(span)):
            errors.append(_error("missing_required", f"{path}.{key}", "required span field is missing"))

        span_id = span.get("span_id")
        if not _is_exact_str(span_id) or not span_id:
            errors.append(_error("invalid_type", f"{path}.span_id", "expected non-empty string"))
            continue
        span_ids.append(span_id)
        span_by_id.setdefault(span_id, span)

        start, end = span.get("start"), span.get("end")
        if not _is_exact_int(start) or not _is_exact_int(end):
            errors.append(_error("invalid_type", f"{path}.start", "span bounds must be integers"))
        elif not (0 <= start <= end <= len(source_text)):
            errors.append(_error("invalid_range", f"{path}.end", "span bounds are outside source_text"))
        else:
            digest = span.get("sha256")
            if not _is_exact_str(digest) or digest != _sha256_text(source_text[start:end]):
                errors.append(_error("digest_mismatch", f"{path}.sha256", "span digest does not match bound text"))

        if span.get("role") not in _SPAN_ROLES:
            errors.append(_error("invalid_enum", f"{path}.role", "unsupported span role"))
        if span.get("modality") not in _MODALITIES:
            errors.append(_error("invalid_enum", f"{path}.modality", "unsupported modality"))
        if span.get("polarity") not in _POLARITIES:
            errors.append(_error("invalid_enum", f"{path}.polarity", "unsupported polarity"))

    for span_id, count in Counter(span_ids).items():
        if count > 1:
            errors.append(_error("duplicate_id", "spans", f"duplicate span_id {span_id}"))

    nodes = r.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        errors.append(_error("invalid_type", "nodes", "expected non-empty array"))
        nodes = []

    node_ids: list[str] = []
    node_by_id: dict[str, dict[str, Any]] = {}
    graph: dict[str, list[str]] = {}
    represented_actions: set[str] = set()

    for index, raw_node in enumerate(nodes):
        path = f"nodes[{index}]"
        if not isinstance(raw_node, Mapping):
            errors.append(_error("invalid_type", path, "node must be an object"))
            continue
        node = dict(raw_node)
        for key in sorted(set(node) - set(_NODE_ALLOWED)):
            errors.append(_error("unknown_field", f"{path}.{key}", "unknown node field"))
        for key in sorted(_NODE_REQUIRED - set(node)):
            errors.append(_error("missing_required", f"{path}.{key}", "required node field is missing"))

        node_id = node.get("node_id")
        if not _is_exact_str(node_id) or not node_id:
            errors.append(_error("invalid_type", f"{path}.node_id", "expected non-empty string"))
            continue
        node_ids.append(node_id)
        node_by_id.setdefault(node_id, node)

        action = node.get("action_type")
        if action not in _ACTION_TYPES:
            errors.append(_error("invalid_enum", f"{path}.action_type", "unsupported action type"))
        else:
            represented_actions.add(action)

        if node.get("target_status") not in _TARGET_STATUSES:
            errors.append(_error("invalid_enum", f"{path}.target_status", "unsupported target status"))
        if not _is_exact_str(node.get("target_ref")):
            errors.append(_error("invalid_type", f"{path}.target_ref", "expected string"))
        if node.get("condition_status") not in _CONDITION_STATUSES:
            errors.append(_error("invalid_enum", f"{path}.condition_status", "unsupported condition status"))
        if node.get("authority_basis") not in _AUTHORITY_BASES:
            errors.append(_error("invalid_enum", f"{path}.authority_basis", "unsupported authority basis"))
        if not _is_exact_str(node.get("authority_receipt_ref")):
            errors.append(_error("invalid_type", f"{path}.authority_receipt_ref", "expected string"))

        dependencies = node.get("depends_on")
        if not _is_str_list(dependencies):
            errors.append(_error("invalid_type", f"{path}.depends_on", "expected string array"))
            dependencies = []
        graph[node_id] = list(dependencies)

        support_ids = node.get("support_span_ids")
        if not _is_str_list(support_ids) or not support_ids:
            errors.append(_error("missing_support", f"{path}.support_span_ids", "action node requires source support"))
            support_ids = []
        for support_id in support_ids:
            if support_id not in span_by_id:
                errors.append(_error("unknown_reference", f"{path}.support_span_ids", f"unknown span {support_id}"))

        unresolved = node.get("unresolved_fields")
        if not _is_str_list(unresolved):
            errors.append(_error("invalid_type", f"{path}.unresolved_fields", "expected string array"))
            unresolved = []

        scenario = node.get("scenario")
        if not isinstance(scenario, Mapping):
            errors.append(_error("invalid_type", f"{path}.scenario", "scenario must be an object"))
            scenario = {}
        else:
            scenario = dict(scenario)
            if action in _ACTION_TYPES and scenario.get("declared_action_type") != action:
                errors.append(_error("semantic_mismatch", f"{path}.scenario.declared_action_type", "node action and scenario action differ"))
            x_level = scenario.get("x_level")
            if action in ACTION_MINIMUM_X and _is_exact_int(x_level) and x_level < ACTION_MINIMUM_X[action]:
                errors.append(_error("risk_underclassification", f"{path}.scenario.x_level", "action is routed below its conservative X lower bound"))

        bindings = node.get("field_bindings")
        if not isinstance(bindings, list) or not bindings:
            errors.append(_error("missing_provenance", f"{path}.field_bindings", "scenario fields require provenance bindings"))
            bindings = []
        binding_paths: list[str] = []
        authority_binding: dict[str, Any] | None = None
        for binding_index, raw_binding in enumerate(bindings):
            binding_path = f"{path}.field_bindings[{binding_index}]"
            if not isinstance(raw_binding, Mapping):
                errors.append(_error("invalid_type", binding_path, "binding must be an object"))
                continue
            binding = dict(raw_binding)
            for key in sorted(set(binding) - set(_BINDING_ALLOWED)):
                errors.append(_error("unknown_field", f"{binding_path}.{key}", "unknown binding field"))
            for key in sorted(_BINDING_REQUIRED - set(binding)):
                errors.append(_error("missing_required", f"{binding_path}.{key}", "required binding field is missing"))

            field_path = binding.get("path")
            if not _is_exact_str(field_path) or field_path not in _SCENARIO_FIELDS:
                errors.append(_error("unknown_path", f"{binding_path}.path", "binding path is not a scenario field"))
                continue
            binding_paths.append(field_path)
            if field_path == "authority_status":
                authority_binding = binding
            if field_path not in scenario:
                errors.append(_error("unknown_path", f"{binding_path}.path", "binding references an absent scenario field"))
            elif not _same_value(binding.get("value"), scenario[field_path]):
                errors.append(_error("value_mismatch", f"{binding_path}.value", "binding value differs from scenario"))

            origin = binding.get("origin")
            if origin not in _BINDING_ORIGINS:
                errors.append(_error("invalid_enum", f"{binding_path}.origin", "unsupported provenance origin"))
            binding_support = binding.get("support_span_ids")
            if not _is_str_list(binding_support):
                errors.append(_error("invalid_type", f"{binding_path}.support_span_ids", "expected string array"))
                binding_support = []
            for support_id in binding_support:
                if support_id not in span_by_id:
                    errors.append(_error("unknown_reference", f"{binding_path}.support_span_ids", f"unknown span {support_id}"))
            if origin == "USER_TEXT" and not binding_support:
                errors.append(_error("missing_support", f"{binding_path}.support_span_ids", "USER_TEXT origin requires source support"))
            if origin == "DERIVED_RULE" and not _is_exact_str(binding.get("rule_id")):
                errors.append(_error("missing_provenance", f"{binding_path}.rule_id", "DERIVED_RULE origin requires rule_id"))
            if origin in {"SYSTEM_CONTEXT", "AUTHORITY_STORE", "TOOL_OUTPUT"} and not _is_exact_str(binding.get("evidence_ref")):
                errors.append(_error("missing_provenance", f"{binding_path}.evidence_ref", f"{origin} origin requires evidence_ref"))
            if origin in {"SYSTEM_CONTEXT", "AUTHORITY_STORE", "TOOL_OUTPUT"} and not binding.get("evidence_ref"):
                errors.append(_error("missing_provenance", f"{binding_path}.evidence_ref", f"{origin} origin requires non-empty evidence_ref"))

        for binding_path, count in Counter(binding_paths).items():
            if count > 1:
                errors.append(_error("duplicate_binding", f"{path}.field_bindings", f"duplicate binding for {binding_path}"))
        required_bound_fields = set(scenario) - set(_SCENARIO_METADATA)
        missing_bindings = sorted(required_bound_fields - set(binding_paths))
        for missing in missing_bindings:
            errors.append(_error("missing_binding", f"{path}.field_bindings", f"missing provenance binding for {missing}"))

        # Authority and modality coherence.
        x_level = scenario.get("x_level")
        authority_status = scenario.get("authority_status")
        basis = node.get("authority_basis")
        supported_spans = [span_by_id[sid] for sid in support_ids if sid in span_by_id]
        direct_positive = any(
            span.get("role") == "USER_CONTROL"
            and span.get("modality") == "DIRECTIVE"
            and span.get("polarity") == "POSITIVE"
            for span in supported_spans
        )
        prohibitions = [
            span
            for span in supported_spans
            if span.get("modality") == "PROHIBITION" or span.get("polarity") == "NEGATIVE"
        ]
        non_authorizing = [
            span
            for span in supported_spans
            if span.get("role") in {"QUOTED_DATA", "EXTERNAL_CONTENT"}
            or span.get("modality") in {"QUESTION", "HYPOTHETICAL"}
        ]

        if prohibitions and not (scenario.get("hard_prohibition") is True and scenario.get("policy_status") == "DENY"):
            errors.append(_error("modality_laundering", path, "prohibition or negative polarity was promoted to permission"))
        if node.get("condition_status") == "UNSATISFIED" and authority_status == "VALID":
            errors.append(_error("condition_unsatisfied", f"{path}.condition_status", "unsatisfied condition cannot authorize action"))
        if non_authorizing and authority_status == "VALID":
            errors.append(_error("authority_laundering", path, "quoted, external, question or hypothetical text cannot mint authority"))
        if node.get("target_status") in {"AMBIGUOUS", "MISSING"} and extraction_status == "VALID":
            errors.append(_error("ambiguous_target", f"{path}.target_status", "material target is unresolved"))
        if unresolved and extraction_status == "VALID":
            errors.append(_error("unresolved_fields", f"{path}.unresolved_fields", "VALID extraction cannot contain unresolved fields"))

        if _is_exact_int(x_level) and x_level > 0 and authority_status == "VALID":
            if basis == "CURRENT_USER_DIRECTIVE":
                if not direct_positive:
                    errors.append(_error("authority_laundering", f"{path}.authority_basis", "current-turn authority lacks a positive user directive"))
                if authority_binding is None:
                    errors.append(_error("missing_binding", f"{path}.field_bindings", "authority_status lacks provenance binding"))
                elif authority_binding.get("origin") != "USER_TEXT":
                    errors.append(_error("authority_laundering", f"{path}.field_bindings", "current-turn authority must originate in USER_TEXT"))
            elif basis == "PRIOR_RECEIPT":
                receipt = node.get("authority_receipt_ref")
                if not _is_exact_str(receipt) or not receipt:
                    errors.append(_error("missing_authority_receipt", f"{path}.authority_receipt_ref", "prior authority requires a receipt reference"))
                if authority_binding is None or authority_binding.get("origin") != "AUTHORITY_STORE":
                    errors.append(_error("authority_laundering", f"{path}.field_bindings", "prior authority requires AUTHORITY_STORE provenance"))
                elif authority_binding.get("evidence_ref") != receipt:
                    errors.append(_error("authority_laundering", f"{path}.field_bindings", "authority evidence does not match receipt reference"))
            else:
                errors.append(_error("authority_laundering", f"{path}.authority_basis", "VALID authority has no admissible basis"))

    for node_id, count in Counter(node_ids).items():
        if count > 1:
            errors.append(_error("duplicate_id", "nodes", f"duplicate node_id {node_id}"))
    known_node_ids = set(node_by_id)
    for node_id, deps in graph.items():
        for dep in deps:
            if dep not in known_node_ids:
                errors.append(_error("unknown_reference", f"nodes[{node_id}].depends_on", f"unknown node {dep}"))
    if graph and _has_cycle(graph):
        errors.append(_error("dependency_cycle", "nodes", "task graph contains a dependency cycle"))

    # Conservative source-surface coverage. It does not invent actions when the
    # scanner sees none; it only rejects visible actions omitted or mismatched.
    detected_actions = _detected_actions(source_text)
    missing_actions = sorted(detected_actions - represented_actions)
    for action in missing_actions:
        errors.append(_error("action_omitted", "nodes", f"explicit source action {action} has no task node"))
    if detected_actions and represented_actions and detected_actions.isdisjoint(represented_actions):
        errors.append(_error("action_mismatch", "nodes", "source action surface and task nodes are disjoint"))

    if _contains_sensitive_surface(source_text) and represented_actions & {"SEND", "PUBLISH"}:
        for node in node_by_id.values():
            if node.get("action_type") not in {"SEND", "PUBLISH"}:
                continue
            scenario = node.get("scenario") if isinstance(node.get("scenario"), Mapping) else {}
            if scenario.get("data_gate_required") is not True or scenario.get("data_status") == "NOT_REQUIRED":
                errors.append(_error("data_surface_omitted", f"nodes[{node.get('node_id')}].scenario", "sensitive external transfer requires an active data gate"))

    unique: dict[tuple[str, str, str], dict[str, str]] = {}
    for item in errors:
        unique[(item["code"], item["path"], item["message"])] = item
    return [unique[key] for key in sorted(unique)]


def ingress_schema_document() -> dict[str, Any]:
    """Return a machine-readable structural projection of ingress v1."""

    span_schema = {
        "type": "object",
        "required": sorted(_SPAN_REQUIRED),
        "additionalProperties": False,
        "properties": {
            "span_id": {"type": "string", "minLength": 1},
            "start": {"type": "integer", "minimum": 0},
            "end": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "role": {"type": "string", "enum": sorted(_SPAN_ROLES)},
            "modality": {"type": "string", "enum": sorted(_MODALITIES)},
            "polarity": {"type": "string", "enum": sorted(_POLARITIES)},
        },
    }
    binding_schema = {
        "type": "object",
        "required": sorted(_BINDING_REQUIRED),
        "additionalProperties": False,
        "properties": {
            "path": {"type": "string", "enum": sorted(_SCENARIO_FIELDS)},
            "value": {},
            "origin": {"type": "string", "enum": sorted(_BINDING_ORIGINS)},
            "support_span_ids": {"type": "array", "items": {"type": "string"}},
            "rule_id": {"type": "string"},
            "evidence_ref": {"type": "string"},
        },
    }
    node_schema = {
        "type": "object",
        "required": sorted(_NODE_REQUIRED),
        "additionalProperties": False,
        "properties": {
            "node_id": {"type": "string", "minLength": 1},
            "action_type": {"type": "string", "enum": sorted(_ACTION_TYPES)},
            "target_status": {"type": "string", "enum": sorted(_TARGET_STATUSES)},
            "target_ref": {"type": "string"},
            "condition_status": {"type": "string", "enum": sorted(_CONDITION_STATUSES)},
            "authority_basis": {"type": "string", "enum": sorted(_AUTHORITY_BASES)},
            "authority_receipt_ref": {"type": "string"},
            "depends_on": {"type": "array", "items": {"type": "string"}},
            "support_span_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "unresolved_fields": {"type": "array", "items": {"type": "string"}},
            "scenario": schema_document(INPUT_CONTRACT_V2_ID),
            "field_bindings": {"type": "array", "minItems": 1, "items": binding_schema},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://local.invalid/triaxis/semantic-ingress-v1.schema.json",
        "title": "TRIAXIS Semantic Ingress Contract v1",
        "type": "object",
        "required": sorted(_ROOT_REQUIRED),
        "additionalProperties": False,
        "properties": {
            "contract_id": {"const": SEMANTIC_INGRESS_CONTRACT_ID},
            "source_text": {"type": "string"},
            "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "extraction_status": {"type": "string", "enum": sorted(_EXTRACTION_STATUSES)},
            "completion_mode": {"type": "string", "enum": sorted(_COMPLETION_MODES)},
            "spans": {"type": "array", "minItems": 1, "items": span_schema},
            "nodes": {"type": "array", "minItems": 1, "items": node_schema},
        },
        "$comment": "Digest, provenance, modality, graph and action-coverage rules are enforced by validate_ingress_record.",
    }


__all__ = [
    "SEMANTIC_INGRESS_CONTRACT_ID",
    "ingress_schema_document",
    "validate_ingress_record",
]
