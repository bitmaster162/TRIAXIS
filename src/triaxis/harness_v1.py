"""TRIAXIS v3.19 governed agent-harness contracts.

This module adopts useful harness patterns from modern coding agents while
preserving TRIAXIS' central invariant: discovery, planning, plugins, skills,
hooks, subagents, workflows and protocol adapters never mint execution
authority.  Authority can only be narrowed, and side effects still require the
existing action-assurance authorization token at the resource boundary.

The implementation is deliberately model/provider neutral.  It does not vendor
or depend on Grok Build code and does not claim ACP conformance; the ACP-style
adapter is a small deterministic boundary contract for later interoperability
work.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import sqlite3
from typing import Any

from .action_assurance import validate_authorization_token
from .integrity import canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

HARNESS_CONFIG_CONTRACT_ID = "TRIAXIS_HARNESS_CONFIG_v1"
CONTEXT_MANIFEST_CONTRACT_ID = "TRIAXIS_CONTEXT_DISCLOSURE_MANIFEST_v1"
CONTEXT_MATERIALIZATION_RECEIPT_CONTRACT_ID = "TRIAXIS_CONTEXT_MATERIALIZATION_RECEIPT_v1"
SKILL_CONTRACT_ID = "TRIAXIS_SKILL_CAPABILITY_CONTRACT_v1"
SKILL_INVOCATION_CONTRACT_ID = "TRIAXIS_SKILL_INVOCATION_v1"
PLUGIN_MANIFEST_CONTRACT_ID = "TRIAXIS_PLUGIN_MANIFEST_v1"
PLUGIN_TRUST_RECEIPT_CONTRACT_ID = "TRIAXIS_PLUGIN_TRUST_RECEIPT_v1"
HOOK_RESULT_CONTRACT_ID = "TRIAXIS_HOOK_RESULT_v1"
HOOK_PIPELINE_RECEIPT_CONTRACT_ID = "TRIAXIS_HOOK_PIPELINE_RECEIPT_v1"
SUBAGENT_CONTRACT_ID = "TRIAXIS_BOUNDED_SUBAGENT_v1"
SESSION_FORK_CONTRACT_ID = "TRIAXIS_SESSION_FORK_v1"
TOOL_SPEC_CONTRACT_ID = "TRIAXIS_TOOL_SPEC_v1"
TOOL_REQUEST_CONTRACT_ID = "TRIAXIS_TOOL_REQUEST_v1"
TOOL_DISPATCH_RECEIPT_CONTRACT_ID = "TRIAXIS_TOOL_DISPATCH_RECEIPT_v1"
WORKFLOW_DEFINITION_CONTRACT_ID = "TRIAXIS_HOST_WORKFLOW_DEFINITION_v1"
WORKFLOW_EVENT_CONTRACT_ID = "TRIAXIS_HOST_WORKFLOW_EVENT_v1"
HEADLESS_EVENT_CONTRACT_ID = "TRIAXIS_HEADLESS_EVENT_v1"
ACP_MESSAGE_CONTRACT_ID = "TRIAXIS_ACP_STYLE_MESSAGE_v1"
RETRY_DECISION_CONTRACT_ID = "TRIAXIS_HARNESS_RETRY_DECISION_v1"
INSPECTION_REPORT_CONTRACT_ID = "TRIAXIS_HARNESS_INSPECTION_REPORT_v1"

DATA_CLASSES = ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET")
CAPABILITY_MODES = {
    "read-only": frozenset({"read"}),
    "read-write": frozenset({"read", "write"}),
    "execute": frozenset({"read", "execute"}),
    "all": frozenset({"read", "write", "execute"}),
}
HOOK_DECISIONS = ("ALLOW", "WARN", "HOLD", "DENY")
HOOK_EVENTS = frozenset(
    {
        "PRE_CONTEXT",
        "POST_CONTEXT",
        "PRE_PLAN",
        "POST_PLAN",
        "PRE_TOOL",
        "POST_TOOL",
        "PRE_EXECUTE",
        "POST_EXECUTE",
        "ON_ERROR",
        "ON_RECOVERY",
    }
)
WORKFLOW_PHASES = (
    "NEW",
    "PLANNED",
    "REVIEWED",
    "DIFF_READY",
    "AUTHORIZED",
    "EXECUTING",
    "VERIFYING",
    "COMPLETED",
)
TERMINAL_WORKFLOW_STATES = frozenset({"COMPLETED", "DENIED", "FAILED", "STOPPED"})
HEADLESS_EVENT_TYPES = frozenset(
    {
        "SESSION_STARTED",
        "CONTEXT_ASSEMBLED",
        "PLAN_CREATED",
        "PLAN_REVIEWED",
        "DIFF_READY",
        "APPROVAL_REQUIRED",
        "TOOL_CALL_REQUESTED",
        "TOOL_CALL_RESULT",
        "SUBAGENT_STARTED",
        "SUBAGENT_COMPLETED",
        "WORKFLOW_PAUSED",
        "WORKFLOW_RESUMED",
        "TURN_COMPLETED",
        "ERROR",
    }
)
ACP_STYLE_METHODS = frozenset(
    {
        "initialize",
        "session/new",
        "session/prompt",
        "session/cancel",
        "session/fork",
        "session/inspect",
        "session/resume",
        "session/close",
    }
)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _string_set(value: Any, path: str, errors: list[dict[str, str]]) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        errors.append(_error("invalid_string_array", path, "non-empty string array required"))
        return set()
    return set(value)


def _canonical_object(value: Any, path: str, errors: list[dict[str, str]]) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        errors.append(_error("invalid_type", path, "object required"))
        return None
    try:
        materialized = materialize_json(value)
    except Exception as exc:
        errors.append(_error("materialization_failed", path, type(exc).__name__))
        return None
    return materialized if isinstance(materialized, dict) else None


def _validate_sealed(
    value: Any,
    *,
    contract_id: str,
    digest_field: str,
    path: str,
    errors: list[dict[str, str]],
) -> dict[str, Any] | None:
    obj = _canonical_object(value, path, errors)
    if obj is None:
        return None
    if obj.get("contract_id") != contract_id:
        errors.append(_error("invalid_contract_id", f"{path}.contract_id", f"expected {contract_id}"))
    if not verify_sealed_mapping(obj, digest_field):
        errors.append(_error("digest_mismatch", f"{path}.{digest_field}", "canonical digest mismatch"))
    return obj


def _ensure_subset(
    requested: Iterable[str],
    allowed: Iterable[str],
    *,
    code: str,
    path: str,
    errors: list[dict[str, str]],
) -> set[str]:
    requested_set = set(requested)
    allowed_set = set(allowed)
    extra = requested_set - allowed_set
    if extra:
        errors.append(_error(code, path, f"not allowed: {sorted(extra)}"))
    return requested_set & allowed_set


def normalize_logical_path(value: str) -> str:
    """Return a canonical repository-relative path or raise ``ValueError``."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("non-empty path required")
    candidate = value.replace("\\", "/")
    if candidate.startswith("/") or (len(candidate) >= 2 and candidate[1] == ":"):
        raise ValueError("absolute paths are forbidden")
    path = PurePosixPath(candidate)
    parts = [part for part in path.parts if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("path traversal is forbidden")
    if any("*" in part or "?" in part or "[" in part or "]" in part for part in parts):
        raise ValueError("wildcards are forbidden")
    return "/".join(parts)


def _authority_is_subset(after: Mapping[str, Any], before: Mapping[str, Any]) -> bool:
    for field in ("capabilities", "tools", "targets", "data_classes", "mcp_servers"):
        after_items = after.get(field, [])
        before_items = before.get(field, [])
        if not isinstance(after_items, list) or not isinstance(before_items, list):
            return False
        if not set(after_items).issubset(set(before_items)):
            return False
    for field in ("max_context_bytes", "max_subagents", "max_workflow_fanout", "max_rounds"):
        a = after.get(field)
        b = before.get(field)
        if type(a) is not int or type(b) is not int or a > b:
            return False
    return True


def _normalized_authority(value: Mapping[str, Any]) -> dict[str, Any]:
    result = materialize_json(value)
    if not isinstance(result, dict):
        raise TypeError("authority envelope must be an object")
    for field in ("capabilities", "tools", "targets", "data_classes", "mcp_servers"):
        items = result.get(field, [])
        if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
            raise ValueError(f"authority.{field} must be a string array")
        result[field] = sorted(set(items))
    for field in ("max_context_bytes", "max_subagents", "max_workflow_fanout", "max_rounds"):
        value_ = result.get(field)
        if type(value_) is not int or value_ < 0:
            raise ValueError(f"authority.{field} must be integer >= 0")
    return result


def resolve_harness_config(layers: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Resolve configuration while preserving safety ceilings.

    Layers are supplied from lowest to highest ordinary precedence.  Each layer
    may contain ordinary values and a ``requirements`` block.  Ordinary values
    replace earlier values; requirements can only narrow sets or lower numeric
    budgets.  This adapts coding-agent config precedence to TRIAXIS governance:
    managed/operator requirements cannot be widened by project or runtime data.
    """

    if not layers:
        raise ValueError("at least one config layer is required")
    effective: dict[str, Any] = {
        "capabilities": [],
        "tools": [],
        "targets": [],
        "data_classes": ["PUBLIC"],
        "mcp_servers": [],
        "max_context_bytes": 0,
        "max_subagents": 0,
        "max_workflow_fanout": 0,
        "max_rounds": 0,
        "whole_repo_upload": False,
        "plugin_digests": [],
        "sandbox_profiles": [],
    }
    applied_layers: list[str] = []
    requirement_sources: list[str] = []
    pending_requirements: list[tuple[str, dict[str, Any]]] = []

    for index, raw_layer in enumerate(layers):
        layer = materialize_json(raw_layer)
        if not isinstance(layer, dict):
            raise TypeError(f"layer {index} must be an object")
        name = layer.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"layer {index} requires name")
        values = layer.get("values", {})
        if not isinstance(values, dict):
            raise ValueError(f"layer {name}.values must be object")
        for field in (
            "capabilities",
            "tools",
            "targets",
            "data_classes",
            "mcp_servers",
            "plugin_digests",
            "sandbox_profiles",
        ):
            if field in values:
                items = values[field]
                if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
                    raise ValueError(f"{name}.{field} must be string array")
                effective[field] = sorted(set(items))
        for field in ("max_context_bytes", "max_subagents", "max_workflow_fanout", "max_rounds"):
            if field in values:
                value_ = values[field]
                if type(value_) is not int or value_ < 0:
                    raise ValueError(f"{name}.{field} must be integer >= 0")
                effective[field] = value_
        if "whole_repo_upload" in values:
            if type(values["whole_repo_upload"]) is not bool:
                raise ValueError(f"{name}.whole_repo_upload must be boolean")
            effective["whole_repo_upload"] = values["whole_repo_upload"]
        requirements = layer.get("requirements", {})
        if requirements:
            if not isinstance(requirements, dict):
                raise ValueError(f"{name}.requirements must be object")
            pending_requirements.append((name, requirements))
        applied_layers.append(name)

    for name, requirements in pending_requirements:
        for field in (
            "capabilities",
            "tools",
            "targets",
            "data_classes",
            "mcp_servers",
            "plugin_digests",
            "sandbox_profiles",
        ):
            if field in requirements:
                items = requirements[field]
                if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
                    raise ValueError(f"{name}.requirements.{field} must be string array")
                effective[field] = sorted(set(effective[field]).intersection(items))
        for field in ("max_context_bytes", "max_subagents", "max_workflow_fanout", "max_rounds"):
            if field in requirements:
                ceiling = requirements[field]
                if type(ceiling) is not int or ceiling < 0:
                    raise ValueError(f"{name}.requirements.{field} must be integer >= 0")
                effective[field] = min(effective[field], ceiling)
        if requirements.get("whole_repo_upload") is False:
            effective["whole_repo_upload"] = False
        elif requirements.get("whole_repo_upload") is True:
            # A requirement can forbid, never force-enable, bulk disclosure.
            pass
        requirement_sources.append(name)

    if effective["whole_repo_upload"]:
        raise ValueError("whole_repo_upload is not supported by TRIAXIS harness")
    if not set(effective["data_classes"]).issubset(DATA_CLASSES):
        raise ValueError("unknown data class")
    config = {
        "contract_id": HARNESS_CONFIG_CONTRACT_ID,
        **effective,
        "applied_layers": applied_layers,
        "requirement_sources": requirement_sources,
        "config_sha256": "",
    }
    return seal_mapping(config, "config_sha256")


def assemble_context(request: Mapping[str, Any], effective_config: Mapping[str, Any]) -> dict[str, Any]:
    """Build an explicit disclosure manifest; never infer a whole repository.

    Context items contain references and digests, not raw file content.  A caller
    may subsequently load only ``selected_items``.  Wildcards, repository
    bundles, git history and deleted/historical objects are denied by default.
    """

    errors: list[dict[str, str]] = []
    config = _validate_sealed(
        effective_config,
        contract_id=HARNESS_CONFIG_CONTRACT_ID,
        digest_field="config_sha256",
        path="config",
        errors=errors,
    )
    req = _canonical_object(request, "request", errors)
    if config is None or req is None:
        return {"status": "BLOCK", "errors": errors}
    session_id = req.get("session_id")
    purpose = req.get("purpose")
    if not isinstance(session_id, str) or not session_id:
        errors.append(_error("missing_session", "request.session_id", "session_id required"))
    if not isinstance(purpose, str) or not purpose:
        errors.append(_error("missing_purpose", "request.purpose", "purpose required"))
    items = req.get("items")
    if not isinstance(items, list):
        errors.append(_error("invalid_items", "request.items", "array required"))
        items = []
    allowed_classes = set(config.get("data_classes", []))
    max_bytes = config.get("max_context_bytes")
    if type(max_bytes) is not int or max_bytes < 0:
        errors.append(_error("invalid_config_budget", "config.max_context_bytes", "integer >= 0 required"))
        max_bytes = 0
    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    total = 0
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(items):
        path = f"request.items[{index}]"
        item = _canonical_object(raw_item, path, errors)
        if item is None:
            continue
        artifact_id = item.get("artifact_id")
        logical_path = item.get("logical_path")
        size_bytes = item.get("size_bytes")
        data_class = item.get("data_class")
        explicit_grant = item.get("explicit_grant") is True
        source_kind = item.get("source_kind")
        content_sha256 = item.get("content_sha256")
        reasons: list[str] = []
        if not isinstance(artifact_id, str) or not artifact_id:
            reasons.append("MISSING_ARTIFACT_ID")
        elif artifact_id in seen_ids:
            reasons.append("DUPLICATE_ARTIFACT_ID")
        else:
            seen_ids.add(artifact_id)
        if not isinstance(logical_path, str) or not logical_path:
            reasons.append("MISSING_LOGICAL_PATH")
        else:
            try:
                logical_path = normalize_logical_path(logical_path)
            except ValueError:
                reasons.append("UNSAFE_OR_WILDCARD_PATH_DENIED")
        if source_kind in {"REPOSITORY_BUNDLE", "GIT_HISTORY", "DELETED_OBJECT"}:
            reasons.append("BULK_OR_HISTORICAL_SOURCE_DENIED")
        if item.get("includes_git_history") is True or item.get("includes_deleted_content") is True:
            reasons.append("HISTORICAL_CONTENT_DENIED")
        if not _is_sha256(content_sha256):
            reasons.append("INVALID_CONTENT_DIGEST")
        if type(size_bytes) is not int or size_bytes < 0:
            reasons.append("INVALID_SIZE")
            size_bytes = 0
        if data_class not in DATA_CLASSES:
            reasons.append("INVALID_DATA_CLASS")
        elif data_class not in allowed_classes:
            reasons.append("DATA_CLASS_NOT_ALLOWED")
        if not explicit_grant:
            reasons.append("EXPLICIT_GRANT_REQUIRED")
        if total + size_bytes > max_bytes:
            reasons.append("CONTEXT_BUDGET_EXCEEDED")
        if reasons:
            rejected.append({"artifact_id": artifact_id, "logical_path": logical_path, "reasons": sorted(set(reasons))})
            continue
        selected_item = {
            "artifact_id": artifact_id,
            "logical_path": logical_path,
            "source_kind": source_kind,
            "content_sha256": content_sha256,
            "size_bytes": size_bytes,
            "data_class": data_class,
            "purpose": item.get("purpose", purpose),
        }
        selected.append(selected_item)
        total += size_bytes

    status = "BLOCK" if errors else ("PASS_WITH_OMISSIONS" if rejected else "PASS")
    manifest = {
        "contract_id": CONTEXT_MANIFEST_CONTRACT_ID,
        "session_id": session_id,
        "purpose": purpose,
        "config_sha256": config.get("config_sha256"),
        "selected_items": selected,
        "rejected_items": rejected,
        "selected_bytes": total,
        "whole_repo_disclosure": False,
        "git_history_disclosure": False,
        "implicit_disclosure": False,
        "status": status,
        "errors": errors,
        "manifest_sha256": "",
    }
    return seal_mapping(manifest, "manifest_sha256")


def materialize_context_receipt(
    manifest_value: Mapping[str, Any],
    materialized_bytes: Mapping[str, bytes],
    *,
    materializer_id: str,
    observed_at_tick: int,
) -> dict[str, Any]:
    """Hash exact bytes loaded for a previously approved context manifest.

    The caller is the host-owned materializer.  The returned receipt contains no
    raw content, only exact observed digests and sizes.  A tool must consume the
    captured bytes represented by this receipt rather than re-reading a mutable
    path after authorization.
    """

    errors: list[dict[str, str]] = []
    manifest = _validate_sealed(
        manifest_value,
        contract_id=CONTEXT_MANIFEST_CONTRACT_ID,
        digest_field="manifest_sha256",
        path="context_manifest",
        errors=errors,
    )
    if not isinstance(materializer_id, str) or not materializer_id:
        errors.append(_error("invalid_materializer", "materializer_id", "non-empty identity required"))
    if type(observed_at_tick) is not int or observed_at_tick < 0:
        errors.append(_error("invalid_observed_at", "observed_at_tick", "integer >= 0 required"))
    if not isinstance(materialized_bytes, Mapping):
        errors.append(_error("invalid_materialized_bytes", "materialized_bytes", "mapping required"))
        materialized_bytes = {}
    selected = {
        item.get("artifact_id"): item
        for item in (manifest or {}).get("selected_items", [])
        if isinstance(item, Mapping)
    }
    observed_items: list[dict[str, Any]] = []
    for artifact_id in sorted(materialized_bytes):
        raw = materialized_bytes[artifact_id]
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append(_error("invalid_artifact_id", "materialized_bytes", "non-empty string key required"))
            continue
        if not isinstance(raw, (bytes, bytearray)):
            errors.append(_error("invalid_materialized_content", f"materialized_bytes.{artifact_id}", "bytes required"))
            continue
        item = selected.get(artifact_id)
        if item is None:
            errors.append(_error("artifact_not_in_manifest", f"materialized_bytes.{artifact_id}", "not selected by manifest"))
            continue
        raw_bytes = bytes(raw)
        observed_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        observed_size = len(raw_bytes)
        expected_sha256 = item.get("content_sha256")
        expected_size = item.get("size_bytes")
        if observed_sha256 != expected_sha256:
            errors.append(_error("materialized_digest_mismatch", f"materialized_bytes.{artifact_id}", f"expected {expected_sha256}, observed {observed_sha256}"))
        if observed_size != expected_size:
            errors.append(_error("materialized_size_mismatch", f"materialized_bytes.{artifact_id}", f"expected {expected_size}, observed {observed_size}"))
        observed_items.append({
            "artifact_id": artifact_id,
            "logical_path": item.get("logical_path"),
            "content_sha256": observed_sha256,
            "size_bytes": observed_size,
            "data_class": item.get("data_class"),
        })
    receipt = {
        "contract_id": CONTEXT_MATERIALIZATION_RECEIPT_CONTRACT_ID,
        "context_manifest_sha256": (manifest or {}).get("manifest_sha256"),
        "materializer_id": materializer_id,
        "observed_at_tick": observed_at_tick,
        "observed_items": observed_items,
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "receipt_sha256": "",
    }
    return seal_mapping(receipt, "receipt_sha256")


def compact_context_manifest(
    manifest_value: Mapping[str, Any],
    *,
    retained_artifact_ids: Sequence[str],
    summary_sha256: str,
    active_task_refs: Sequence[str] = (),
    background_state_sha256: str | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    manifest = _validate_sealed(
        manifest_value,
        contract_id=CONTEXT_MANIFEST_CONTRACT_ID,
        digest_field="manifest_sha256",
        path="manifest",
        errors=errors,
    )
    if manifest is None:
        raise ValueError(str(errors))
    if not _is_sha256(summary_sha256):
        raise ValueError("summary_sha256 required")
    if background_state_sha256 is not None and not _is_sha256(background_state_sha256):
        raise ValueError("background_state_sha256 must be SHA-256 or null")
    if not all(isinstance(item, str) and item for item in active_task_refs):
        raise ValueError("active_task_refs must be non-empty strings")
    retained = set(retained_artifact_ids)
    selected = manifest.get("selected_items", [])
    if not isinstance(selected, list):
        raise ValueError("selected_items missing")
    known = {item.get("artifact_id") for item in selected if isinstance(item, Mapping)}
    if not retained.issubset(known):
        raise ValueError("cannot retain unknown artifact")
    result = {
        "contract_id": "TRIAXIS_CONTEXT_COMPACTION_RECEIPT_v1",
        "source_manifest_sha256": manifest["manifest_sha256"],
        "summary_sha256": summary_sha256,
        "retained_artifact_ids": sorted(retained),
        "omitted_artifact_ids": sorted(str(item) for item in known - retained if isinstance(item, str)),
        "active_task_refs": sorted(set(active_task_refs)),
        "background_state_sha256": background_state_sha256,
        "receipt_sha256": "",
    }
    return seal_mapping(result, "receipt_sha256")


class SkillRegistryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[str, list[dict[str, Any]]] = {}

    @staticmethod
    def seal_skill(value: Mapping[str, Any]) -> dict[str, Any]:
        body = materialize_json(value)
        if not isinstance(body, dict):
            raise TypeError("skill must be an object")
        body.setdefault("contract_id", SKILL_CONTRACT_ID)
        body.setdefault("skill_sha256", "")
        return seal_mapping(body, "skill_sha256")

    @staticmethod
    def validate_skill(value: Any) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        skill = _validate_sealed(
            value,
            contract_id=SKILL_CONTRACT_ID,
            digest_field="skill_sha256",
            path="skill",
            errors=errors,
        )
        if skill is None:
            return {"status": "BLOCK", "errors": errors}
        for field in ("skill_id", "name", "description"):
            if not isinstance(skill.get(field), str) or not skill.get(field):
                errors.append(_error("missing_required", f"skill.{field}", f"{field} required"))
        if type(skill.get("version")) is not int or skill.get("version", 0) < 1:
            errors.append(_error("invalid_version", "skill.version", "integer >= 1 required"))
        for field in ("required_inputs", "produced_outputs", "requested_capabilities", "allowed_tools"):
            _string_set(skill.get(field), f"skill.{field}", errors)
        if skill.get("default_isolation") not in {"none", "worktree"}:
            errors.append(_error("invalid_isolation", "skill.default_isolation", "none or worktree required"))
        previous = skill.get("supersedes_skill_sha256")
        if previous is not None and not _is_sha256(previous):
            errors.append(_error("invalid_supersedes", "skill.supersedes_skill_sha256", "SHA-256 or null required"))
        return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "skill": skill}

    def register(self, value: Mapping[str, Any]) -> dict[str, Any]:
        result = self.validate_skill(value)
        if result["status"] != "PASS":
            raise SkillRegistryError("invalid_skill", str(result["errors"]))
        skill = result["skill"]
        history = self._skills.setdefault(skill["skill_id"], [])
        if history:
            head = history[-1]
            if skill["version"] <= head["version"]:
                raise SkillRegistryError("skill_rollback", "version must increase")
            if skill.get("supersedes_skill_sha256") != head["skill_sha256"]:
                raise SkillRegistryError("skill_lineage_break", "new version must supersede current head")
        elif skill.get("supersedes_skill_sha256") is not None:
            raise SkillRegistryError("orphan_skill", "genesis cannot supersede unknown skill")
        history.append(skill)
        return deepcopy(skill)

    def head(self, skill_id: str) -> dict[str, Any] | None:
        history = self._skills.get(skill_id, [])
        return None if not history else deepcopy(history[-1])

    def invoke(
        self,
        skill_id: str,
        *,
        provided_inputs: Mapping[str, Any],
        session_authority: Mapping[str, Any],
    ) -> dict[str, Any]:
        skill = self.head(skill_id)
        if skill is None:
            raise SkillRegistryError("unknown_skill", skill_id)
        authority = _normalized_authority(session_authority)
        missing = sorted(set(skill["required_inputs"]) - set(provided_inputs.keys()))
        requested_capabilities = set(skill["requested_capabilities"])
        requested_tools = set(skill["allowed_tools"])
        allowed_capabilities = set(authority["capabilities"])
        allowed_tools = set(authority["tools"])
        errors: list[dict[str, str]] = []
        if missing:
            errors.append(_error("missing_skill_inputs", "inputs", str(missing)))
        if not requested_capabilities.issubset(allowed_capabilities):
            errors.append(_error("skill_capability_widening", "skill.requested_capabilities", str(sorted(requested_capabilities - allowed_capabilities))))
        if not requested_tools.issubset(allowed_tools):
            errors.append(_error("skill_tool_widening", "skill.allowed_tools", str(sorted(requested_tools - allowed_tools))))
        invocation = {
            "contract_id": SKILL_INVOCATION_CONTRACT_ID,
            "skill_id": skill_id,
            "skill_sha256": skill["skill_sha256"],
            "input_names": sorted(provided_inputs.keys()),
            "effective_capabilities": sorted(requested_capabilities & allowed_capabilities),
            "effective_tools": sorted(requested_tools & allowed_tools),
            "default_isolation": skill["default_isolation"],
            "status": "PASS" if not errors else "BLOCK",
            "errors": errors,
            "invocation_sha256": "",
        }
        return seal_mapping(invocation, "invocation_sha256")


class PluginRegistryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PluginRegistry:
    """Trust-before-activation plugin catalog.

    Plugin manifests are data only.  Loading executable plugin code is outside
    this reference module; the registry returns an activation receipt that a
    host may use only after digest pinning and capability checks.
    """

    def __init__(self, trusted_digests: Iterable[str]) -> None:
        self.trusted_digests = set(trusted_digests)
        self._installed: dict[str, dict[str, Any]] = {}

    @staticmethod
    def seal_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
        body = materialize_json(value)
        if not isinstance(body, dict):
            raise TypeError("plugin manifest must be object")
        body.setdefault("contract_id", PLUGIN_MANIFEST_CONTRACT_ID)
        body.setdefault("manifest_sha256", "")
        return seal_mapping(body, "manifest_sha256")

    def inspect_and_activate(
        self,
        value: Mapping[str, Any],
        *,
        session_authority: Mapping[str, Any],
    ) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        manifest = _validate_sealed(
            value,
            contract_id=PLUGIN_MANIFEST_CONTRACT_ID,
            digest_field="manifest_sha256",
            path="plugin",
            errors=errors,
        )
        if manifest is None:
            raise PluginRegistryError("invalid_plugin", str(errors))
        for field in ("plugin_id", "version", "source_sha256"):
            if not isinstance(manifest.get(field), str) or not manifest.get(field):
                errors.append(_error("missing_required", f"plugin.{field}", f"{field} required"))
        if not _is_sha256(manifest.get("source_sha256")):
            errors.append(_error("invalid_source_digest", "plugin.source_sha256", "SHA-256 required"))
        for field in ("skills", "commands", "agents", "hooks", "mcp_servers", "requested_capabilities"):
            _string_set(manifest.get(field), f"plugin.{field}", errors)
        if manifest.get("permission_mode") == "bypassPermissions":
            errors.append(_error("permission_bypass_forbidden", "plugin.permission_mode", "bypassPermissions forbidden"))
        if manifest.get("source_sha256") not in self.trusted_digests:
            errors.append(_error("plugin_not_pinned", "plugin.source_sha256", "operator-pinned digest required"))
        authority = _normalized_authority(session_authority)
        requested_capabilities = set(manifest.get("requested_capabilities", []))
        requested_mcp = set(manifest.get("mcp_servers", []))
        if not requested_capabilities.issubset(authority["capabilities"]):
            errors.append(_error("plugin_capability_widening", "plugin.requested_capabilities", "plugin exceeds session authority"))
        if not requested_mcp.issubset(authority["mcp_servers"]):
            errors.append(_error("plugin_mcp_widening", "plugin.mcp_servers", "plugin MCP not inherited/allowed"))
        status = "ACTIVE" if not errors else "QUARANTINED"
        receipt = {
            "contract_id": PLUGIN_TRUST_RECEIPT_CONTRACT_ID,
            "plugin_id": manifest.get("plugin_id"),
            "plugin_manifest_sha256": manifest.get("manifest_sha256"),
            "source_sha256": manifest.get("source_sha256"),
            "status": status,
            "effective_capabilities": sorted(requested_capabilities & set(authority["capabilities"])),
            "effective_mcp_servers": sorted(requested_mcp & set(authority["mcp_servers"])),
            "component_inventory": {
                field: list(manifest.get(field, []))
                for field in ("skills", "commands", "agents", "hooks", "mcp_servers")
            },
            "errors": errors,
            "receipt_sha256": "",
        }
        receipt = seal_mapping(receipt, "receipt_sha256")
        if status == "ACTIVE" and isinstance(manifest.get("plugin_id"), str):
            self._installed[manifest["plugin_id"]] = manifest
        return receipt

    def installed(self) -> list[str]:
        return sorted(self._installed)


def evaluate_hook_pipeline(
    *,
    event: str,
    hook_results: Sequence[Mapping[str, Any]],
    authority_before: Mapping[str, Any],
) -> dict[str, Any]:
    if event not in HOOK_EVENTS:
        raise ValueError("unknown hook event")
    before = _normalized_authority(authority_before)
    errors: list[dict[str, str]] = []
    accepted: list[dict[str, Any]] = []
    outcome = "ALLOW"
    rank = {"ALLOW": 0, "WARN": 1, "HOLD": 2, "DENY": 3}
    for index, raw in enumerate(hook_results):
        hook = _validate_sealed(
            raw,
            contract_id=HOOK_RESULT_CONTRACT_ID,
            digest_field="hook_result_sha256",
            path=f"hooks[{index}]",
            errors=errors,
        )
        if hook is None:
            outcome = "DENY"
            continue
        if hook.get("event") != event:
            errors.append(_error("hook_event_mismatch", f"hooks[{index}].event", event))
        decision = hook.get("decision")
        if decision not in HOOK_DECISIONS:
            errors.append(_error("invalid_hook_decision", f"hooks[{index}].decision", "ALLOW/WARN/HOLD/DENY required"))
            decision = "DENY"
        after_raw = hook.get("authority_after")
        try:
            after = _normalized_authority(after_raw) if isinstance(after_raw, Mapping) else before
        except Exception:
            after = before
            errors.append(_error("invalid_hook_authority", f"hooks[{index}].authority_after", "invalid authority"))
        if not _authority_is_subset(after, before):
            errors.append(_error("hook_authority_widening", f"hooks[{index}].authority_after", "hooks may only narrow authority"))
            decision = "DENY"
        if rank[decision] > rank[outcome]:
            outcome = decision
        accepted.append(hook)
    if errors:
        outcome = "DENY"
    receipt = {
        "contract_id": HOOK_PIPELINE_RECEIPT_CONTRACT_ID,
        "event": event,
        "hook_result_digests": [item.get("hook_result_sha256") for item in accepted],
        "outcome": outcome,
        "authority_before": before,
        "errors": errors,
        "receipt_sha256": "",
    }
    return seal_mapping(receipt, "receipt_sha256")


def seal_hook_result(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("hook result must be object")
    body.setdefault("contract_id", HOOK_RESULT_CONTRACT_ID)
    body.setdefault("hook_result_sha256", "")
    return seal_mapping(body, "hook_result_sha256")


def resolve_mcp_inheritance(parent_servers: Sequence[str], rule: Mapping[str, Any]) -> list[str]:
    parent = set(parent_servers)
    mode = rule.get("mode", "all")
    names = rule.get("names", [])
    if not isinstance(names, list) or not all(isinstance(item, str) and item for item in names):
        raise ValueError("MCP names must be string array")
    name_set = set(names)
    if mode == "all":
        result = parent
    elif mode == "none":
        result = set()
    elif mode == "named":
        if not name_set.issubset(parent):
            raise ValueError("cannot inherit unknown MCP server")
        result = parent & name_set
    elif mode == "except":
        result = parent - name_set
    else:
        raise ValueError("MCP inheritance mode must be all/none/named/except")
    return sorted(result)


def build_subagent_contract(
    parent_session: Mapping[str, Any],
    request: Mapping[str, Any],
    effective_config: Mapping[str, Any],
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    parent = _canonical_object(parent_session, "parent", errors)
    req = _canonical_object(request, "request", errors)
    config = _validate_sealed(
        effective_config,
        contract_id=HARNESS_CONFIG_CONTRACT_ID,
        digest_field="config_sha256",
        path="config",
        errors=errors,
    )
    if parent is None or req is None or config is None:
        return {"status": "BLOCK", "errors": errors}
    depth = parent.get("depth")
    if type(depth) is not int or depth < 0:
        errors.append(_error("invalid_parent_depth", "parent.depth", "integer >= 0 required"))
        depth = 99
    if depth >= 1:
        errors.append(_error("subagent_depth_limit", "parent.depth", "maximum child depth is one"))
    active_children = parent.get("active_child_count", 0)
    if type(active_children) is not int or active_children < 0:
        errors.append(_error("invalid_child_count", "parent.active_child_count", "integer >= 0 required"))
        active_children = 0
    if active_children >= config.get("max_subagents", 0):
        errors.append(_error("subagent_fanout_limit", "parent.active_child_count", "subagent limit reached"))
    mode = req.get("capability_mode", "read-only")
    if mode not in CAPABILITY_MODES:
        errors.append(_error("invalid_capability_mode", "request.capability_mode", "unknown mode"))
        mode = "read-only"
    isolation = req.get("isolation", "none")
    if isolation not in {"none", "worktree"}:
        errors.append(_error("invalid_isolation", "request.isolation", "none or worktree required"))
    if mode in {"read-write", "all"} and isolation != "worktree":
        errors.append(_error("write_requires_worktree", "request.isolation", "worktree required for write capability"))
    sandbox_profile = req.get("sandbox_profile")
    if "execute" in CAPABILITY_MODES[mode]:
        if not isinstance(sandbox_profile, str) or sandbox_profile not in set(config.get("sandbox_profiles", [])):
            errors.append(_error("execute_requires_sandbox", "request.sandbox_profile", "operator-approved sandbox profile required"))
    parent_capabilities = set(parent.get("capabilities", []))
    requested_capabilities = set(req.get("requested_capabilities", []))
    if not requested_capabilities:
        requested_capabilities = set(CAPABILITY_MODES[mode])
    effective_capabilities = requested_capabilities & set(CAPABILITY_MODES[mode]) & parent_capabilities & set(config.get("capabilities", []))
    if requested_capabilities - effective_capabilities:
        errors.append(_error("subagent_capability_widening", "request.requested_capabilities", str(sorted(requested_capabilities - effective_capabilities))))
    try:
        inherited_mcp = resolve_mcp_inheritance(parent.get("mcp_servers", []), req.get("mcp_inheritance", {"mode": "all", "names": []}))
    except ValueError as exc:
        inherited_mcp = []
        errors.append(_error("invalid_mcp_inheritance", "request.mcp_inheritance", str(exc)))
    if not set(inherited_mcp).issubset(set(config.get("mcp_servers", []))):
        errors.append(_error("mcp_not_allowed_by_config", "request.mcp_inheritance", "MCP inheritance exceeds config"))
        inherited_mcp = sorted(set(inherited_mcp) & set(config.get("mcp_servers", [])))
    context_manifest_sha256 = req.get("context_manifest_sha256")
    if not _is_sha256(context_manifest_sha256):
        errors.append(_error("missing_context_manifest", "request.context_manifest_sha256", "explicit context manifest required"))
    child_id = req.get("child_session_id")
    if not isinstance(child_id, str) or not child_id:
        errors.append(_error("missing_child_id", "request.child_session_id", "child_session_id required"))
    contract = {
        "contract_id": SUBAGENT_CONTRACT_ID,
        "parent_session_id": parent.get("session_id"),
        "child_session_id": child_id,
        "depth": 1,
        "agent_type": req.get("agent_type", "general-purpose"),
        "persona_id": req.get("persona_id"),
        "capability_mode": mode,
        "effective_capabilities": sorted(effective_capabilities),
        "inherited_mcp_servers": inherited_mcp,
        "context_manifest_sha256": context_manifest_sha256,
        "isolation": isolation,
        "worktree_ref": req.get("worktree_ref") if isolation == "worktree" else None,
        "sandbox_profile": sandbox_profile,
        "background": req.get("background") is True,
        "resume_from": req.get("resume_from"),
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "subagent_sha256": "",
    }
    return seal_mapping(contract, "subagent_sha256")


def fork_session(parent_session: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, Any]:
    parent = materialize_json(parent_session)
    req = materialize_json(request)
    if not isinstance(parent, dict) or not isinstance(req, dict):
        raise TypeError("parent and request must be objects")
    mode = req.get("mode")
    if mode not in {"read-only", "worktree"}:
        raise ValueError("fork mode must be read-only or worktree")
    if mode == "worktree" and not isinstance(req.get("worktree_ref"), str):
        raise ValueError("worktree_ref required")
    if not _is_sha256(req.get("context_manifest_sha256")):
        raise ValueError("context manifest digest required")
    if req.get("inherit_authority") is True:
        raise ValueError("forks cannot inherit mutable authority implicitly")
    result = {
        "contract_id": SESSION_FORK_CONTRACT_ID,
        "parent_session_id": parent.get("session_id"),
        "fork_session_id": req.get("fork_session_id"),
        "mode": mode,
        "worktree_ref": req.get("worktree_ref") if mode == "worktree" else None,
        "context_manifest_sha256": req["context_manifest_sha256"],
        "memory_refs": sorted(set(req.get("memory_refs", []))),
        "policy_refs": sorted(set(req.get("policy_refs", []))),
        "evidence_refs": sorted(set(req.get("evidence_refs", []))),
        "authority_checkpoint_sha256": req.get("authority_checkpoint_sha256"),
        "implicit_authority_inheritance": False,
        "fork_sha256": "",
    }
    if not isinstance(result["fork_session_id"], str) or not result["fork_session_id"]:
        raise ValueError("fork_session_id required")
    if result["authority_checkpoint_sha256"] is not None and not _is_sha256(result["authority_checkpoint_sha256"]):
        raise ValueError("authority checkpoint must be SHA-256 or null")
    return seal_mapping(result, "fork_sha256")


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    capability: str
    side_effect: bool
    allowed_targets: tuple[str, ...]
    max_output_bytes: int
    accepted_data_classes: tuple[str, ...]

    def to_contract(self) -> dict[str, Any]:
        return seal_mapping(
            {
                "contract_id": TOOL_SPEC_CONTRACT_ID,
                "tool_id": self.tool_id,
                "capability": self.capability,
                "side_effect": self.side_effect,
                "allowed_targets": list(self.allowed_targets),
                "max_output_bytes": self.max_output_bytes,
                "accepted_data_classes": list(self.accepted_data_classes),
                "tool_spec_sha256": "",
            },
            "tool_spec_sha256",
        )


class CapabilityBroker:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if not spec.tool_id or not spec.capability:
            raise ValueError("tool_id and capability required")
        if spec.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be >= 0")
        if not set(spec.accepted_data_classes).issubset(DATA_CLASSES):
            raise ValueError("unknown data class")
        if spec.tool_id in self._tools:
            raise ValueError("duplicate tool")
        self._tools[spec.tool_id] = spec

    def inspect(self) -> list[dict[str, Any]]:
        return [self._tools[key].to_contract() for key in sorted(self._tools)]

    def dispatch(
        self,
        request_value: Mapping[str, Any],
        *,
        session_authority: Mapping[str, Any],
        context_manifest: Mapping[str, Any],
        hook_receipt: Mapping[str, Any] | None,
        evaluation_tick: int,
        authorization_token: Mapping[str, Any] | None = None,
        materialization_receipt: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        request = _validate_sealed(
            request_value,
            contract_id=TOOL_REQUEST_CONTRACT_ID,
            digest_field="request_sha256",
            path="request",
            errors=errors,
        )
        manifest = _validate_sealed(
            context_manifest,
            contract_id=CONTEXT_MANIFEST_CONTRACT_ID,
            digest_field="manifest_sha256",
            path="context_manifest",
            errors=errors,
        )
        authority = _normalized_authority(session_authority)
        spec = self._tools.get(request.get("tool_id") if request else None)
        if request is None or manifest is None or spec is None:
            if spec is None:
                errors.append(_error("unknown_tool", "request.tool_id", "tool not registered"))
        else:
            if spec.capability not in set(authority["capabilities"]):
                errors.append(_error("capability_denied", "request.tool_id", spec.capability))
            if spec.tool_id not in set(authority["tools"]):
                errors.append(_error("tool_denied", "request.tool_id", spec.tool_id))
            target = request.get("target")
            if target not in set(spec.allowed_targets) or target not in set(authority["targets"]):
                errors.append(_error("target_denied", "request.target", str(target)))
            requested_refs = request.get("input_artifact_ids", [])
            if not isinstance(requested_refs, list) or not all(isinstance(item, str) and item for item in requested_refs):
                errors.append(_error("invalid_artifact_refs", "request.input_artifact_ids", "string array required"))
                requested_refs = []
            selected = {
                item.get("artifact_id"): item
                for item in manifest.get("selected_items", [])
                if isinstance(item, Mapping)
            }
            missing = set(requested_refs) - set(selected)
            if missing:
                errors.append(_error("context_reference_denied", "request.input_artifact_ids", str(sorted(missing))))
            for artifact_id in set(requested_refs) & set(selected):
                if selected[artifact_id].get("data_class") not in spec.accepted_data_classes:
                    errors.append(_error("tool_data_class_denied", "request.input_artifact_ids", artifact_id))
            materialized = None
            if requested_refs:
                if materialization_receipt is None:
                    errors.append(_error("materialization_receipt_required", "materialization_receipt", "exact loaded bytes must be attested"))
                else:
                    materialized = _validate_sealed(
                        materialization_receipt,
                        contract_id=CONTEXT_MATERIALIZATION_RECEIPT_CONTRACT_ID,
                        digest_field="receipt_sha256",
                        path="materialization_receipt",
                        errors=errors,
                    )
                    if materialized is not None:
                        if materialized.get("status") != "PASS":
                            errors.append(_error("materialization_blocked", "materialization_receipt.status", str(materialized.get("status"))))
                        if materialized.get("context_manifest_sha256") != manifest.get("manifest_sha256"):
                            errors.append(_error("materialization_manifest_mismatch", "materialization_receipt.context_manifest_sha256", "wrong manifest"))
                        if request.get("materialization_receipt_sha256") != materialized.get("receipt_sha256"):
                            errors.append(_error("request_materialization_mismatch", "request.materialization_receipt_sha256", "request must bind exact receipt"))
                        observed_tick = materialized.get("observed_at_tick")
                        if type(observed_tick) is not int or observed_tick < 0 or observed_tick > evaluation_tick:
                            errors.append(_error("invalid_materialization_time", "materialization_receipt.observed_at_tick", "must not be in the future"))
                        observed = {
                            item.get("artifact_id"): item
                            for item in materialized.get("observed_items", [])
                            if isinstance(item, Mapping)
                        }
                        unmaterialized = set(requested_refs) - set(observed)
                        if unmaterialized:
                            errors.append(_error("artifact_not_materialized", "request.input_artifact_ids", str(sorted(unmaterialized))))
                        for artifact_id in set(requested_refs) & set(observed) & set(selected):
                            if observed[artifact_id].get("content_sha256") != selected[artifact_id].get("content_sha256"):
                                errors.append(_error("materialized_digest_mismatch", "materialization_receipt.observed_items", artifact_id))
                            if observed[artifact_id].get("size_bytes") != selected[artifact_id].get("size_bytes"):
                                errors.append(_error("materialized_size_mismatch", "materialization_receipt.observed_items", artifact_id))
            output_limit = request.get("max_output_bytes", spec.max_output_bytes)
            if type(output_limit) is not int or output_limit < 0 or output_limit > spec.max_output_bytes:
                errors.append(_error("invalid_output_limit", "request.max_output_bytes", f"max {spec.max_output_bytes}"))
            if hook_receipt is not None:
                if not verify_sealed_mapping(hook_receipt, "receipt_sha256"):
                    errors.append(_error("invalid_hook_receipt", "hook_receipt", "digest mismatch"))
                elif hook_receipt.get("outcome") in {"HOLD", "DENY"}:
                    errors.append(_error("hook_blocked", "hook_receipt.outcome", str(hook_receipt.get("outcome"))))
            elif spec.side_effect:
                errors.append(_error("pre_tool_hook_required", "hook_receipt", "side effects require PRE_TOOL hook receipt"))
            if spec.side_effect:
                if authorization_token is None:
                    errors.append(_error("authorization_required", "authorization_token", "side effect requires token"))
                else:
                    result = validate_authorization_token(authorization_token, evaluation_tick, require_allow=True)
                    errors.extend({**item, "path": f"authorization_token.{item['path']}"} for item in result["errors"])
                    token = result.get("token", {})
                    payload_sha256 = request.get("payload_sha256")
                    if token.get("tool_id") != spec.tool_id:
                        errors.append(_error("token_tool_mismatch", "authorization_token.tool_id", spec.tool_id))
                    if token.get("execution_target") != request.get("target"):
                        errors.append(_error("token_target_mismatch", "authorization_token.execution_target", str(request.get("target"))))
                    if token.get("payload_sha256") != payload_sha256:
                        errors.append(_error("token_payload_mismatch", "authorization_token.payload_sha256", str(payload_sha256)))
        receipt = {
            "contract_id": TOOL_DISPATCH_RECEIPT_CONTRACT_ID,
            "request_sha256": request.get("request_sha256") if request else None,
            "tool_id": request.get("tool_id") if request else None,
            "target": request.get("target") if request else None,
            "context_manifest_sha256": manifest.get("manifest_sha256") if manifest else None,
            "materialization_receipt_sha256": materialized.get("receipt_sha256") if 'materialized' in locals() and materialized else None,
            "outcome": "ALLOW" if not errors else "DENY",
            "side_effect": spec.side_effect if spec else None,
            "errors": errors,
            "receipt_sha256": "",
        }
        return seal_mapping(receipt, "receipt_sha256")


def seal_tool_request(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("tool request must be object")
    body.setdefault("contract_id", TOOL_REQUEST_CONTRACT_ID)
    body.setdefault("materialization_receipt_sha256", None)
    body.setdefault("request_sha256", "")
    return seal_mapping(body, "request_sha256")


def seal_workflow_definition(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("workflow definition must be object")
    body.setdefault("contract_id", WORKFLOW_DEFINITION_CONTRACT_ID)
    body.setdefault("workflow_sha256", "")
    return seal_mapping(body, "workflow_sha256")


def validate_workflow_definition(value: Any, effective_config: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    workflow = _validate_sealed(
        value,
        contract_id=WORKFLOW_DEFINITION_CONTRACT_ID,
        digest_field="workflow_sha256",
        path="workflow",
        errors=errors,
    )
    config = _validate_sealed(
        effective_config,
        contract_id=HARNESS_CONFIG_CONTRACT_ID,
        digest_field="config_sha256",
        path="config",
        errors=errors,
    )
    if workflow is None or config is None:
        return {"status": "BLOCK", "errors": errors}
    for field in ("workflow_id", "name"):
        if not isinstance(workflow.get(field), str) or not workflow.get(field):
            errors.append(_error("missing_required", f"workflow.{field}", f"{field} required"))
    steps = workflow.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append(_error("invalid_steps", "workflow.steps", "non-empty array required"))
        steps = []
    ids: set[str] = set()
    deps: dict[str, set[str]] = {}
    fanout: dict[str, int] = {}
    for index, step in enumerate(steps):
        path = f"workflow.steps[{index}]"
        if not isinstance(step, Mapping):
            errors.append(_error("invalid_step", path, "object required"))
            continue
        step_id = step.get("step_id")
        if not isinstance(step_id, str) or not step_id:
            errors.append(_error("missing_step_id", f"{path}.step_id", "required"))
            continue
        if step_id in ids:
            errors.append(_error("duplicate_step_id", f"{path}.step_id", step_id))
        ids.add(step_id)
        dependencies = step.get("depends_on", [])
        if not isinstance(dependencies, list) or not all(isinstance(item, str) and item for item in dependencies):
            errors.append(_error("invalid_dependencies", f"{path}.depends_on", "string array required"))
            dependencies = []
        deps[step_id] = set(dependencies)
        for dep in dependencies:
            fanout[dep] = fanout.get(dep, 0) + 1
        mode = step.get("capability_mode", "read-only")
        if mode not in CAPABILITY_MODES:
            errors.append(_error("invalid_capability_mode", f"{path}.capability_mode", str(mode)))
        if step.get("kind") not in {"PLAN", "REVIEW", "DIFF", "AUTHORIZE", "EXECUTE", "VERIFY", "RECEIPT", "RESEARCH"}:
            errors.append(_error("invalid_step_kind", f"{path}.kind", str(step.get("kind"))))
    for step_id, dependencies in deps.items():
        unknown = dependencies - ids
        if unknown:
            errors.append(_error("unknown_dependency", f"workflow.steps.{step_id}", str(sorted(unknown))))
    # Cycle check.
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            errors.append(_error("workflow_cycle", "workflow.steps", node))
            return
        if node in visited:
            return
        visiting.add(node)
        for dep in deps.get(node, set()):
            visit(dep)
        visiting.remove(node)
        visited.add(node)

    for node in ids:
        visit(node)
    max_fanout = max(fanout.values(), default=0)
    if max_fanout > config.get("max_workflow_fanout", 0):
        errors.append(_error("workflow_fanout_exceeded", "workflow.steps", f"{max_fanout}"))
    rounds = workflow.get("max_rounds")
    if type(rounds) is not int or rounds < 1 or rounds > config.get("max_rounds", 0):
        errors.append(_error("workflow_round_limit", "workflow.max_rounds", str(rounds)))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "workflow": workflow}


class WorkflowStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteWorkflowStore:
    """Host-owned resumable workflow state with CAS transitions and receipts."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                run_id TEXT PRIMARY KEY,
                workflow_sha256 TEXT NOT NULL,
                phase TEXT NOT NULL,
                paused_from TEXT,
                version INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workflow_events (
                run_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                event_sha256 TEXT NOT NULL,
                event_json TEXT NOT NULL,
                PRIMARY KEY(run_id, seq)
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteWorkflowStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _row(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT run_id, workflow_sha256, phase, paused_from, version, state_json, updated_at FROM workflow_runs WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "run_id": row[0],
            "workflow_sha256": row[1],
            "phase": row[2],
            "paused_from": row[3],
            "version": row[4],
            "state": json.loads(row[5]),
            "updated_at": row[6],
        }

    def create(self, run_id: str, workflow: Mapping[str, Any], created_at: int) -> dict[str, Any]:
        if not isinstance(run_id, str) or not run_id:
            raise WorkflowStoreError("invalid_run_id", "run_id required")
        if not verify_sealed_mapping(workflow, "workflow_sha256"):
            raise WorkflowStoreError("invalid_workflow", "workflow digest mismatch")
        state = {
            "completed_steps": [],
            "artifacts": {},
            "attempts": {},
            "authorization_token_sha256": None,
            "verification_sha256": None,
            "final_receipt_sha256": None,
        }
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            if self._row(run_id) is not None:
                raise WorkflowStoreError("run_exists", run_id)
            self._conn.execute(
                "INSERT INTO workflow_runs(run_id, workflow_sha256, phase, paused_from, version, state_json, updated_at) VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    workflow["workflow_sha256"],
                    "NEW",
                    None,
                    0,
                    json.dumps(state, sort_keys=True, separators=(",", ":")),
                    created_at,
                ),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(run_id)
        assert result is not None
        return result

    def get(self, run_id: str) -> dict[str, Any] | None:
        return self._row(run_id)

    def _append_event(self, run_id: str, event: Mapping[str, Any]) -> None:
        seq = self._conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM workflow_events WHERE run_id=?", (run_id,)).fetchone()[0]
        body = materialize_json(event)
        if not isinstance(body, dict):
            raise WorkflowStoreError("invalid_event", "event must be object")
        body.update({"contract_id": WORKFLOW_EVENT_CONTRACT_ID, "run_id": run_id, "seq": seq, "event_sha256": ""})
        sealed = seal_mapping(body, "event_sha256")
        self._conn.execute(
            "INSERT INTO workflow_events(run_id, seq, event_sha256, event_json) VALUES(?,?,?,?)",
            (run_id, seq, sealed["event_sha256"], json.dumps(sealed, sort_keys=True, separators=(",", ":"))),
        )

    def advance(
        self,
        run_id: str,
        *,
        expected_version: int,
        event_type: str,
        artifact_sha256: str,
        observed_at: int,
        authorization_token: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        transitions = {
            ("NEW", "PLAN_ACCEPTED"): "PLANNED",
            ("PLANNED", "REVIEW_ACCEPTED"): "REVIEWED",
            ("REVIEWED", "DIFF_ACCEPTED"): "DIFF_READY",
            ("DIFF_READY", "AUTHORIZATION_ACCEPTED"): "AUTHORIZED",
            ("AUTHORIZED", "EXECUTION_STARTED"): "EXECUTING",
            ("EXECUTING", "EXECUTION_FINISHED"): "VERIFYING",
            ("VERIFYING", "VERIFICATION_ACCEPTED"): "COMPLETED",
        }
        if not _is_sha256(artifact_sha256):
            raise WorkflowStoreError("invalid_artifact_digest", "SHA-256 required")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(run_id)
            if current is None:
                raise WorkflowStoreError("unknown_run", run_id)
            if current["version"] != expected_version:
                raise WorkflowStoreError("workflow_cas_conflict", f"expected {expected_version}, observed {current['version']}")
            if current["phase"] == "PAUSED":
                raise WorkflowStoreError("workflow_paused", run_id)
            key = (current["phase"], event_type)
            if key not in transitions:
                raise WorkflowStoreError("invalid_transition", f"{current['phase']} + {event_type}")
            state = current["state"]
            if event_type == "AUTHORIZATION_ACCEPTED":
                if authorization_token is None:
                    raise WorkflowStoreError("authorization_required", "token required")
                token_result = validate_authorization_token(authorization_token, observed_at, require_allow=True)
                if token_result["status"] != "PASS":
                    raise WorkflowStoreError("invalid_authorization", str(token_result["errors"]))
                if token_result["token"]["token_sha256"] != artifact_sha256:
                    raise WorkflowStoreError("authorization_digest_mismatch", "artifact digest must be token digest")
                state["authorization_token_sha256"] = artifact_sha256
            if event_type == "EXECUTION_STARTED" and not state.get("authorization_token_sha256"):
                raise WorkflowStoreError("execution_without_authorization", run_id)
            if event_type == "VERIFICATION_ACCEPTED":
                state["verification_sha256"] = artifact_sha256
                state["final_receipt_sha256"] = canonical_sha256(
                    {
                        "run_id": run_id,
                        "workflow_sha256": current["workflow_sha256"],
                        "authorization_token_sha256": state.get("authorization_token_sha256"),
                        "verification_sha256": artifact_sha256,
                    }
                )
            state["artifacts"][event_type] = artifact_sha256
            state["completed_steps"].append(event_type)
            next_phase = transitions[key]
            next_version = current["version"] + 1
            self._append_event(
                run_id,
                {
                    "event_type": event_type,
                    "from_phase": current["phase"],
                    "to_phase": next_phase,
                    "artifact_sha256": artifact_sha256,
                    "observed_at": observed_at,
                },
            )
            self._conn.execute(
                "UPDATE workflow_runs SET phase=?, version=?, state_json=?, updated_at=? WHERE run_id=? AND version=?",
                (
                    next_phase,
                    next_version,
                    json.dumps(state, sort_keys=True, separators=(",", ":")),
                    observed_at,
                    run_id,
                    expected_version,
                ),
            )
            if self._conn.total_changes < 1:
                raise WorkflowStoreError("workflow_cas_conflict", run_id)
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row(run_id)
        assert result is not None
        return result

    def pause(self, run_id: str, expected_version: int, observed_at: int) -> dict[str, Any]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(run_id)
            if current is None:
                raise WorkflowStoreError("unknown_run", run_id)
            if current["version"] != expected_version:
                raise WorkflowStoreError("workflow_cas_conflict", run_id)
            if current["phase"] in TERMINAL_WORKFLOW_STATES or current["phase"] == "PAUSED":
                raise WorkflowStoreError("cannot_pause", current["phase"])
            self._append_event(run_id, {"event_type": "PAUSED", "from_phase": current["phase"], "to_phase": "PAUSED", "observed_at": observed_at})
            self._conn.execute(
                "UPDATE workflow_runs SET phase='PAUSED', paused_from=?, version=?, updated_at=? WHERE run_id=? AND version=?",
                (current["phase"], current["version"] + 1, observed_at, run_id, expected_version),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        return self._row(run_id) or {}

    def resume(self, run_id: str, expected_version: int, observed_at: int) -> dict[str, Any]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row(run_id)
            if current is None:
                raise WorkflowStoreError("unknown_run", run_id)
            if current["version"] != expected_version:
                raise WorkflowStoreError("workflow_cas_conflict", run_id)
            if current["phase"] != "PAUSED" or current["paused_from"] not in WORKFLOW_PHASES:
                raise WorkflowStoreError("cannot_resume", current["phase"])
            target = current["paused_from"]
            self._append_event(run_id, {"event_type": "RESUMED", "from_phase": "PAUSED", "to_phase": target, "observed_at": observed_at})
            self._conn.execute(
                "UPDATE workflow_runs SET phase=?, paused_from=NULL, version=?, updated_at=? WHERE run_id=? AND version=?",
                (target, current["version"] + 1, observed_at, run_id, expected_version),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        return self._row(run_id) or {}

    def events(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT event_json FROM workflow_events WHERE run_id=? ORDER BY seq", (run_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]


def classify_harness_failure(
    *,
    error_kind: str,
    attempt: int,
    max_attempts: int,
    http_status: int | None = None,
) -> dict[str, Any]:
    """Return a bounded host-owned recovery decision for common harness failures."""

    if type(attempt) is not int or attempt < 0 or type(max_attempts) is not int or max_attempts < 0:
        raise ValueError("attempt and max_attempts must be integers >= 0")
    outcome = "DENY"
    reason = "UNKNOWN_FAILURE_FAIL_CLOSED"
    consumes_retry_budget = False
    if error_kind == "CONTEXT_OVERFLOW":
        outcome, reason = "COMPACT", "CONTEXT_COMPACTION_REQUIRED"
    elif error_kind == "BUDGET_EXCEEDED":
        outcome, reason = "HOLD", "OPERATOR_BUDGET_REVIEW_REQUIRED"
    elif error_kind == "AUTH_EXPIRED" or http_status == 401:
        outcome, reason = "HOLD", "AUTH_REFRESH_REQUIRED"
    elif error_kind == "DISK_FULL":
        outcome, reason = "DENY", "DURABLE_STATE_UNAVAILABLE"
    elif error_kind in {"TRANSIENT_TRANSPORT", "MODEL_OVERLOAD"} or (isinstance(http_status, int) and 500 <= http_status <= 599):
        consumes_retry_budget = True
        if attempt < max_attempts:
            outcome, reason = "RETRY", "BOUNDED_TRANSIENT_RETRY"
        else:
            outcome, reason = "HOLD", "RETRY_BUDGET_EXHAUSTED"
    decision = {
        "contract_id": RETRY_DECISION_CONTRACT_ID,
        "error_kind": error_kind,
        "http_status": http_status,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "outcome": outcome,
        "reason": reason,
        "consumes_retry_budget": consumes_retry_budget,
        "decision_sha256": "",
    }
    return seal_mapping(decision, "decision_sha256")


def make_headless_event(
    *,
    session_id: str,
    turn_id: str,
    seq: int,
    event_type: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not session_id or not turn_id:
        raise ValueError("session_id and turn_id required")
    if type(seq) is not int or seq < 1:
        raise ValueError("seq must be integer >= 1")
    if event_type not in HEADLESS_EVENT_TYPES:
        raise ValueError("unknown event type")
    event = {
        "contract_id": HEADLESS_EVENT_CONTRACT_ID,
        "session_id": session_id,
        "turn_id": turn_id,
        "seq": seq,
        "event_type": event_type,
        "payload": materialize_json(payload),
        "event_sha256": "",
    }
    return seal_mapping(event, "event_sha256")


def validate_headless_stream(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    previous_digest: str | None = None
    expected_seq = 1
    session_id: str | None = None
    turn_id: str | None = None
    for index, raw in enumerate(events):
        event = _validate_sealed(
            raw,
            contract_id=HEADLESS_EVENT_CONTRACT_ID,
            digest_field="event_sha256",
            path=f"events[{index}]",
            errors=errors,
        )
        if event is None:
            continue
        if event.get("seq") != expected_seq:
            errors.append(_error("event_sequence_gap", f"events[{index}].seq", f"expected {expected_seq}"))
        expected_seq += 1
        if event.get("event_type") not in HEADLESS_EVENT_TYPES:
            errors.append(_error("unknown_event_type", f"events[{index}].event_type", str(event.get("event_type"))))
        if session_id is None:
            session_id = event.get("session_id")
            turn_id = event.get("turn_id")
        elif event.get("session_id") != session_id or event.get("turn_id") != turn_id:
            errors.append(_error("stream_scope_mismatch", f"events[{index}]", "session/turn changed"))
        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            errors.append(_error("invalid_event_payload", f"events[{index}].payload", "object required"))
        if previous_digest is not None and isinstance(payload, Mapping):
            declared = payload.get("previous_event_sha256")
            if declared is not None and declared != previous_digest:
                errors.append(_error("event_chain_mismatch", f"events[{index}].payload.previous_event_sha256", previous_digest))
        previous_digest = event.get("event_sha256")
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "event_count": len(events)}


def make_acp_style_message(
    *,
    protocol_version: str,
    request_id: str,
    method: str,
    session_id: str | None,
    params: Mapping[str, Any],
) -> dict[str, Any]:
    if method not in ACP_STYLE_METHODS:
        raise ValueError("unsupported ACP-style method")
    if not protocol_version or not request_id:
        raise ValueError("protocol_version and request_id required")
    message = {
        "contract_id": ACP_MESSAGE_CONTRACT_ID,
        "compatibility_claim": "REFERENCE_ONLY_NOT_ACP_CERTIFIED",
        "protocol_version": protocol_version,
        "request_id": request_id,
        "method": method,
        "session_id": session_id,
        "params": materialize_json(params),
        "message_sha256": "",
    }
    return seal_mapping(message, "message_sha256")


def validate_acp_style_message(value: Any) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    message = _validate_sealed(
        value,
        contract_id=ACP_MESSAGE_CONTRACT_ID,
        digest_field="message_sha256",
        path="message",
        errors=errors,
    )
    if message is None:
        return {"status": "BLOCK", "errors": errors}
    if message.get("compatibility_claim") != "REFERENCE_ONLY_NOT_ACP_CERTIFIED":
        errors.append(_error("invalid_compatibility_claim", "message.compatibility_claim", "reference-only marker required"))
    if message.get("method") not in ACP_STYLE_METHODS:
        errors.append(_error("unsupported_method", "message.method", str(message.get("method"))))
    if message.get("method") not in {"initialize", "session/new"} and not isinstance(message.get("session_id"), str):
        errors.append(_error("session_required", "message.session_id", "session_id required"))
    if not isinstance(message.get("params"), Mapping):
        errors.append(_error("invalid_params", "message.params", "object required"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "message": message}


def inspect_harness(
    *,
    config: Mapping[str, Any],
    skill_registry: SkillRegistry,
    plugin_registry: PluginRegistry,
    tool_broker: CapabilityBroker,
    discovered_hooks: Sequence[str],
    discovered_workflows: Sequence[str],
) -> dict[str, Any]:
    if not verify_sealed_mapping(config, "config_sha256"):
        raise ValueError("invalid config")
    report = {
        "contract_id": INSPECTION_REPORT_CONTRACT_ID,
        "config_sha256": config["config_sha256"],
        "config_layers": list(config.get("applied_layers", [])),
        "requirement_sources": list(config.get("requirement_sources", [])),
        "skills": sorted(skill_registry._skills.keys()),
        "active_plugins": plugin_registry.installed(),
        "tools": tool_broker.inspect(),
        "hooks": sorted(set(discovered_hooks)),
        "workflows": sorted(set(discovered_workflows)),
        "mcp_servers": list(config.get("mcp_servers", [])),
        "whole_repo_upload": False,
        "inspection_sha256": "",
    }
    return seal_mapping(report, "inspection_sha256")


__all__ = [
    "ACP_MESSAGE_CONTRACT_ID",
    "CapabilityBroker",
    "RETRY_DECISION_CONTRACT_ID",
    "CONTEXT_MANIFEST_CONTRACT_ID",
    "HARNESS_CONFIG_CONTRACT_ID",
    "HEADLESS_EVENT_CONTRACT_ID",
    "HOOK_RESULT_CONTRACT_ID",
    "PluginRegistry",
    "PluginRegistryError",
    "SQLiteWorkflowStore",
    "SkillRegistry",
    "SkillRegistryError",
    "SUBAGENT_CONTRACT_ID",
    "TOOL_REQUEST_CONTRACT_ID",
    "ToolSpec",
    "WorkflowStoreError",
    "assemble_context",
    "build_subagent_contract",
    "classify_harness_failure",
    "compact_context_manifest",
    "evaluate_hook_pipeline",
    "fork_session",
    "inspect_harness",
    "make_acp_style_message",
    "make_headless_event",
    "normalize_logical_path",
    "resolve_harness_config",
    "resolve_mcp_inheritance",
    "seal_hook_result",
    "seal_tool_request",
    "seal_workflow_definition",
    "validate_acp_style_message",
    "validate_headless_stream",
    "validate_workflow_definition",
]
