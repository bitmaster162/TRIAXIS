"""TRIAXIS v3.24 cross-harness governance contracts.

This module clean-room adapts high-value runtime patterns observed in modern
agent harnesses:

* tiered allow/deny/ask policy evaluation and hidden denied tools;
* one-shot sandbox expansion instead of broad permanent escalation;
* pre-approval, pre-execution and post-execution tool guardrails;
* durable interrupt/resume/fork state;
* filtered handoffs with explicit context transfer;
* digest-chained traces and action/observation correlation.

The implementation is provider-neutral and keeps TRIAXIS invariants:
configuration, prompts, policies and agent handoffs cannot mint authority;
headless uncertainty fails closed; persistent state transitions use CAS.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import json
import re
import shlex
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from .integrity import canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

TOOL_POLICY_RULE_CONTRACT_ID = "TRIAXIS_TOOL_POLICY_RULE_v2"
TOOL_POLICY_DECISION_CONTRACT_ID = "TRIAXIS_TOOL_POLICY_DECISION_v2"
TARGET_IDENTITY_CONTRACT_ID = "TRIAXIS_CANONICAL_TOOL_TARGET_v1"
PERMISSION_DELTA_CONTRACT_ID = "TRIAXIS_ONE_SHOT_PERMISSION_DELTA_v1"
GUARDRAIL_RESULT_CONTRACT_ID = "TRIAXIS_TOOL_GUARDRAIL_RESULT_v1"
GUARDRAIL_PIPELINE_CONTRACT_ID = "TRIAXIS_TOOL_GUARDRAIL_PIPELINE_v1"
HANDOFF_CONTEXT_CONTRACT_ID = "TRIAXIS_FILTERED_HANDOFF_CONTEXT_v1"
INTERRUPT_CHECKPOINT_CONTRACT_ID = "TRIAXIS_INTERRUPT_CHECKPOINT_v1"
TRACE_SPAN_CONTRACT_ID = "TRIAXIS_TRACE_SPAN_v1"
TRACE_CHAIN_CONTRACT_ID = "TRIAXIS_TRACE_CHAIN_v1"
ACTION_OBSERVATION_EVENT_CONTRACT_ID = "TRIAXIS_ACTION_OBSERVATION_EVENT_v1"

POLICY_TIERS = {"DEFAULT": 1, "EXTENSION": 2, "PROJECT": 3, "USER": 4, "ADMIN": 5}
POLICY_DECISIONS = {"ALLOW", "ASK_USER", "DENY"}
DECISION_SEVERITY = {"ALLOW": 1, "ASK_USER": 2, "DENY": 3}
RUN_MODES = {"PLAN", "DEFAULT", "AUTO_EDIT", "HEADLESS"}
GUARDRAIL_PHASES = {"PRE_APPROVAL", "PRE_EXECUTION", "POST_EXECUTION"}
GUARDRAIL_OUTCOMES = {"PASS", "TRIPWIRE", "REWRITE", "HOLD"}
TRACE_SPAN_TYPES = {"RUN", "TURN", "MODEL", "TOOL", "HANDOFF", "GUARDRAIL", "INTERRUPT", "CUSTOM"}
EVENT_KINDS = {"ACTION", "OBSERVATION"}


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


class TargetValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_DANGEROUS_ENCODED = {0x2F, 0x5C, 0x25, 0x2E}


def _normalize_percent_component(value: str, *, field: str) -> str:
    if "\\" in value:
        raise TargetValidationError("raw_backslash_denied", f"{field} contains backslash")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise TargetValidationError("target_control_character", f"{field} contains control character")
    if any(ch.isspace() for ch in value):
        raise TargetValidationError("target_whitespace_denied", f"{field} contains raw whitespace")
    out: list[str] = []
    index = 0
    while index < len(value):
        ch = value[index]
        if ch != "%":
            out.append(ch)
            index += 1
            continue
        if index + 2 >= len(value) or not all(c in "0123456789abcdefABCDEF" for c in value[index + 1:index + 3]):
            raise TargetValidationError("malformed_percent_encoding", f"{field} contains malformed percent encoding")
        byte = int(value[index + 1:index + 3], 16)
        if byte in _DANGEROUS_ENCODED:
            raise TargetValidationError("encoded_separator_or_traversal_denied", f"{field} contains encoded separator, percent or dot")
        if byte < 0x20 or byte == 0x7F:
            raise TargetValidationError("encoded_control_character", f"{field} contains encoded control character")
        decoded = chr(byte)
        out.append(decoded if decoded in _UNRESERVED else f"%{byte:02X}")
        index += 3
    return "".join(out)


def _reject_dot_segments(path: str) -> None:
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise TargetValidationError("path_traversal_segment", "target contains dot traversal segment")


def canonicalize_tool_target(value: str, *, prefix: bool = False) -> dict[str, Any]:
    """Create a strict, provider-neutral target identity.

    The function intentionally rejects ambiguous forms rather than relying on a
    downstream proxy/runtime to decode them consistently. Policy prefixes may
    not contain query or fragment components.
    """

    if not isinstance(value, str) or not value:
        raise TargetValidationError("target_required", "target must be a non-empty string")
    if len(value) > 4096:
        raise TargetValidationError("target_too_long", "target exceeds 4096 bytes")
    if "#" in value:
        raise TargetValidationError("target_fragment_denied", "fragments are not authorization identity")

    if "://" in value:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise TargetValidationError("invalid_url_authority", str(exc)) from exc
        scheme = parsed.scheme.lower()
        if not _SCHEME.fullmatch(scheme):
            raise TargetValidationError("invalid_target_scheme", scheme)
        if parsed.username is not None or parsed.password is not None:
            raise TargetValidationError("url_userinfo_denied", "userinfo is not allowed")
        if not parsed.hostname:
            raise TargetValidationError("url_host_required", "URL host required")
        try:
            host = parsed.hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetValidationError("invalid_idna_host", str(exc)) from exc
        if host.endswith("."):
            host = host[:-1]
        if not host:
            raise TargetValidationError("url_host_required", "URL host required")
        path = _normalize_percent_component(parsed.path or "/", field="path")
        _reject_dot_segments(path)
        query = _normalize_percent_component(parsed.query, field="query") if parsed.query else ""
        if prefix and query:
            raise TargetValidationError("policy_prefix_query_denied", "policy prefixes cannot include query")
        default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        authority = host if port is None or default_port else f"{host}:{port}"
        canonical = f"{scheme}://{authority}{path}"
        if query:
            canonical += f"?{query}"
        body = {
            "contract_id": TARGET_IDENTITY_CONTRACT_ID,
            "kind": "URL",
            "scheme": scheme,
            "authority": authority,
            "path": path,
            "query": query,
            "canonical_target": canonical,
            "target_sha256": "",
        }
        return seal_mapping(body, "target_sha256")

    if ":" not in value:
        raise TargetValidationError("opaque_target_scheme_required", "opaque target requires scheme prefix")
    scheme, rest = value.split(":", 1)
    scheme = scheme.lower()
    if not _SCHEME.fullmatch(scheme):
        raise TargetValidationError("invalid_target_scheme", scheme)
    if "?" in rest and prefix:
        raise TargetValidationError("policy_prefix_query_denied", "policy prefixes cannot include query")
    normalized = _normalize_percent_component(rest, field="opaque_target")
    path_part = normalized.split("?", 1)[0]
    _reject_dot_segments(path_part)
    canonical = f"{scheme}:{normalized}"
    body = {
        "contract_id": TARGET_IDENTITY_CONTRACT_ID,
        "kind": "OPAQUE",
        "scheme": scheme,
        "authority": None,
        "path": path_part,
        "query": normalized.split("?", 1)[1] if "?" in normalized else "",
        "canonical_target": canonical,
        "target_sha256": "",
    }
    return seal_mapping(body, "target_sha256")


def _target_prefix_matches(prefix_identity: Mapping[str, Any], target_identity: Mapping[str, Any]) -> bool:
    if prefix_identity.get("kind") != target_identity.get("kind"):
        return False
    if prefix_identity.get("scheme") != target_identity.get("scheme"):
        return False
    if prefix_identity.get("authority") != target_identity.get("authority"):
        return False
    prefix_path = str(prefix_identity.get("path", ""))
    target_path = str(target_identity.get("path", ""))
    if prefix_identity.get("kind") == "URL":
        if prefix_path.endswith("/"):
            return target_path.startswith(prefix_path)
        return target_path == prefix_path or target_path.startswith(prefix_path + "/")
    if prefix_path == "":
        return True
    if prefix_path.endswith("/"):
        return target_path.startswith(prefix_path)
    return target_path == prefix_path or target_path.startswith(prefix_path + "/")


def seal_tool_policy_rule(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("policy rule must be object")
    for field in ("rule_id", "source_id"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    tier = body.get("tier")
    if tier not in POLICY_TIERS:
        raise ValueError("unknown policy tier")
    decision = body.get("decision")
    if decision not in POLICY_DECISIONS:
        raise ValueError("unknown policy decision")
    if tier == "EXTENSION" and decision == "ALLOW":
        raise ValueError("extension policy cannot grant ALLOW")
    priority = body.get("priority", 0)
    if type(priority) is not int:
        raise TypeError("priority must be integer")
    tools = body.get("tool_ids", ["*"])
    if not isinstance(tools, list) or not tools or not all(isinstance(x, str) and x for x in tools):
        raise ValueError("tool_ids must be non-empty string array")
    body["tool_ids"] = sorted(set(tools))
    capabilities = body.get("capabilities", [])
    if not isinstance(capabilities, list) or not all(isinstance(x, str) and x for x in capabilities):
        raise ValueError("capabilities must be string array")
    body["capabilities"] = sorted(set(capabilities))
    modes = body.get("modes", sorted(RUN_MODES))
    if not isinstance(modes, list) or not modes or not set(modes).issubset(RUN_MODES):
        raise ValueError("invalid modes")
    body["modes"] = sorted(set(modes))
    mutating = body.get("mutating")
    if mutating is not None and type(mutating) is not bool:
        raise TypeError("mutating must be boolean or null")
    target_prefixes = body.get("target_prefixes", [])
    if not isinstance(target_prefixes, list) or not all(isinstance(x, str) and x for x in target_prefixes):
        raise ValueError("target_prefixes must be string array")
    body["target_prefixes"] = sorted({
        canonicalize_tool_target(item, prefix=True)["canonical_target"] for item in target_prefixes
    })
    body.setdefault("contract_id", TOOL_POLICY_RULE_CONTRACT_ID)
    body.setdefault("rule_sha256", "")
    return seal_mapping(body, "rule_sha256")


def _rule_matches(
    rule: Mapping[str, Any],
    request: Mapping[str, Any],
    mode: str,
    target_identity: Mapping[str, Any],
) -> bool:
    if mode not in set(rule.get("modes", [])):
        return False
    tool_id = request.get("tool_id")
    tools = set(rule.get("tool_ids", []))
    if "*" not in tools and tool_id not in tools:
        return False
    capabilities = set(rule.get("capabilities", []))
    if capabilities and request.get("capability") not in capabilities:
        return False
    mutating = rule.get("mutating")
    if mutating is not None and request.get("mutating") is not mutating:
        return False
    prefixes = rule.get("target_prefixes", [])
    if prefixes:
        identities = [canonicalize_tool_target(item, prefix=True) for item in prefixes]
        if not any(_target_prefix_matches(identity, target_identity) for identity in identities):
            return False
    return True


def evaluate_tool_policy(
    rules: Sequence[Mapping[str, Any]],
    tool_request: Mapping[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    """Evaluate tiered policy with deterministic conflict resolution.

    Highest tier wins. Within a tier, highest priority wins. At equal priority,
    DENY > ASK_USER > ALLOW. In HEADLESS mode ASK_USER becomes DENY. A global
    deny hides the tool from model discovery to reduce both attack surface and
    context usage.
    """

    if mode not in RUN_MODES:
        raise ValueError("unknown run mode")
    request = materialize_json(tool_request)
    if not isinstance(request, dict):
        raise TypeError("tool_request must be object")
    for field in ("request_sha256", "tool_id", "capability", "target"):
        if not isinstance(request.get(field), str) or not request.get(field):
            raise ValueError(f"tool_request.{field} required")
    if not _is_sha256(request["request_sha256"]):
        raise ValueError("request_sha256 required")
    if type(request.get("mutating")) is not bool:
        raise TypeError("tool_request.mutating must be bool")

    target_errors: list[str] = []
    target_identity: dict[str, Any] | None = None
    try:
        target_identity = canonicalize_tool_target(request["target"])
    except TargetValidationError as exc:
        target_errors.append(exc.code)

    candidates: list[dict[str, Any]] = []
    for raw in rules:
        rule = materialize_json(raw)
        if not isinstance(rule, dict) or not verify_sealed_mapping(rule, "rule_sha256"):
            raise ValueError("invalid policy rule")
        if target_identity is not None and _rule_matches(rule, request, mode, target_identity):
            candidates.append(rule)
    if target_errors:
        decision = "DENY"
        selected = None
    elif not candidates:
        decision = "ASK_USER" if mode != "HEADLESS" else "DENY"
        selected = None
    else:
        candidates.sort(
            key=lambda r: (
                POLICY_TIERS[r["tier"]],
                r["priority"],
                DECISION_SEVERITY[r["decision"]],
                r["rule_id"],
            ),
            reverse=True,
        )
        selected = candidates[0]
        decision = selected["decision"]
        if mode == "HEADLESS" and decision == "ASK_USER":
            decision = "DENY"
    global_deny = bool(
        decision == "DENY"
        and selected
        and selected.get("tool_ids") in ([request["tool_id"]], ["*"])
        and not selected.get("capabilities")
        and selected.get("mutating") is None
        and not selected.get("target_prefixes")
    )
    body = {
        "contract_id": TOOL_POLICY_DECISION_CONTRACT_ID,
        "request_sha256": request["request_sha256"],
        "original_target_sha256": canonical_sha256(request["target"]),
        "canonical_target": None if target_identity is None else target_identity["canonical_target"],
        "canonical_target_sha256": None if target_identity is None else target_identity["target_sha256"],
        "target_validation_status": "PASS" if not target_errors else "BLOCK",
        "target_validation_error_codes": sorted(target_errors),
        "mode": mode,
        "decision": decision,
        "selected_rule_sha256": None if selected is None else selected["rule_sha256"],
        "selected_rule_id": None if selected is None else selected["rule_id"],
        "matched_rule_sha256s": sorted(rule["rule_sha256"] for rule in candidates),
        "model_visibility": "HIDDEN" if global_deny else "VISIBLE",
        "decision_sha256": "",
    }
    return seal_mapping(body, "decision_sha256")


_FORBIDDEN_COMPLEX_SHELL = re.compile(r"[`]|\$\(|\$\{|[<>]|(?<!\\)[*?\[]")
_CONTROL_OPERATOR = re.compile(r"(\&\&|\|\||[|;])")


def split_shell_segments(command: str) -> list[list[str]]:
    """Conservatively split shell commands for independent policy checks.

    Advanced shell syntax is rejected rather than interpreted broadly. This
    follows the useful principle that persistent command rules should apply to
    simple categorical prefixes, not arbitrary shell programs.
    """

    if not isinstance(command, str) or not command.strip():
        raise ValueError("command required")
    if _FORBIDDEN_COMPLEX_SHELL.search(command):
        raise ValueError("advanced shell syntax requires exact one-shot approval")
    raw_segments = [part.strip() for part in _CONTROL_OPERATOR.split(command) if part.strip() and not _CONTROL_OPERATOR.fullmatch(part)]
    segments: list[list[str]] = []
    for raw in raw_segments:
        tokens = shlex.split(raw, posix=True)
        if not tokens:
            raise ValueError("empty command segment")
        if "=" in tokens[0] and not tokens[0].startswith(("./", "/")):
            raise ValueError("environment assignment requires exact one-shot approval")
        segments.append(tokens)
    return segments


def seal_one_shot_permission_delta(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("permission delta must be object")
    for field in ("grant_id", "request_sha256", "approval_sha256", "nonce"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    if not _is_sha256(body["request_sha256"]) or not _is_sha256(body["approval_sha256"]):
        raise ValueError("request and approval digests required")
    if body.get("scope") != "ONCE":
        raise ValueError("only ONCE permission deltas are supported")
    for field in ("additional_read_paths", "additional_write_paths", "network_destinations"):
        items = body.get(field, [])
        if not isinstance(items, list) or not all(isinstance(x, str) and x for x in items):
            raise ValueError(f"{field} must be string array")
        body[field] = sorted(set(items))
    issued = body.get("issued_at_tick")
    expires = body.get("expires_at_tick")
    if type(issued) is not int or type(expires) is not int or issued < 0 or expires <= issued:
        raise ValueError("invalid permission window")
    body.setdefault("contract_id", PERMISSION_DELTA_CONTRACT_ID)
    body.setdefault("delta_sha256", "")
    return seal_mapping(body, "delta_sha256")


class PermissionDeltaLedger:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS consumed_permission_deltas (delta_sha256 TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, consumed_at INTEGER NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def consume(self, delta: Mapping[str, Any], *, request_sha256: str, approval_sha256: str, evaluation_tick: int) -> dict[str, Any]:
        obj = materialize_json(delta)
        if not isinstance(obj, dict) or not verify_sealed_mapping(obj, "delta_sha256"):
            return {"status": "BLOCK", "errors": [_error("invalid_permission_delta", "delta", "sealed delta required")]}
        errors: list[dict[str, str]] = []
        if obj.get("request_sha256") != request_sha256:
            errors.append(_error("permission_request_mismatch", "delta.request_sha256", request_sha256))
        if obj.get("approval_sha256") != approval_sha256:
            errors.append(_error("permission_approval_mismatch", "delta.approval_sha256", approval_sha256))
        if obj.get("scope") != "ONCE":
            errors.append(_error("permission_scope_denied", "delta.scope", "ONCE required"))
        if type(obj.get("issued_at_tick")) is not int or type(obj.get("expires_at_tick")) is not int or obj["issued_at_tick"] > evaluation_tick or evaluation_tick >= obj["expires_at_tick"]:
            errors.append(_error("permission_delta_expired", "delta.expires_at_tick", str(evaluation_tick)))
        if errors:
            return {"status": "BLOCK", "errors": errors}
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO consumed_permission_deltas(delta_sha256, nonce, consumed_at) VALUES(?,?,?)",
                (obj["delta_sha256"], obj["nonce"], evaluation_tick),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            self._conn.rollback()
            return {"status": "BLOCK", "errors": [_error("permission_delta_replay", "delta.nonce", obj["nonce"])]}
        return {"status": "PASS", "errors": [], "delta_sha256": obj["delta_sha256"]}


def seal_guardrail_result(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("guardrail result must be object")
    if body.get("phase") not in GUARDRAIL_PHASES:
        raise ValueError("unknown guardrail phase")
    if body.get("outcome") not in GUARDRAIL_OUTCOMES:
        raise ValueError("unknown guardrail outcome")
    for field in ("guardrail_id", "request_sha256"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    if not _is_sha256(body["request_sha256"]):
        raise ValueError("request_sha256 required")
    observed = body.get("observed_at_tick")
    if type(observed) is not int or observed < 0:
        raise ValueError("observed_at_tick integer required")
    replacement = body.get("replacement_output_sha256")
    if replacement is not None and not _is_sha256(replacement):
        raise ValueError("replacement_output_sha256 invalid")
    body.setdefault("contract_id", GUARDRAIL_RESULT_CONTRACT_ID)
    body.setdefault("result_sha256", "")
    return seal_mapping(body, "result_sha256")


def evaluate_guardrail_pipeline(
    *,
    request_sha256: str,
    mutating: bool,
    approval_sha256: str | None,
    pre_approval_results: Sequence[Mapping[str, Any]],
    pre_execution_results: Sequence[Mapping[str, Any]],
    post_execution_results: Sequence[Mapping[str, Any]],
    execution_output_sha256: str | None,
    evaluation_tick: int,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    normalized: list[dict[str, Any]] = []
    grouped = {
        "PRE_APPROVAL": pre_approval_results,
        "PRE_EXECUTION": pre_execution_results,
        "POST_EXECUTION": post_execution_results,
    }
    for expected_phase, rows in grouped.items():
        for index, raw in enumerate(rows):
            row = materialize_json(raw)
            if not isinstance(row, dict) or not verify_sealed_mapping(row, "result_sha256"):
                errors.append(_error("invalid_guardrail_result", f"{expected_phase}[{index}]", "sealed result required"))
                continue
            normalized.append(row)
            if row.get("phase") != expected_phase:
                errors.append(_error("guardrail_phase_mismatch", f"{expected_phase}[{index}].phase", expected_phase))
            if row.get("request_sha256") != request_sha256:
                errors.append(_error("guardrail_request_mismatch", f"{expected_phase}[{index}].request_sha256", request_sha256))
            if type(row.get("observed_at_tick")) is not int or row["observed_at_tick"] > evaluation_tick:
                errors.append(_error("guardrail_time_invalid", f"{expected_phase}[{index}].observed_at_tick", str(evaluation_tick)))
            if row.get("outcome") in {"TRIPWIRE", "HOLD"}:
                errors.append(_error("guardrail_tripwire", f"{expected_phase}[{index}].outcome", row.get("guardrail_id", "")))
    if mutating:
        if not pre_approval_results:
            errors.append(_error("pre_approval_guardrail_required", "pre_approval_results", "mutating tool requires pre-approval guardrail"))
        if not approval_sha256 or not _is_sha256(approval_sha256):
            errors.append(_error("approval_required", "approval_sha256", "mutating tool requires exact approval"))
        if not pre_execution_results:
            errors.append(_error("pre_execution_recheck_required", "pre_execution_results", "guardrails must re-run after approval"))
        if pre_approval_results and pre_execution_results:
            pre_approval_ticks = [
                row["observed_at_tick"]
                for row in normalized
                if row.get("phase") == "PRE_APPROVAL" and type(row.get("observed_at_tick")) is int
            ]
            pre_execution_ticks = [
                row["observed_at_tick"]
                for row in normalized
                if row.get("phase") == "PRE_EXECUTION" and type(row.get("observed_at_tick")) is int
            ]
            if pre_approval_ticks and pre_execution_ticks and min(pre_execution_ticks) < max(pre_approval_ticks):
                errors.append(_error("guardrail_temporal_order", "pre_execution_results", "pre-execution must follow pre-approval"))
    if execution_output_sha256 is not None and not _is_sha256(execution_output_sha256):
        errors.append(_error("invalid_execution_output", "execution_output_sha256", "SHA-256 required"))
    if execution_output_sha256 is not None and not post_execution_results:
        errors.append(_error("post_execution_guardrail_required", "post_execution_results", "observed output requires post guardrail"))
    replacements = [row["replacement_output_sha256"] for row in normalized if row.get("outcome") == "REWRITE" and row.get("replacement_output_sha256")]
    if len(set(replacements)) > 1:
        errors.append(_error("guardrail_rewrite_conflict", "post_execution_results", "multiple replacement outputs"))
    body = {
        "contract_id": GUARDRAIL_PIPELINE_CONTRACT_ID,
        "request_sha256": request_sha256,
        "approval_sha256": approval_sha256,
        "mutating": mutating,
        "pre_approval_result_sha256s": [row["result_sha256"] for row in normalized if row.get("phase") == "PRE_APPROVAL"],
        "pre_execution_result_sha256s": [row["result_sha256"] for row in normalized if row.get("phase") == "PRE_EXECUTION"],
        "post_execution_result_sha256s": [row["result_sha256"] for row in normalized if row.get("phase") == "POST_EXECUTION"],
        "execution_output_sha256": execution_output_sha256,
        "effective_output_sha256": replacements[0] if replacements else execution_output_sha256,
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "pipeline_sha256": "",
    }
    return seal_mapping(body, "pipeline_sha256")


def make_filtered_handoff_context(
    *,
    source_session_id: str,
    destination_agent_id: str,
    source_context_manifest_sha256: str,
    allowed_artifact_ids: Sequence[str],
    summary_sha256: str | None,
    include_tool_history: bool,
    authority_checkpoint_sha256: str,
) -> dict[str, Any]:
    if not all(isinstance(x, str) and x for x in (source_session_id, destination_agent_id)):
        raise ValueError("session and destination required")
    for digest in (source_context_manifest_sha256, authority_checkpoint_sha256):
        if not _is_sha256(digest):
            raise ValueError("context and authority digests required")
    if summary_sha256 is not None and not _is_sha256(summary_sha256):
        raise ValueError("summary digest invalid")
    artifacts = sorted(set(allowed_artifact_ids))
    if not all(isinstance(x, str) and x for x in artifacts):
        raise ValueError("allowed artifacts invalid")
    body = {
        "contract_id": HANDOFF_CONTEXT_CONTRACT_ID,
        "source_session_id": source_session_id,
        "destination_agent_id": destination_agent_id,
        "source_context_manifest_sha256": source_context_manifest_sha256,
        "allowed_artifact_ids": artifacts,
        "summary_sha256": summary_sha256,
        "include_tool_history": bool(include_tool_history),
        "authority_checkpoint_sha256": authority_checkpoint_sha256,
        "implicit_context_inheritance": False,
        "implicit_authority_inheritance": False,
        "handoff_sha256": "",
    }
    return seal_mapping(body, "handoff_sha256")


class InterruptStoreError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteInterruptStore:
    """Durable interrupt/resume/fork store with exact CAS and ancestry."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS interrupt_checkpoints (
              checkpoint_id TEXT PRIMARY KEY,
              thread_id TEXT NOT NULL,
              run_id TEXT NOT NULL,
              parent_checkpoint_id TEXT,
              state_sha256 TEXT NOT NULL,
              status TEXT NOT NULL,
              version INTEGER NOT NULL,
              payload_json TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              resumed_at INTEGER,
              FOREIGN KEY(parent_checkpoint_id) REFERENCES interrupt_checkpoints(checkpoint_id)
            );
            CREATE INDEX IF NOT EXISTS idx_interrupt_thread ON interrupt_checkpoints(thread_id, created_at);
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def create_interrupt(
        self,
        *,
        checkpoint_id: str,
        thread_id: str,
        run_id: str,
        parent_checkpoint_id: str | None,
        state: Mapping[str, Any],
        interrupt_payload: Mapping[str, Any],
        created_at: int,
        allow_cross_thread_parent: bool = False,
    ) -> dict[str, Any]:
        state_obj = materialize_json(state)
        payload = materialize_json(interrupt_payload)
        if not isinstance(state_obj, dict) or not isinstance(payload, dict):
            raise TypeError("state and payload must be objects")
        state_sha = canonical_sha256(state_obj)
        body = {
            "contract_id": INTERRUPT_CHECKPOINT_CONTRACT_ID,
            "checkpoint_id": checkpoint_id,
            "thread_id": thread_id,
            "run_id": run_id,
            "parent_checkpoint_id": parent_checkpoint_id,
            "state_sha256": state_sha,
            "status": "WAITING",
            "version": 1,
            "interrupt_payload": payload,
            "created_at": created_at,
            "resumed_at": None,
            "checkpoint_sha256": "",
        }
        sealed = seal_mapping(body, "checkpoint_sha256")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            if parent_checkpoint_id is not None:
                parent = self._conn.execute("SELECT thread_id FROM interrupt_checkpoints WHERE checkpoint_id=?", (parent_checkpoint_id,)).fetchone()
                if parent is None:
                    raise InterruptStoreError("unknown_parent_checkpoint", parent_checkpoint_id)
                if parent[0] != thread_id and not allow_cross_thread_parent:
                    raise InterruptStoreError("cross_thread_parent", parent_checkpoint_id)
            self._conn.execute(
                "INSERT INTO interrupt_checkpoints VALUES(?,?,?,?,?,?,?,?,?,?)",
                (checkpoint_id, thread_id, run_id, parent_checkpoint_id, state_sha, "WAITING", 1, json.dumps(sealed, sort_keys=True), created_at, None),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return sealed

    def get(self, checkpoint_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT payload_json FROM interrupt_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def resume(self, checkpoint_id: str, *, expected_version: int, resume_value: Mapping[str, Any], resumed_at: int) -> dict[str, Any]:
        resume_obj = materialize_json(resume_value)
        if not isinstance(resume_obj, dict):
            raise TypeError("resume value must be object")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT payload_json, status, version FROM interrupt_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)).fetchone()
            if row is None:
                raise InterruptStoreError("unknown_checkpoint", checkpoint_id)
            payload, status, version = json.loads(row[0]), row[1], row[2]
            if version != expected_version:
                raise InterruptStoreError("interrupt_cas_conflict", f"expected {expected_version}, observed {version}")
            if status != "WAITING":
                raise InterruptStoreError("checkpoint_not_waiting", status)
            payload["status"] = "RESUMED"
            payload["version"] = version + 1
            payload["resumed_at"] = resumed_at
            payload["resume_value_sha256"] = canonical_sha256(resume_obj)
            payload["checkpoint_sha256"] = ""
            payload = seal_mapping(payload, "checkpoint_sha256")
            cur = self._conn.execute(
                "UPDATE interrupt_checkpoints SET status='RESUMED', version=?, payload_json=?, resumed_at=? WHERE checkpoint_id=? AND version=?",
                (version + 1, json.dumps(payload, sort_keys=True), resumed_at, checkpoint_id, version),
            )
            if cur.rowcount != 1:
                raise InterruptStoreError("interrupt_cas_conflict", checkpoint_id)
            self._conn.commit()
            return payload
        except Exception:
            self._conn.rollback()
            raise

    def fork(self, source_checkpoint_id: str, *, new_checkpoint_id: str, new_thread_id: str, new_run_id: str, created_at: int) -> dict[str, Any]:
        source = self.get(source_checkpoint_id)
        if source is None:
            raise InterruptStoreError("unknown_checkpoint", source_checkpoint_id)
        return self.create_interrupt(
            checkpoint_id=new_checkpoint_id,
            thread_id=new_thread_id,
            run_id=new_run_id,
            parent_checkpoint_id=source_checkpoint_id,
            state={"forked_from_state_sha256": source["state_sha256"]},
            interrupt_payload={"forked_from": source_checkpoint_id},
            created_at=created_at,
            allow_cross_thread_parent=True,
        )


def seal_trace_span(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("trace span must be object")
    for field in ("trace_id", "span_id", "name"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    if body.get("span_type") not in TRACE_SPAN_TYPES:
        raise ValueError("unknown span type")
    parent = body.get("parent_span_id")
    if parent is not None and (not isinstance(parent, str) or not parent):
        raise ValueError("parent_span_id invalid")
    previous = body.get("previous_span_sha256")
    if previous is not None and not _is_sha256(previous):
        raise ValueError("previous span digest invalid")
    started = body.get("started_at_tick")
    ended = body.get("ended_at_tick")
    if type(started) is not int or type(ended) is not int or started < 0 or ended < started:
        raise ValueError("invalid span time window")
    attributes = body.get("attributes", {})
    if not isinstance(attributes, dict):
        raise ValueError("attributes object required")
    redacted = body.get("redacted_fields", [])
    if not isinstance(redacted, list) or not all(isinstance(x, str) and x for x in redacted):
        raise ValueError("redacted_fields invalid")
    body["redacted_fields"] = sorted(set(redacted))
    body.setdefault("contract_id", TRACE_SPAN_CONTRACT_ID)
    body.setdefault("span_sha256", "")
    return seal_mapping(body, "span_sha256")


def validate_trace_chain(spans: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_sha: str | None = None
    trace_id: str | None = None
    for index, raw in enumerate(spans):
        span = materialize_json(raw)
        if not isinstance(span, dict) or not verify_sealed_mapping(span, "span_sha256"):
            errors.append(_error("invalid_trace_span", f"spans[{index}]", "sealed span required"))
            continue
        normalized.append(span)
        if trace_id is None:
            trace_id = span["trace_id"]
        elif span["trace_id"] != trace_id:
            errors.append(_error("trace_id_mismatch", f"spans[{index}].trace_id", trace_id))
        if span["span_id"] in seen_ids:
            errors.append(_error("duplicate_span_id", f"spans[{index}].span_id", span["span_id"]))
        seen_ids.add(span["span_id"])
        if span.get("previous_span_sha256") != previous_sha:
            errors.append(_error("trace_chain_break", f"spans[{index}].previous_span_sha256", str(previous_sha)))
        parent = span.get("parent_span_id")
        if parent is not None and parent not in seen_ids:
            errors.append(_error("unknown_parent_span", f"spans[{index}].parent_span_id", parent))
        previous_sha = span["span_sha256"]
    body = {
        "contract_id": TRACE_CHAIN_CONTRACT_ID,
        "trace_id": trace_id,
        "span_sha256s": [span["span_sha256"] for span in normalized],
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "trace_chain_sha256": "",
    }
    return seal_mapping(body, "trace_chain_sha256")


def seal_action_observation_event(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("event must be object")
    if body.get("kind") not in EVENT_KINDS:
        raise ValueError("kind must be ACTION or OBSERVATION")
    for field in ("event_id", "run_id", "correlation_id", "payload_sha256"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    if not _is_sha256(body["payload_sha256"]):
        raise ValueError("payload_sha256 required")
    action_event_id = body.get("action_event_id")
    if body["kind"] == "OBSERVATION" and (not isinstance(action_event_id, str) or not action_event_id):
        raise ValueError("observation requires action_event_id")
    if body["kind"] == "ACTION" and action_event_id is not None:
        raise ValueError("action cannot reference action_event_id")
    body.setdefault("contract_id", ACTION_OBSERVATION_EVENT_CONTRACT_ID)
    body.setdefault("event_sha256", "")
    return seal_mapping(body, "event_sha256")


def validate_action_observation_stream(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    actions: dict[str, dict[str, Any]] = {}
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(events):
        event = materialize_json(raw)
        if not isinstance(event, dict) or not verify_sealed_mapping(event, "event_sha256"):
            errors.append(_error("invalid_event", f"events[{index}]", "sealed event required"))
            continue
        normalized.append(event)
        if event["event_id"] in seen_ids:
            errors.append(_error("duplicate_event_id", f"events[{index}].event_id", event["event_id"]))
        seen_ids.add(event["event_id"])
        if event["kind"] == "ACTION":
            actions[event["event_id"]] = event
        else:
            action = actions.get(event.get("action_event_id"))
            if action is None:
                errors.append(_error("orphan_observation", f"events[{index}].action_event_id", str(event.get("action_event_id"))))
            elif action["run_id"] != event["run_id"] or action["correlation_id"] != event["correlation_id"]:
                errors.append(_error("observation_binding_mismatch", f"events[{index}]", "run/correlation mismatch"))
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "event_sha256s": [event["event_sha256"] for event in normalized],
    }


__all__ = [
    "ACTION_OBSERVATION_EVENT_CONTRACT_ID",
    "GUARDRAIL_PIPELINE_CONTRACT_ID",
    "GUARDRAIL_RESULT_CONTRACT_ID",
    "HANDOFF_CONTEXT_CONTRACT_ID",
    "INTERRUPT_CHECKPOINT_CONTRACT_ID",
    "InterruptStoreError",
    "PERMISSION_DELTA_CONTRACT_ID",
    "PermissionDeltaLedger",
    "SQLiteInterruptStore",
    "TARGET_IDENTITY_CONTRACT_ID",
    "TargetValidationError",
    "TOOL_POLICY_DECISION_CONTRACT_ID",
    "TOOL_POLICY_RULE_CONTRACT_ID",
    "TRACE_CHAIN_CONTRACT_ID",
    "TRACE_SPAN_CONTRACT_ID",
    "canonicalize_tool_target",
    "evaluate_guardrail_pipeline",
    "evaluate_tool_policy",
    "make_filtered_handoff_context",
    "seal_action_observation_event",
    "seal_guardrail_result",
    "seal_one_shot_permission_delta",
    "seal_tool_policy_rule",
    "seal_trace_span",
    "split_shell_segments",
    "validate_action_observation_stream",
    "validate_trace_chain",
]
