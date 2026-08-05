"""TRIAXIS v3.2 deterministic policy lifecycle and policy-as-code adapter.

The module intentionally accepts only structured facts.  Natural-language
policy interpretation belongs to the assurance plane and cannot mint an ACTIVE
policy or an ALLOW outcome here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

POLICY_BUNDLE_CONTRACT_ID = "TRIAXIS_POLICY_BUNDLE_v1"
POLICY_DECISION_CONTRACT_ID = "TRIAXIS_POLICY_DECISION_v1"
POLICY_STATES = frozenset({"DRAFT", "SHADOW", "ACTIVE", "DEPRECATED", "REVOKED"})
RISK_CLASSES = ("R0", "R1", "R2", "R3", "R4")


def seal_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    return seal_mapping(value, "policy_sha256")


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def validate_policy_bundle(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "policy", "mapping required")]}
    try:
        policy = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "policy", type(exc).__name__)]}
    if not isinstance(policy, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "policy", "object required")]}
    errors: list[dict[str, str]] = []
    if policy.get("contract_id") != POLICY_BUNDLE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "policy.contract_id", "unexpected policy contract"))
    if not verify_sealed_mapping(policy, "policy_sha256"):
        errors.append(_error("digest_mismatch", "policy.policy_sha256", "canonical digest mismatch"))
    for field in ("policy_id", "subject_id", "issuer_id"):
        if not isinstance(policy.get(field), str) or not policy.get(field):
            errors.append(_error("missing_required", f"policy.{field}", f"{field} required"))
    sequence = policy.get("sequence")
    if type(sequence) is not int or sequence < 1:
        errors.append(_error("invalid_sequence", "policy.sequence", "integer >= 1 required"))
    minimum = policy.get("minimum_accepted_sequence")
    if type(minimum) is not int or minimum < 1:
        errors.append(_error("invalid_minimum_sequence", "policy.minimum_accepted_sequence", "integer >= 1 required"))
    elif type(sequence) is int and minimum > sequence:
        errors.append(_error("minimum_exceeds_sequence", "policy.minimum_accepted_sequence", "cannot exceed policy sequence"))
    if policy.get("state") not in POLICY_STATES:
        errors.append(_error("invalid_policy_state", "policy.state", "unknown lifecycle state"))
    for field in ("effective_from", "valid_until"):
        value_ = policy.get(field)
        if value_ is not None and (type(value_) is not int or value_ < 0):
            errors.append(_error("invalid_time", f"policy.{field}", "integer >= 0 or null required"))
    if type(policy.get("effective_from")) is int and type(policy.get("valid_until")) is int:
        if policy["valid_until"] <= policy["effective_from"]:
            errors.append(_error("invalid_time_window", "policy.valid_until", "must be after effective_from"))
    for field in ("allowed_capabilities", "allowed_tools", "allowed_targets", "required_approval_types"):
        items = policy.get(field)
        if not isinstance(items, list) or not all(isinstance(item, str) and item for item in items):
            errors.append(_error("invalid_string_array", f"policy.{field}", "string array required"))
    if policy.get("max_risk_class") not in RISK_CLASSES:
        errors.append(_error("invalid_risk_class", "policy.max_risk_class", "R0-R4 required"))
    previous = policy.get("supersedes_policy_sha256")
    if previous is not None and not _is_sha256(previous):
        errors.append(_error("invalid_supersedes_digest", "policy.supersedes_policy_sha256", "SHA-256 or null required"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "policy": policy}


class PolicyRegistryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PolicyRegistry:
    """Append-only in-memory lifecycle registry used by the deterministic gate.

    Persistence and signatures are integration responsibilities.  The registry
    itself enforces sequence monotonicity, explicit supersession and rollback
    resistance over the policy records it has received.
    """

    def __init__(self) -> None:
        self._history: dict[str, list[dict[str, Any]]] = {}

    def register(self, value: Mapping[str, Any]) -> dict[str, Any]:
        validation = validate_policy_bundle(value)
        if validation["status"] != "PASS":
            raise PolicyRegistryError("invalid_policy_bundle", str(validation["errors"]))
        policy = validation["policy"]
        policy_id = policy["policy_id"]
        history = self._history.setdefault(policy_id, [])
        if history:
            previous = history[-1]
            if policy["sequence"] <= previous["sequence"]:
                raise PolicyRegistryError("policy_rollback", "sequence must strictly increase")
            if policy.get("supersedes_policy_sha256") != previous["policy_sha256"]:
                raise PolicyRegistryError("policy_lineage_break", "new policy must supersede current head")
            if policy["minimum_accepted_sequence"] < previous["minimum_accepted_sequence"]:
                raise PolicyRegistryError("minimum_sequence_rollback", "minimum accepted sequence cannot decrease")
        elif policy.get("supersedes_policy_sha256") is not None:
            raise PolicyRegistryError("orphan_policy", "genesis policy cannot supersede an unknown digest")
        history.append(policy)
        return policy

    def history(self, policy_id: str) -> list[dict[str, Any]]:
        return [dict(item) for item in self._history.get(policy_id, [])]

    def head(self, policy_id: str) -> dict[str, Any] | None:
        history = self._history.get(policy_id, [])
        return None if not history else dict(history[-1])

    def select_active(self, policy_id: str, evaluation_tick: int, minimum_sequence: int = 1) -> dict[str, Any]:
        if type(evaluation_tick) is not int or evaluation_tick < 0:
            raise PolicyRegistryError("invalid_evaluation_tick", "evaluation_tick must be integer >= 0")
        head = self.head(policy_id)
        if head is None:
            raise PolicyRegistryError("policy_not_found", policy_id)
        if head["sequence"] < max(minimum_sequence, head["minimum_accepted_sequence"]):
            raise PolicyRegistryError("policy_below_minimum", "policy sequence below accepted floor")
        if head["state"] != "ACTIVE":
            raise PolicyRegistryError("policy_not_active", head["state"])
        if head.get("effective_from") is not None and evaluation_tick < head["effective_from"]:
            raise PolicyRegistryError("policy_not_yet_effective", policy_id)
        if head.get("valid_until") is not None and evaluation_tick >= head["valid_until"]:
            raise PolicyRegistryError("policy_expired", policy_id)
        return head


def evaluate_policy(policy: Mapping[str, Any], request: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
    """Evaluate a structured action request against one ACTIVE policy bundle."""

    validation = validate_policy_bundle(policy)
    errors = list(validation["errors"])
    if validation["status"] != "PASS":
        return {"status": "DENY", "reason": "INVALID_POLICY", "errors": errors, "trace": []}
    p = validation["policy"]
    trace: list[dict[str, Any]] = []

    def check(predicate_id: str, passed: bool, observed: Any, expected: Any) -> None:
        trace.append({"predicate_id": predicate_id, "passed": passed, "observed": observed, "expected": expected})
        if not passed:
            errors.append(_error(predicate_id, "request", f"observed={observed!r}, expected={expected!r}"))

    check("policy_active", p["state"] == "ACTIVE", p["state"], "ACTIVE")
    effective = p.get("effective_from") is None or evaluation_tick >= p["effective_from"]
    current = p.get("valid_until") is None or evaluation_tick < p["valid_until"]
    check("policy_effective", effective, evaluation_tick, p.get("effective_from"))
    check("policy_not_expired", current, evaluation_tick, p.get("valid_until"))
    check("policy_id_match", request.get("policy_id") == p["policy_id"], request.get("policy_id"), p["policy_id"])
    check("policy_sequence_match", request.get("policy_sequence") == p["sequence"], request.get("policy_sequence"), p["sequence"])
    check("policy_subject_match", request.get("subject_id") == p["subject_id"], request.get("subject_id"), p["subject_id"])
    check("capability_allowed", request.get("capability") in set(p["allowed_capabilities"]), request.get("capability"), p["allowed_capabilities"])
    check("tool_allowed", request.get("tool_id") in set(p["allowed_tools"]), request.get("tool_id"), p["allowed_tools"])
    check("target_allowed", request.get("execution_target") in set(p["allowed_targets"]), request.get("execution_target"), p["allowed_targets"])
    risk = request.get("risk_class")
    risk_ok = risk in RISK_CLASSES and RISK_CLASSES.index(risk) <= RISK_CLASSES.index(p["max_risk_class"])
    check("risk_within_policy", risk_ok, risk, p["max_risk_class"])
    approvals = request.get("approval_types", [])
    approvals_set = set(approvals) if isinstance(approvals, list) else set()
    required = set(p["required_approval_types"])
    check("required_approvals_present", required.issubset(approvals_set), sorted(approvals_set), sorted(required))

    decision = {
        "contract_id": POLICY_DECISION_CONTRACT_ID,
        "policy_id": p["policy_id"],
        "policy_sequence": p["sequence"],
        "policy_sha256": p["policy_sha256"],
        "evaluation_tick": evaluation_tick,
        "outcome": "ALLOW" if not errors else "DENY",
        "trace": trace,
        "errors": errors,
        "decision_sha256": "",
    }
    return seal_mapping(decision, "decision_sha256")


__all__ = [
    "POLICY_BUNDLE_CONTRACT_ID",
    "POLICY_DECISION_CONTRACT_ID",
    "POLICY_STATES",
    "PolicyRegistry",
    "PolicyRegistryError",
    "evaluate_policy",
    "seal_policy",
    "validate_policy_bundle",
]
