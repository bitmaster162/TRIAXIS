"""Recovered deterministic Analysis Bundle v5 contract.

This module is a bounded reconstruction required to execute the physically
available v2.34 authority-ingress artifacts.  It is not represented as the
byte-identical unavailable historical implementation.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

ANALYSIS_BUNDLE_CONTRACT_ID = "TRIAXIS_ANALYSIS_BUNDLE_v5"
ANALYSIS_FRAME_CONTRACT_ID = "TRIAXIS_ANALYSIS_FRAME_v5"
ANALYTIC_PASS_CONTRACT_ID = "TRIAXIS_ANALYTIC_PASS_v5"
SYNTHESIS_RECEIPT_CONTRACT_ID = "TRIAXIS_SYNTHESIS_RECEIPT_v5"

_PASS_TYPES = frozenset({"PRIMARY", "SELF_AUDIT", "DEVIL", "ANGEL", "FALSIFIER"})
_RATIONALE_ROLES = frozenset({"RATIONALE", "CONTROL", "DEPENDENCY", "TRADEOFF"})
_RISK_ROLES = frozenset({"RISK", "CONTROL"})


def seal_contract(value: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    return seal_mapping(value, digest_field)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _block(errors: list[dict[str, str]], reason: str = "BLOCKED_BY_ANALYSIS_CONTRACT") -> dict[str, Any]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in errors:
        key = (item["code"], item["path"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return {
        "status": "BLOCK",
        "primary_reason": reason,
        "errors": unique,
        "error_count": len(unique),
    }


def _claim_index(bundle: Mapping[str, Any], errors: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    claims: dict[str, dict[str, Any]] = {}
    passes = bundle.get("passes")
    if not isinstance(passes, list):
        errors.append(_error("invalid_type", "bundle.passes", "passes must be an array"))
        return claims
    seen_passes: set[str] = set()
    for index, item in enumerate(passes):
        path = f"bundle.passes[{index}]"
        if not isinstance(item, Mapping):
            errors.append(_error("invalid_type", path, "pass must be an object"))
            continue
        pass_type = item.get("pass_type")
        if pass_type not in _PASS_TYPES:
            errors.append(_error("invalid_pass_type", f"{path}.pass_type", "unknown pass type"))
        elif pass_type in seen_passes:
            errors.append(_error("duplicate_pass_type", f"{path}.pass_type", "duplicate pass type"))
        else:
            seen_passes.add(str(pass_type))
        if not verify_sealed_mapping(item, "pass_sha256"):
            errors.append(_error("digest_mismatch", f"{path}.pass_sha256", "pass digest mismatch"))
        pass_claims = item.get("claims")
        if not isinstance(pass_claims, list):
            errors.append(_error("invalid_type", f"{path}.claims", "claims must be an array"))
            continue
        for claim_index, raw_claim in enumerate(pass_claims):
            cpath = f"{path}.claims[{claim_index}]"
            if not isinstance(raw_claim, Mapping):
                errors.append(_error("invalid_type", cpath, "claim must be an object"))
                continue
            claim_id = raw_claim.get("claim_id")
            role = raw_claim.get("role")
            if not isinstance(claim_id, str) or not claim_id:
                errors.append(_error("missing_required", f"{cpath}.claim_id", "claim_id required"))
                continue
            if claim_id in claims:
                errors.append(_error("duplicate_claim_id", f"{cpath}.claim_id", "claim_id must be unique"))
                continue
            if not isinstance(role, str) or not role:
                errors.append(_error("missing_required", f"{cpath}.role", "claim role required"))
                continue
            claims[claim_id] = dict(raw_claim)
    return claims


def validate_analysis_bundle(
    value: Any,
    *,
    trust_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate the recovered v5 shape and the key synthesis-role invariants."""

    if not isinstance(value, Mapping):
        return _block([_error("invalid_type", "bundle", "bundle must be an object")])
    try:
        bundle = materialize_json(value)
    except Exception as exc:
        return _block([_error(
            "invalid_analysis_bundle_materialization",
            "bundle",
            f"bundle could not be materialized: {type(exc).__name__}",
        )])
    if not isinstance(bundle, dict):
        return _block([_error("invalid_type", "bundle", "bundle must be an object")])

    errors: list[dict[str, str]] = []
    required = {"contract_id", "frame", "passes", "synthesis", "bundle_sha256"}
    for field in sorted(required - bundle.keys()):
        errors.append(_error("missing_required", f"bundle.{field}", f"{field} is required"))
    if bundle.get("contract_id") != ANALYSIS_BUNDLE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "bundle.contract_id", "unexpected bundle contract"))
    if "bundle_sha256" in bundle and not verify_sealed_mapping(bundle, "bundle_sha256"):
        errors.append(_error("digest_mismatch", "bundle.bundle_sha256", "bundle digest mismatch"))

    frame = bundle.get("frame")
    if not isinstance(frame, Mapping):
        errors.append(_error("invalid_type", "bundle.frame", "frame must be an object"))
    else:
        if frame.get("contract_id") != ANALYSIS_FRAME_CONTRACT_ID:
            errors.append(_error("invalid_contract_id", "bundle.frame.contract_id", "unexpected frame contract"))
        if not verify_sealed_mapping(frame, "frame_sha256"):
            errors.append(_error("digest_mismatch", "bundle.frame.frame_sha256", "frame digest mismatch"))
        if frame.get("control_profile") not in {"A0", "A1", "A2", "A3"}:
            errors.append(_error("invalid_control_profile", "bundle.frame.control_profile", "invalid control profile"))
        tick = frame.get("evaluation_tick")
        if type(tick) is not int or tick < 0:  # bool deliberately rejected
            errors.append(_error("invalid_type", "bundle.frame.evaluation_tick", "evaluation_tick must be integer >= 0"))

    claims = _claim_index(bundle, errors)
    synthesis = bundle.get("synthesis")
    if not isinstance(synthesis, Mapping):
        errors.append(_error("invalid_type", "bundle.synthesis", "synthesis must be an object"))
    else:
        if synthesis.get("contract_id") != SYNTHESIS_RECEIPT_CONTRACT_ID:
            errors.append(_error("invalid_contract_id", "bundle.synthesis.contract_id", "unexpected synthesis contract"))
        if not verify_sealed_mapping(synthesis, "synthesis_sha256"):
            errors.append(_error("digest_mismatch", "bundle.synthesis.synthesis_sha256", "synthesis digest mismatch"))
        rationale = synthesis.get("rationale_claim_ids")
        if not isinstance(rationale, list):
            errors.append(_error("invalid_type", "bundle.synthesis.rationale_claim_ids", "rationale_claim_ids must be an array"))
        else:
            for index, claim_id in enumerate(rationale):
                claim = claims.get(claim_id) if isinstance(claim_id, str) else None
                if claim is None:
                    errors.append(_error("unknown_reference", f"bundle.synthesis.rationale_claim_ids[{index}]", "unknown claim"))
                elif claim.get("role") not in _RATIONALE_ROLES:
                    errors.append(_error("invalid_rationale_role", f"bundle.synthesis.rationale_claim_ids[{index}]", "rationale references a non-rationale claim"))
        residual = synthesis.get("residual_risk_claim_ids")
        if not isinstance(residual, list):
            errors.append(_error("invalid_type", "bundle.synthesis.residual_risk_claim_ids", "residual_risk_claim_ids must be an array"))
        else:
            for index, claim_id in enumerate(residual):
                claim = claims.get(claim_id) if isinstance(claim_id, str) else None
                if claim is None:
                    errors.append(_error("unknown_reference", f"bundle.synthesis.residual_risk_claim_ids[{index}]", "unknown claim"))
                elif claim.get("role") not in _RISK_ROLES:
                    errors.append(_error("invalid_residual_risk_role", f"bundle.synthesis.residual_risk_claim_ids[{index}]", "residual risk references a non-risk claim"))

    if trust_snapshot is not None:
        if not isinstance(trust_snapshot, Mapping):
            errors.append(_error("invalid_trust_snapshot", "trust_snapshot", "trust snapshot must be an object"))
        else:
            snapshot_tick = trust_snapshot.get("evaluation_tick")
            if type(snapshot_tick) is not int or snapshot_tick < 0:
                errors.append(_error("invalid_trust_snapshot", "trust_snapshot.evaluation_tick", "snapshot tick must be integer >= 0"))

    if errors:
        return _block(errors)
    return {
        "status": "PASS",
        "primary_reason": "ANALYSIS_CONTRACT_VALID",
        "errors": [],
        "error_count": 0,
        "bundle_sha256": str(bundle["bundle_sha256"]),
        "verified_scope": "RECOVERED_ANALYSIS_BUNDLE_V5_STRUCTURE_AND_ROLE_BINDING",
    }


__all__ = [
    "ANALYSIS_BUNDLE_CONTRACT_ID",
    "ANALYSIS_FRAME_CONTRACT_ID",
    "ANALYTIC_PASS_CONTRACT_ID",
    "SYNTHESIS_RECEIPT_CONTRACT_ID",
    "seal_contract",
    "validate_analysis_bundle",
]
