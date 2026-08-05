"""TRIAXIS v3.8 external trust-registry head witness.

A local registry database cannot prove that an older copy of itself was not
restored. This module requires a fresh, separately signed witness for the exact
accepted registry sequence and snapshot digest before operational keys are
loaded.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .crypto_trust import (
    PURPOSE_TRUST_REGISTRY_ANCHOR,
    TrustKeyRegistry,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_state import SQLiteTrustRegistryStore

TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID = "TRIAXIS_TRUST_REGISTRY_HEAD_WITNESS_v1"


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def make_trust_registry_head_witness(
    *,
    anchor_id: str,
    registry_id: str,
    sequence: int,
    snapshot_sha256: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return seal_mapping(
        {
            "contract_id": TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID,
            "anchor_id": anchor_id,
            "registry_id": registry_id,
            "sequence": sequence,
            "snapshot_sha256": snapshot_sha256,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def validate_trust_registry_head_witness(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "anchor", "mapping required")]}
    try:
        witness = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "anchor", type(exc).__name__)]}
    if not isinstance(witness, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "anchor", "object required")]}
    if witness.get("contract_id") != TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "anchor.contract_id", "unexpected anchor contract"))
    if not verify_sealed_mapping(witness, "witness_sha256"):
        errors.append(_error("digest_mismatch", "anchor.witness_sha256", "canonical digest mismatch"))
    for field in ("anchor_id", "registry_id"):
        if not isinstance(witness.get(field), str) or not witness.get(field):
            errors.append(_error("missing_required", f"anchor.{field}", f"{field} required"))
    if type(witness.get("sequence")) is not int or witness.get("sequence", -1) < 1:
        errors.append(_error("invalid_sequence", "anchor.sequence", "integer >= 1 required"))
    if not _is_sha256(witness.get("snapshot_sha256")):
        errors.append(_error("invalid_snapshot_digest", "anchor.snapshot_sha256", "lowercase SHA-256 required"))
    issued_at, valid_until = witness.get("issued_at"), witness.get("valid_until")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_issued_at", "anchor.issued_at", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "anchor.valid_until", "integer >= 0 required"))
    elif type(issued_at) is int and valid_until <= issued_at:
        errors.append(_error("invalid_anchor_window", "anchor.valid_until", "must be after issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_anchor", "anchor.issued_at", "anchor from the future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("stale_anchor", "anchor.valid_until", "anchor expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "witness": witness}


class TrustRegistryAnchorError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def load_registry_with_external_anchor(
    store: SQLiteTrustRegistryStore,
    signed_anchor_value: Mapping[str, Any],
    *,
    anchor_registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_anchor_signer_id: str,
    expected_anchor_trust_domain: str,
    expected_anchor_id: str,
) -> TrustKeyRegistry:
    """Load operational keys only when local head exactly matches external witness."""
    signed_result = verify_contract_envelope(
        signed_anchor_value,
        registry=anchor_registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_TRUST_REGISTRY_ANCHOR,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID,
        expected_signer_id=expected_anchor_signer_id,
        expected_trust_domain=expected_anchor_trust_domain,
    )
    if signed_result["status"] != "PASS":
        raise TrustRegistryAnchorError("invalid_external_anchor_signature", str(signed_result["errors"]))
    witness_result = validate_trust_registry_head_witness(signed_result["inner_contract"], evaluation_tick)
    if witness_result["status"] != "PASS":
        raise TrustRegistryAnchorError("invalid_external_anchor", str(witness_result["errors"]))
    witness = witness_result["witness"]
    if witness["anchor_id"] != expected_anchor_id:
        raise TrustRegistryAnchorError("anchor_id_mismatch", str(witness["anchor_id"]))
    if witness["registry_id"] != store.registry_id:
        raise TrustRegistryAnchorError("anchor_registry_id_mismatch", str(witness["registry_id"]))
    head = store.head()
    if head is None:
        raise TrustRegistryAnchorError("local_registry_missing", store.registry_id)
    if head["sequence"] < witness["sequence"]:
        raise TrustRegistryAnchorError(
            "local_registry_rollback",
            f"local={head['sequence']} anchor={witness['sequence']}",
        )
    if head["sequence"] > witness["sequence"]:
        raise TrustRegistryAnchorError(
            "stale_external_anchor",
            f"local={head['sequence']} anchor={witness['sequence']}",
        )
    if head["snapshot_sha256"] != witness["snapshot_sha256"]:
        raise TrustRegistryAnchorError("local_registry_fork", "sequence matches but snapshot digest differs")
    return store.load_registry(evaluation_tick)


__all__ = [
    "TRUST_REGISTRY_HEAD_WITNESS_CONTRACT_ID",
    "TrustRegistryAnchorError",
    "load_registry_with_external_anchor",
    "make_trust_registry_head_witness",
    "validate_trust_registry_head_witness",
]
