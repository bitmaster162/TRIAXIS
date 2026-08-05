"""TRIAXIS v3.7 monotonic, root-signed trust-registry state.

This module prevents a process from accepting an older or forked registry
snapshot after a newer head has been durably installed. It does not protect
against restoration of an older copy of the entire SQLite database; an
external monotonic anchor is required for that threat model.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_TRUST_REGISTRY_SNAPSHOT,
    TrustKeyRegistry,
    verify_contract_envelope,
    validate_trust_key_record,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID = "TRIAXIS_TRUST_REGISTRY_SNAPSHOT_v1"


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def make_trust_registry_snapshot(
    *,
    registry_id: str,
    sequence: int,
    parent_snapshot_sha256: str | None,
    issued_at: int,
    valid_until: int,
    key_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    records = [materialize_json(record) for record in key_records]
    records.sort(key=lambda item: str(item.get("key_id")) if isinstance(item, Mapping) else "")
    value = {
        "contract_id": TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID,
        "registry_id": registry_id,
        "sequence": sequence,
        "parent_snapshot_sha256": parent_snapshot_sha256,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "key_records": records,
        "snapshot_sha256": "",
    }
    return seal_mapping(value, "snapshot_sha256")


def validate_trust_registry_snapshot(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "snapshot", "mapping required")]}
    try:
        snapshot = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "snapshot", type(exc).__name__)]}
    if not isinstance(snapshot, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "snapshot", "object required")]}
    if snapshot.get("contract_id") != TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "snapshot.contract_id", "unexpected snapshot contract"))
    if not verify_sealed_mapping(snapshot, "snapshot_sha256"):
        errors.append(_error("digest_mismatch", "snapshot.snapshot_sha256", "canonical digest mismatch"))
    if not isinstance(snapshot.get("registry_id"), str) or not snapshot.get("registry_id"):
        errors.append(_error("missing_registry_id", "snapshot.registry_id", "non-empty string required"))
    sequence = snapshot.get("sequence")
    if type(sequence) is not int or sequence < 1:
        errors.append(_error("invalid_sequence", "snapshot.sequence", "integer >= 1 required"))
    parent = snapshot.get("parent_snapshot_sha256")
    if sequence == 1:
        if parent is not None:
            errors.append(_error("genesis_parent_forbidden", "snapshot.parent_snapshot_sha256", "sequence 1 requires null parent"))
    elif type(sequence) is int and sequence > 1 and not _is_sha256(parent):
        errors.append(_error("parent_required", "snapshot.parent_snapshot_sha256", "non-genesis snapshot requires SHA-256 parent"))
    issued_at, valid_until = snapshot.get("issued_at"), snapshot.get("valid_until")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_issued_at", "snapshot.issued_at", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "snapshot.valid_until", "integer >= 0 required"))
    elif type(issued_at) is int and valid_until <= issued_at:
        errors.append(_error("invalid_snapshot_window", "snapshot.valid_until", "must be after issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_snapshot", "snapshot.issued_at", "snapshot from the future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("expired_snapshot", "snapshot.valid_until", "snapshot expired"))

    records = snapshot.get("key_records")
    normalized: list[dict[str, Any]] = []
    key_ids: set[str] = set()
    if not isinstance(records, list):
        errors.append(_error("invalid_key_records", "snapshot.key_records", "array required"))
    else:
        previous_key_id: str | None = None
        for index, record in enumerate(records):
            result = validate_trust_key_record(record)
            errors.extend({**item, "path": f"snapshot.key_records[{index}].{item['path']}"} for item in result["errors"])
            if result["status"] != "PASS":
                continue
            item = result["record"]
            key_id = item["key_id"]
            if key_id in key_ids:
                errors.append(_error("duplicate_key_id", f"snapshot.key_records[{index}].key_id", key_id))
            key_ids.add(key_id)
            if previous_key_id is not None and key_id <= previous_key_id:
                errors.append(_error("non_canonical_key_order", f"snapshot.key_records[{index}].key_id", "key records must be strictly sorted"))
            previous_key_id = key_id
            normalized.append(item)
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "snapshot": snapshot,
        "key_records": normalized,
    }


class TrustRegistryStateError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteTrustRegistryStore:
    """Durable, sequence-checked trust-registry head."""

    def __init__(
        self,
        path: str | Path,
        *,
        root_registry: TrustKeyRegistry,
        registry_id: str,
        root_signer_id: str,
        root_trust_domain: str,
        minimum_sequence: int = 1,
    ) -> None:
        if minimum_sequence < 1:
            raise ValueError("minimum_sequence must be >= 1")
        self.path = str(path)
        self.root_registry = root_registry
        self.registry_id = registry_id
        self.root_signer_id = root_signer_id
        self.root_trust_domain = root_trust_domain
        self.minimum_sequence = minimum_sequence
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS trust_registry_state (
                registry_id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL,
                snapshot_sha256 TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                signed_envelope_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteTrustRegistryStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _row(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT registry_id, sequence, snapshot_sha256, snapshot_json, signed_envelope_json, updated_at "
            "FROM trust_registry_state WHERE registry_id=?",
            (self.registry_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "registry_id": row[0],
            "sequence": row[1],
            "snapshot_sha256": row[2],
            "snapshot": json.loads(row[3]),
            "signed_envelope": json.loads(row[4]),
            "updated_at": row[5],
        }

    def head(self) -> dict[str, Any] | None:
        value = self._row()
        return deepcopy(value) if value is not None else None

    def _verify_signed_snapshot(self, signed_snapshot: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        signed_result = verify_contract_envelope(
            signed_snapshot,
            registry=self.root_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_TRUST_REGISTRY_SNAPSHOT,
            expected_digest_field="snapshot_sha256",
            expected_inner_contract_id=TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID,
            expected_signer_id=self.root_signer_id,
            expected_trust_domain=self.root_trust_domain,
        )
        if signed_result["status"] != "PASS":
            raise TrustRegistryStateError("invalid_root_signature", str(signed_result["errors"]))
        snapshot_result = validate_trust_registry_snapshot(signed_result["inner_contract"], evaluation_tick)
        if snapshot_result["status"] != "PASS":
            raise TrustRegistryStateError("invalid_registry_snapshot", str(snapshot_result["errors"]))
        snapshot = snapshot_result["snapshot"]
        if snapshot["registry_id"] != self.registry_id:
            raise TrustRegistryStateError("registry_id_mismatch", str(snapshot["registry_id"]))
        return {"snapshot": snapshot, "signed_envelope": materialize_json(signed_snapshot)}

    def install(self, signed_snapshot: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        verified = self._verify_signed_snapshot(signed_snapshot, evaluation_tick)
        snapshot = verified["snapshot"]
        sequence = snapshot["sequence"]
        digest = snapshot["snapshot_sha256"]
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self._row()
            if current is None:
                if sequence != self.minimum_sequence:
                    raise TrustRegistryStateError("unexpected_initial_sequence", f"expected {self.minimum_sequence}, got {sequence}")
                if sequence == 1 and snapshot["parent_snapshot_sha256"] is not None:
                    raise TrustRegistryStateError("invalid_genesis_parent", "genesis parent must be null")
            else:
                if sequence == current["sequence"] and digest == current["snapshot_sha256"]:
                    self._conn.execute("COMMIT")
                    return current
                if sequence <= current["sequence"]:
                    raise TrustRegistryStateError("registry_rollback", f"current={current['sequence']} candidate={sequence}")
                if sequence != current["sequence"] + 1:
                    raise TrustRegistryStateError("registry_sequence_gap", f"current={current['sequence']} candidate={sequence}")
                if snapshot["parent_snapshot_sha256"] != current["snapshot_sha256"]:
                    raise TrustRegistryStateError("registry_parent_mismatch", "candidate does not extend current head")
            snapshot_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            envelope_json = json.dumps(verified["signed_envelope"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            self._conn.execute(
                "INSERT INTO trust_registry_state(registry_id,sequence,snapshot_sha256,snapshot_json,signed_envelope_json,updated_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(registry_id) DO UPDATE SET "
                "sequence=excluded.sequence,snapshot_sha256=excluded.snapshot_sha256,snapshot_json=excluded.snapshot_json,"
                "signed_envelope_json=excluded.signed_envelope_json,updated_at=excluded.updated_at",
                (self.registry_id, sequence, digest, snapshot_json, envelope_json, evaluation_tick),
            )
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise
        result = self._row()
        assert result is not None
        return result

    def load_registry(self, evaluation_tick: int) -> TrustKeyRegistry:
        current = self._row()
        if current is None:
            raise TrustRegistryStateError("registry_not_initialized", self.registry_id)
        verified = self._verify_signed_snapshot(current["signed_envelope"], evaluation_tick)
        snapshot = verified["snapshot"]
        if snapshot["sequence"] != current["sequence"] or snapshot["snapshot_sha256"] != current["snapshot_sha256"]:
            raise TrustRegistryStateError("stored_head_mismatch", "row metadata does not match signed snapshot")
        if snapshot["sequence"] < self.minimum_sequence:
            raise TrustRegistryStateError("registry_below_minimum_sequence", str(snapshot["sequence"]))
        return TrustKeyRegistry(snapshot["key_records"])


__all__ = [
    "SQLiteTrustRegistryStore",
    "TRUST_REGISTRY_SNAPSHOT_CONTRACT_ID",
    "TrustRegistryStateError",
    "make_trust_registry_snapshot",
    "validate_trust_registry_snapshot",
]
