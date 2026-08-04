"""Transactional local persistence for authenticated TRIAXIS checkpoints.

This module provides one-host durability and cooperating-writer compare-and-swap.
It does not provide whole-database anti-rollback, multi-host consensus or trusted
storage.  Loading still requires a host-controlled expected checkpoint digest.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any

from .integrity import canonical_json_bytes, materialize_json
from .provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
    validate_checkpoint_receipt,
)

SCHEMA_VERSION = 1
_HEX64 = re.compile(r"[0-9a-f]{64}")


class CheckpointStoreError(RuntimeError):
    """Fail-closed durable checkpoint error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _store_error_from_trust(exc: TrustSnapshotStateError) -> CheckpointStoreError:
    return CheckpointStoreError(exc.code, str(exc))


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _freeze_object(value: Any, *, code: str, label: str) -> dict[str, Any]:
    try:
        frozen = materialize_json(value)
    except Exception as exc:
        raise CheckpointStoreError(code, f"{label} could not be materialized: {type(exc).__name__}") from exc
    if not isinstance(frozen, dict):
        raise CheckpointStoreError(code, f"{label} must be an object")
    return frozen


def _decode_canonical(blob: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise CheckpointStoreError("checkpoint_store_corrupt_state", f"{label} is not stored as bytes")
    raw = bytes(blob)
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise CheckpointStoreError("checkpoint_store_corrupt_state", f"{label} JSON is invalid") from exc
    try:
        frozen = materialize_json(value)
    except Exception as exc:
        raise CheckpointStoreError("checkpoint_store_corrupt_state", f"{label} is not canonical JSON data") from exc
    if not isinstance(frozen, dict) or canonical_json_bytes(frozen) != raw:
        raise CheckpointStoreError("checkpoint_store_corrupt_state", f"{label} bytes are not canonical")
    return frozen


class SQLiteCheckpointStore:
    """Namespace-scoped SQLite checkpoint store with transactional CAS."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        namespace: str,
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(namespace, str) or not namespace or len(namespace) > 512:
            raise ValueError("namespace must be a non-empty string of at most 512 characters")
        if "\x00" in namespace:
            raise ValueError("namespace cannot contain NUL")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number")

        self._path = Path(path)
        self._namespace = namespace
        self._lock = RLock()
        self._closed = False
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists() and self._path.is_symlink():
            raise CheckpointStoreError("checkpoint_store_unsafe_path", "checkpoint database path cannot be a symlink")
        try:
            self._conn = sqlite3.connect(
                str(self._path),
                timeout=float(timeout),
                isolation_level=None,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = FULL")
            self._conn.execute(f"PRAGMA busy_timeout = {int(float(timeout) * 1000)}")
            self._initialize_schema()
            if self._path.exists():
                try:
                    os.chmod(self._path, 0o600)
                except OSError:
                    pass
        except sqlite3.Error as exc:
            raise CheckpointStoreError("checkpoint_store_io_error", f"cannot open checkpoint store: {exc}") from exc

    @property
    def path(self) -> Path:
        return self._path

    @property
    def namespace(self) -> str:
        return self._namespace

    def __del__(self) -> None:
        # Best-effort hygiene for callers that fail to use close/context manager.
        # Correctness must never rely on destructor timing.
        try:
            if not getattr(self, "_closed", True):
                self._conn.close()
                self._closed = True
        except Exception:
            pass

    def __enter__(self) -> "SQLiteCheckpointStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise CheckpointStoreError("checkpoint_store_closed", "checkpoint store is closed")

    def _initialize_schema(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise CheckpointStoreError(
                    "checkpoint_store_schema_mismatch",
                    f"unsupported checkpoint store schema version {version}",
                )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint_current (
                    namespace TEXT PRIMARY KEY,
                    head_sha256 TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    receipt_json BLOB NOT NULL,
                    envelope_json BLOB NOT NULL
                ) WITHOUT ROWID
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS checkpoint_history (
                    namespace TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence >= 1),
                    checkpoint_sha256 TEXT NOT NULL,
                    receipt_json BLOB NOT NULL,
                    envelope_json BLOB NOT NULL,
                    PRIMARY KEY(namespace, sequence),
                    UNIQUE(namespace, checkpoint_sha256)
                ) WITHOUT ROWID
                """
            )
            if version == 0:
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.close()
            finally:
                self._closed = True

    def _select_current_row(self) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT namespace, head_sha256, sequence, receipt_json, envelope_json "
            "FROM checkpoint_current WHERE namespace = ?",
            (self._namespace,),
        ).fetchone()

    @staticmethod
    def _row_pair(row: sqlite3.Row) -> dict[str, Any]:
        receipt = _decode_canonical(row["receipt_json"], label="checkpoint receipt")
        envelope = _decode_canonical(row["envelope_json"], label="trust envelope")
        validation = validate_checkpoint_receipt(receipt)
        if validation.get("status") != "PASS":
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored checkpoint receipt is invalid")
        if row["head_sha256"] != receipt.get("checkpoint_sha256"):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored head does not match receipt")
        if row["sequence"] != receipt.get("sequence"):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored sequence does not match receipt")
        return {
            "namespace": str(row["namespace"]),
            "head_sha256": str(row["head_sha256"]),
            "receipt": receipt,
            "envelope": envelope,
        }

    @staticmethod
    def _validated_pair(
        *,
        checkpoint_receipt: Mapping[str, Any],
        trust_envelope: Mapping[str, Any],
        authority_roots: Sequence[Mapping[str, Any]],
    ) -> tuple[dict[str, Any], dict[str, Any], ProvenanceTrustStateGuard]:
        receipt = _freeze_object(
            checkpoint_receipt,
            code="invalid_checkpoint_receipt_materialization",
            label="checkpoint receipt",
        )
        envelope = _freeze_object(
            trust_envelope,
            code="invalid_trust_snapshot_envelope",
            label="trust envelope",
        )
        validation = validate_checkpoint_receipt(receipt)
        if validation.get("status") != "PASS":
            errors = validation.get("errors")
            first = errors[0] if isinstance(errors, list) and errors else {}
            raise CheckpointStoreError(
                str(first.get("code", "invalid_checkpoint_receipt")),
                str(first.get("message", "checkpoint receipt invalid")),
            )
        try:
            guard = ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=authority_roots,
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                expected_checkpoint_sha256=str(receipt["checkpoint_sha256"]),
            )
        except TrustSnapshotStateError as exc:
            raise _store_error_from_trust(exc) from exc
        return receipt, envelope, guard

    def get_current(self) -> dict[str, Any] | None:
        with self._lock:
            self._ensure_open()
            try:
                row = self._select_current_row()
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            return None if row is None else deepcopy(self._row_pair(row))

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            self._ensure_open()
            try:
                rows = self._conn.execute(
                    "SELECT namespace, checkpoint_sha256 AS head_sha256, sequence, "
                    "receipt_json, envelope_json FROM checkpoint_history "
                    "WHERE namespace = ? ORDER BY sequence ASC",
                    (self._namespace,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            return [deepcopy(self._row_pair(row)) for row in rows]

    def load_guard(
        self,
        *,
        authority_roots: Sequence[Mapping[str, Any]],
        expected_checkpoint_sha256: str,
    ) -> ProvenanceTrustStateGuard:
        if not _is_hex64(expected_checkpoint_sha256):
            raise CheckpointStoreError(
                "invalid_checkpoint_store_head",
                "expected checkpoint head must be 64 lowercase hexadecimal characters",
            )
        current = self.get_current()
        if current is None:
            raise CheckpointStoreError("checkpoint_store_empty", "checkpoint store has no current state")
        if current["head_sha256"] != expected_checkpoint_sha256:
            raise CheckpointStoreError(
                "checkpoint_store_head_mismatch",
                "durable head does not match the host-controlled expected head",
            )
        try:
            return ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=authority_roots,
                checkpoint_receipt=current["receipt"],
                trust_envelope=current["envelope"],
                expected_checkpoint_sha256=expected_checkpoint_sha256,
            )
        except TrustSnapshotStateError as exc:
            raise CheckpointStoreError("checkpoint_store_corrupt_state", str(exc)) from exc

    def commit(
        self,
        *,
        checkpoint_receipt: Mapping[str, Any],
        trust_envelope: Mapping[str, Any],
        authority_roots: Sequence[Mapping[str, Any]],
        expected_previous_head: str | None,
    ) -> str:
        receipt, envelope, _ = self._validated_pair(
            checkpoint_receipt=checkpoint_receipt,
            trust_envelope=trust_envelope,
            authority_roots=authority_roots,
        )
        new_head = str(receipt["checkpoint_sha256"])
        if expected_previous_head is not None and not _is_hex64(expected_previous_head):
            raise CheckpointStoreError(
                "invalid_checkpoint_store_expected_head",
                "expected previous head must be null or 64 lowercase hexadecimal characters",
            )
        receipt_blob = canonical_json_bytes(receipt)
        envelope_blob = canonical_json_bytes(envelope)

        with self._lock:
            self._ensure_open()
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._select_current_row()
                if row is None:
                    if expected_previous_head is not None:
                        raise CheckpointStoreError(
                            "checkpoint_store_cas_mismatch",
                            "genesis expected previous head must be null",
                        )
                    if receipt["sequence"] != 1 or receipt["previous_envelope_sha256"] is not None:
                        raise CheckpointStoreError(
                            "checkpoint_store_chain_mismatch",
                            "durable genesis must be sequence 1 with null parent",
                        )
                else:
                    current = self._row_pair(row)

                    # Unknown-outcome reconciliation: if the exact requested
                    # pair is already the durable head, validate its immutable
                    # history position and exact predecessor claim, then return
                    # without appending or updating anything.  A merely stale
                    # but different writer must continue to fail CAS.
                    if current["head_sha256"] == new_head:
                        if current["receipt"] != receipt or current["envelope"] != envelope:
                            raise CheckpointStoreError(
                                "checkpoint_store_head_collision",
                                "current head identifies different receipt or envelope bytes",
                            )
                        history_row = self._conn.execute(
                            "SELECT namespace, checkpoint_sha256 AS head_sha256, sequence, "
                            "receipt_json, envelope_json FROM checkpoint_history "
                            "WHERE namespace = ? AND sequence = ?",
                            (self._namespace, receipt["sequence"]),
                        ).fetchone()
                        if history_row is None or self._row_pair(history_row) != current:
                            raise CheckpointStoreError(
                                "checkpoint_store_corrupt_state",
                                "current checkpoint is missing or differs in immutable history",
                            )
                        if receipt["sequence"] == 1:
                            actual_previous_head = None
                        else:
                            previous_row = self._conn.execute(
                                "SELECT namespace, checkpoint_sha256 AS head_sha256, sequence, "
                                "receipt_json, envelope_json FROM checkpoint_history "
                                "WHERE namespace = ? AND sequence = ?",
                                (self._namespace, receipt["sequence"] - 1),
                            ).fetchone()
                            if previous_row is None:
                                raise CheckpointStoreError(
                                    "checkpoint_store_corrupt_state",
                                    "idempotent checkpoint predecessor is missing from history",
                                )
                            previous = self._row_pair(previous_row)
                            if (
                                receipt["previous_envelope_sha256"]
                                != previous["receipt"]["envelope_sha256"]
                            ):
                                raise CheckpointStoreError(
                                    "checkpoint_store_corrupt_state",
                                    "idempotent checkpoint parent differs from history",
                                )
                            actual_previous_head = previous["head_sha256"]
                        if expected_previous_head != actual_previous_head:
                            raise CheckpointStoreError(
                                "checkpoint_store_cas_mismatch",
                                "idempotent retry does not name the exact predecessor head",
                            )
                        self._conn.execute("COMMIT")
                        return new_head

                    if current["head_sha256"] != expected_previous_head:
                        raise CheckpointStoreError(
                            "checkpoint_store_cas_mismatch",
                            "durable head changed since caller preparation",
                        )
                    try:
                        ProvenanceTrustStateGuard.from_checkpoint(
                            authority_roots=authority_roots,
                            checkpoint_receipt=current["receipt"],
                            trust_envelope=current["envelope"],
                            expected_checkpoint_sha256=current["head_sha256"],
                        )
                    except TrustSnapshotStateError as exc:
                        raise CheckpointStoreError("checkpoint_store_corrupt_state", str(exc)) from exc
                    old = current["receipt"]
                    if receipt["sequence"] != old["sequence"] + 1:
                        raise CheckpointStoreError(
                            "checkpoint_store_chain_mismatch",
                            "successor sequence does not follow the durable head",
                        )
                    if receipt["previous_envelope_sha256"] != old["envelope_sha256"]:
                        raise CheckpointStoreError(
                            "checkpoint_store_chain_mismatch",
                            "successor parent does not match the durable envelope head",
                        )
                    if receipt["evaluation_tick"] < old["evaluation_tick"]:
                        raise CheckpointStoreError(
                            "checkpoint_store_chain_mismatch",
                            "successor evaluation time rolls back durable state",
                        )
                    for field in ("authority_id", "key_id", "authority_root_sha256"):
                        if receipt[field] != old[field]:
                            raise CheckpointStoreError(
                                "checkpoint_store_chain_mismatch",
                                f"successor {field} breaks durable root continuity",
                            )

                self._conn.execute(
                    "INSERT INTO checkpoint_history "
                    "(namespace, sequence, checkpoint_sha256, receipt_json, envelope_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (self._namespace, receipt["sequence"], new_head, receipt_blob, envelope_blob),
                )
                if row is None:
                    self._conn.execute(
                        "INSERT INTO checkpoint_current "
                        "(namespace, head_sha256, sequence, receipt_json, envelope_json) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (self._namespace, new_head, receipt["sequence"], receipt_blob, envelope_blob),
                    )
                else:
                    updated = self._conn.execute(
                        "UPDATE checkpoint_current SET head_sha256 = ?, sequence = ?, "
                        "receipt_json = ?, envelope_json = ? "
                        "WHERE namespace = ? AND head_sha256 = ?",
                        (
                            new_head,
                            receipt["sequence"],
                            receipt_blob,
                            envelope_blob,
                            self._namespace,
                            expected_previous_head,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise CheckpointStoreError(
                            "checkpoint_store_cas_mismatch",
                            "durable head changed before commit",
                        )
                self._conn.execute("COMMIT")
                return new_head
            except CheckpointStoreError:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise
            except sqlite3.IntegrityError as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise CheckpointStoreError("checkpoint_store_history_conflict", str(exc)) from exc
            except sqlite3.Error as exc:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise


__all__ = [
    "CheckpointStoreError",
    "SCHEMA_VERSION",
    "SQLiteCheckpointStore",
]
