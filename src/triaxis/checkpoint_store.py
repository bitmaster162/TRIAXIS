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
from time import monotonic, sleep
from typing import Any

from .checkpoint_scope import (
    AuthenticatedCheckpointScope,
    CheckpointScopeError,
    checkpoint_namespace_sha256,
    verify_checkpoint_scope_envelope,
)
from .integrity import canonical_json_bytes, materialize_json
from .provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
    validate_checkpoint_receipt,
)

SCHEMA_VERSION = 3
_HEX64 = re.compile(r"[0-9a-f]{64}")
_INITIALIZATION_LOCK = RLock()


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
        deadline = monotonic() + float(timeout)
        with _INITIALIZATION_LOCK:
            while True:
                conn: sqlite3.Connection | None = None
                try:
                    conn = sqlite3.connect(
                        str(self._path),
                        timeout=float(timeout),
                        isolation_level=None,
                        check_same_thread=False,
                    )
                    conn.row_factory = sqlite3.Row
                    # Configure lock waiting before any PRAGMA that may need a
                    # schema or journal lock. The process-local lock removes the
                    # common first-open race; the bounded retry also covers a
                    # cooperating process finishing its own initialization.
                    conn.execute(f"PRAGMA busy_timeout = {int(float(timeout) * 1000)}")
                    conn.execute("PRAGMA foreign_keys = ON")
                    conn.execute("PRAGMA journal_mode = WAL")
                    conn.execute("PRAGMA synchronous = FULL")
                    self._conn = conn
                    self._initialize_schema()
                    break
                except sqlite3.OperationalError as exc:
                    if conn is not None:
                        try:
                            conn.close()
                        except sqlite3.Error:
                            pass
                    if "locked" not in str(exc).lower() or monotonic() >= deadline:
                        raise CheckpointStoreError(
                            "checkpoint_store_io_error",
                            f"cannot open checkpoint store: {exc}",
                        ) from exc
                    sleep(min(0.025, max(0.0, deadline - monotonic())))
                except CheckpointStoreError:
                    if conn is not None:
                        try:
                            conn.close()
                        except sqlite3.Error:
                            pass
                    raise
                except sqlite3.Error as exc:
                    if conn is not None:
                        try:
                            conn.close()
                        except sqlite3.Error:
                            pass
                    raise CheckpointStoreError(
                        "checkpoint_store_io_error",
                        f"cannot open checkpoint store: {exc}",
                    ) from exc
        if self._path.exists():
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass

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

    @staticmethod
    def _create_base_tables(conn: sqlite3.Connection) -> None:
        conn.execute(
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
        conn.execute(
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

    @staticmethod
    def _create_ownership_table(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoint_ownership (
                checkpoint_sha256 TEXT PRIMARY KEY,
                envelope_sha256 TEXT NOT NULL UNIQUE,
                namespace TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence >= 1)
            ) WITHOUT ROWID
            """
        )

    @staticmethod
    def _create_scope_table(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS checkpoint_scope (
                checkpoint_sha256 TEXT PRIMARY KEY,
                envelope_sha256 TEXT NOT NULL,
                namespace TEXT NOT NULL,
                namespace_sha256 TEXT NOT NULL,
                scope_envelope_sha256 TEXT NOT NULL UNIQUE,
                scope_envelope_json BLOB NOT NULL
            ) WITHOUT ROWID
            """
        )

    @staticmethod
    def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (name,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _decode_row_pair_unowned(row: sqlite3.Row) -> dict[str, Any]:
        receipt = _decode_canonical(row["receipt_json"], label="checkpoint receipt")
        envelope = _decode_canonical(row["envelope_json"], label="trust envelope")
        validation = validate_checkpoint_receipt(receipt)
        if validation.get("status") != "PASS":
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored checkpoint receipt is invalid")
        head_key = "head_sha256" if "head_sha256" in row.keys() else "checkpoint_sha256"
        if row[head_key] != receipt.get("checkpoint_sha256"):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored head does not match receipt")
        if row["sequence"] != receipt.get("sequence"):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored sequence does not match receipt")
        if envelope.get("envelope_sha256") != receipt.get("envelope_sha256"):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored envelope does not match receipt")
        return {
            "namespace": str(row["namespace"]),
            "head_sha256": str(row[head_key]),
            "receipt": receipt,
            "envelope": envelope,
        }

    def _migrate_v1_to_v2(self) -> None:
        self._create_ownership_table(self._conn)
        history_rows = self._conn.execute(
            "SELECT namespace, checkpoint_sha256 AS head_sha256, sequence, "
            "receipt_json, envelope_json FROM checkpoint_history "
            "ORDER BY namespace ASC, sequence ASC"
        ).fetchall()
        checkpoint_owners: dict[str, str] = {}
        envelope_owners: dict[str, str] = {}
        pairs_by_key: dict[tuple[str, int], dict[str, Any]] = {}
        history_by_namespace: dict[str, list[dict[str, Any]]] = {}
        for row in history_rows:
            pair = self._decode_row_pair_unowned(row)
            namespace = pair["namespace"]
            checkpoint_sha256 = pair["head_sha256"]
            envelope_sha256 = str(pair["receipt"]["envelope_sha256"])
            previous_checkpoint_owner = checkpoint_owners.get(checkpoint_sha256)
            previous_envelope_owner = envelope_owners.get(envelope_sha256)
            if previous_checkpoint_owner is not None and previous_checkpoint_owner != namespace:
                raise CheckpointStoreError(
                    "checkpoint_store_namespace_replay",
                    "legacy database assigns one checkpoint identity to multiple namespaces",
                )
            if previous_envelope_owner is not None and previous_envelope_owner != namespace:
                raise CheckpointStoreError(
                    "checkpoint_store_namespace_replay",
                    "legacy database assigns one envelope identity to multiple namespaces",
                )
            checkpoint_owners[checkpoint_sha256] = namespace
            envelope_owners[envelope_sha256] = namespace
            pairs_by_key[(namespace, int(pair["receipt"]["sequence"]))] = pair
            history_by_namespace.setdefault(namespace, []).append(pair)
            self._conn.execute(
                "INSERT INTO checkpoint_ownership "
                "(checkpoint_sha256, envelope_sha256, namespace, sequence) VALUES (?, ?, ?, ?)",
                (
                    checkpoint_sha256,
                    envelope_sha256,
                    namespace,
                    pair["receipt"]["sequence"],
                ),
            )

        current_rows = self._conn.execute(
            "SELECT namespace, head_sha256, sequence, receipt_json, envelope_json "
            "FROM checkpoint_current ORDER BY namespace ASC"
        ).fetchall()
        current_by_namespace: dict[str, dict[str, Any]] = {}
        for row in current_rows:
            current = self._decode_row_pair_unowned(row)
            key = (current["namespace"], int(current["receipt"]["sequence"]))
            if pairs_by_key.get(key) != current:
                raise CheckpointStoreError(
                    "checkpoint_store_corrupt_state",
                    "legacy current checkpoint is missing or differs in immutable history",
                )
            current_by_namespace[current["namespace"]] = current
        if set(history_by_namespace) != set(current_by_namespace):
            raise CheckpointStoreError(
                "checkpoint_store_current_not_history_tip",
                "legacy current/history namespace sets differ",
            )
        for namespace, history in history_by_namespace.items():
            self._validate_chain_pairs(
                namespace=namespace,
                current=current_by_namespace[namespace],
                history=history,
            )

    def _initialize_schema(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, 1, 2, SCHEMA_VERSION):
                raise CheckpointStoreError(
                    "checkpoint_store_schema_mismatch",
                    f"unsupported checkpoint store schema version {version}",
                )
            if version == 0:
                self._create_base_tables(self._conn)
                self._create_ownership_table(self._conn)
                self._create_scope_table(self._conn)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version == 1:
                if not self._table_exists(self._conn, "checkpoint_current") or not self._table_exists(
                    self._conn, "checkpoint_history"
                ):
                    raise CheckpointStoreError(
                        "checkpoint_store_schema_mismatch",
                        "legacy checkpoint schema is incomplete",
                    )
                self._migrate_v1_to_v2()
                self._create_scope_table(self._conn)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version == 2:
                for name in ("checkpoint_current", "checkpoint_history", "checkpoint_ownership"):
                    if not self._table_exists(self._conn, name):
                        raise CheckpointStoreError(
                            "checkpoint_store_schema_mismatch",
                            f"checkpoint schema v2 is missing table {name}",
                        )
                self._create_scope_table(self._conn)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            else:
                for name in (
                    "checkpoint_current",
                    "checkpoint_history",
                    "checkpoint_ownership",
                    "checkpoint_scope",
                ):
                    if not self._table_exists(self._conn, name):
                        raise CheckpointStoreError(
                            "checkpoint_store_schema_mismatch",
                            f"checkpoint schema v{SCHEMA_VERSION} is missing table {name}",
                        )
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

    def _select_history_rows(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT namespace, checkpoint_sha256 AS head_sha256, sequence, "
            "receipt_json, envelope_json FROM checkpoint_history "
            "WHERE namespace = ? ORDER BY sequence ASC",
            (self._namespace,),
        ).fetchall()

    @staticmethod
    def _validate_chain_pairs(
        *,
        namespace: str,
        current: Mapping[str, Any],
        history: Sequence[Mapping[str, Any]],
    ) -> None:
        current_receipt = current.get("receipt")
        if not isinstance(current_receipt, Mapping):
            raise CheckpointStoreError(
                "checkpoint_store_corrupt_state",
                "current checkpoint receipt is missing",
            )
        current_sequence = current_receipt.get("sequence")
        if type(current_sequence) is not int or current_sequence < 1:
            raise CheckpointStoreError(
                "checkpoint_store_corrupt_state",
                "current checkpoint sequence is invalid",
            )
        if not history:
            raise CheckpointStoreError(
                "checkpoint_store_history_incomplete",
                "non-empty current state has no immutable history",
            )

        observed_sequences: list[int] = []
        for pair in history:
            if pair.get("namespace") != namespace:
                raise CheckpointStoreError(
                    "checkpoint_store_namespace_replay",
                    "history row belongs to another namespace",
                )
            receipt = pair.get("receipt")
            if not isinstance(receipt, Mapping) or type(receipt.get("sequence")) is not int:
                raise CheckpointStoreError(
                    "checkpoint_store_corrupt_state",
                    "history checkpoint sequence is invalid",
                )
            observed_sequences.append(int(receipt["sequence"]))

        if observed_sequences[-1] > current_sequence:
            raise CheckpointStoreError(
                "checkpoint_store_current_not_history_tip",
                "immutable history contains a checkpoint after current state",
            )
        expected_sequences = list(range(1, current_sequence + 1))
        if observed_sequences != expected_sequences:
            raise CheckpointStoreError(
                "checkpoint_store_history_incomplete",
                "immutable history is truncated or contains a sequence gap",
            )
        if dict(history[-1]) != dict(current):
            raise CheckpointStoreError(
                "checkpoint_store_current_not_history_tip",
                "current checkpoint differs from the immutable history tip",
            )

        previous_receipt: Mapping[str, Any] | None = None
        for pair in history:
            receipt = pair["receipt"]
            if previous_receipt is None:
                if receipt.get("previous_envelope_sha256") is not None:
                    raise CheckpointStoreError(
                        "checkpoint_store_history_chain_mismatch",
                        "history genesis has a non-null parent",
                    )
            else:
                if receipt.get("previous_envelope_sha256") != previous_receipt.get("envelope_sha256"):
                    raise CheckpointStoreError(
                        "checkpoint_store_history_chain_mismatch",
                        "history successor parent does not match the previous envelope",
                    )
                if int(receipt.get("evaluation_tick", -1)) < int(previous_receipt.get("evaluation_tick", -1)):
                    raise CheckpointStoreError(
                        "checkpoint_store_history_chain_mismatch",
                        "history evaluation time rolls back",
                    )
                for field in ("authority_id", "key_id", "authority_root_sha256"):
                    if receipt.get(field) != previous_receipt.get(field):
                        raise CheckpointStoreError(
                            "checkpoint_store_history_chain_mismatch",
                            f"history {field} continuity mismatch",
                        )
            previous_receipt = receipt

    def _validated_namespace_state(
        self,
        *,
        current_row: sqlite3.Row | None = None,
    ) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        row = self._select_current_row() if current_row is None else current_row
        history_rows = self._select_history_rows()
        if row is None:
            if history_rows:
                raise CheckpointStoreError(
                    "checkpoint_store_current_not_history_tip",
                    "immutable history exists without current state",
                )
            return None, []
        current = self._row_pair(row)
        history = [self._row_pair(item) for item in history_rows]
        self._validate_chain_pairs(
            namespace=self._namespace,
            current=current,
            history=history,
        )
        return current, history

    @staticmethod
    def _authenticate_history(
        history: Sequence[Mapping[str, Any]],
        *,
        authority_roots: Sequence[Mapping[str, Any]],
    ) -> None:
        for pair in history:
            try:
                ProvenanceTrustStateGuard.from_checkpoint(
                    authority_roots=authority_roots,
                    checkpoint_receipt=pair["receipt"],
                    trust_envelope=pair["envelope"],
                    expected_checkpoint_sha256=pair["head_sha256"],
                )
            except TrustSnapshotStateError as exc:
                raise CheckpointStoreError(
                    "checkpoint_store_corrupt_state",
                    f"immutable history authentication failed: {exc}",
                ) from exc

    def _scope_row(self, checkpoint_sha256: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT checkpoint_sha256, envelope_sha256, namespace, namespace_sha256, "
            "scope_envelope_sha256, scope_envelope_json FROM checkpoint_scope "
            "WHERE checkpoint_sha256 = ?",
            (checkpoint_sha256,),
        ).fetchone()

    @staticmethod
    def _decode_scope_row(row: sqlite3.Row) -> dict[str, Any]:
        scope = _decode_canonical(row["scope_envelope_json"], label="checkpoint scope envelope")
        exact = {
            "checkpoint_sha256": row["checkpoint_sha256"],
            "envelope_sha256": row["envelope_sha256"],
            "namespace_sha256": row["namespace_sha256"],
            "scope_envelope_sha256": row["scope_envelope_sha256"],
        }
        for field, observed in exact.items():
            if scope.get(field) != observed:
                raise CheckpointStoreError(
                    "checkpoint_store_corrupt_state",
                    f"stored checkpoint scope field {field} differs from its indexed value",
                )
        return {
            "namespace": str(row["namespace"]),
            "scope": scope,
        }

    def _scope_rows_for_namespace(self) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT checkpoint_sha256, envelope_sha256, namespace, namespace_sha256, "
            "scope_envelope_sha256, scope_envelope_json FROM checkpoint_scope "
            "WHERE namespace = ? ORDER BY checkpoint_sha256 ASC",
            (self._namespace,),
        ).fetchall()

    def _namespace_has_scope_rows(self) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM checkpoint_scope WHERE namespace = ? LIMIT 1",
            (self._namespace,),
        ).fetchone() is not None

    def _authenticate_scope_history(
        self,
        history: Sequence[Mapping[str, Any]],
        *,
        authority_roots: Sequence[Mapping[str, Any]],
        current_scope_tick: int | None = None,
    ) -> list[dict[str, Any]]:
        authenticated: list[dict[str, Any]] = []
        for index, pair in enumerate(history):
            receipt = pair.get("receipt")
            envelope = pair.get("envelope")
            if not isinstance(receipt, Mapping) or not isinstance(envelope, Mapping):
                raise CheckpointStoreError(
                    "checkpoint_store_corrupt_state",
                    "scoped history contains an invalid checkpoint pair",
                )
            checkpoint_sha256 = str(pair.get("head_sha256"))
            row = self._scope_row(checkpoint_sha256)
            if row is None:
                raise CheckpointStoreError(
                    "checkpoint_scope_history_incomplete",
                    "scoped checkpoint history contains an entry without a signed scope",
                )
            decoded = self._decode_scope_row(row)
            if decoded["namespace"] != self._namespace:
                raise CheckpointStoreError(
                    "checkpoint_scope_namespace_mismatch",
                    "stored checkpoint scope belongs to another namespace",
                )
            tick = int(receipt.get("evaluation_tick", -1))
            if current_scope_tick is not None and index == len(history) - 1:
                tick = current_scope_tick
            try:
                verified = verify_checkpoint_scope_envelope(
                    decoded["scope"],
                    namespace=self._namespace,
                    checkpoint_sha256=checkpoint_sha256,
                    trust_envelope_sha256=str(envelope.get("envelope_sha256")),
                    authority_roots=authority_roots,
                    trusted_evaluation_tick=tick,
                )
            except CheckpointScopeError as exc:
                raise CheckpointStoreError(exc.code, str(exc)) from exc
            authenticated.append(deepcopy(verified.envelope))
        return authenticated

    def _claim_scope_binding(self, scope: AuthenticatedCheckpointScope) -> None:
        checkpoint_sha256 = scope.checkpoint_sha256
        scope_sha256 = scope.scope_envelope_sha256
        rows = self._conn.execute(
            "SELECT checkpoint_sha256, envelope_sha256, namespace, namespace_sha256, "
            "scope_envelope_sha256, scope_envelope_json FROM checkpoint_scope "
            "WHERE checkpoint_sha256 = ? OR scope_envelope_sha256 = ?",
            (checkpoint_sha256, scope_sha256),
        ).fetchall()
        expected = {
            "namespace": self._namespace,
            "checkpoint_sha256": checkpoint_sha256,
            "envelope_sha256": scope.trust_envelope_sha256,
            "namespace_sha256": scope.namespace_sha256,
            "scope_envelope_sha256": scope_sha256,
            "scope": scope.envelope,
        }
        if rows:
            if len(rows) != 1:
                raise CheckpointStoreError(
                    "checkpoint_scope_binding_conflict",
                    "checkpoint scope identities resolve to multiple durable rows",
                )
            decoded = self._decode_scope_row(rows[0])
            observed = {
                "namespace": decoded["namespace"],
                "checkpoint_sha256": str(rows[0]["checkpoint_sha256"]),
                "envelope_sha256": str(rows[0]["envelope_sha256"]),
                "namespace_sha256": str(rows[0]["namespace_sha256"]),
                "scope_envelope_sha256": str(rows[0]["scope_envelope_sha256"]),
                "scope": decoded["scope"],
            }
            if observed != expected:
                raise CheckpointStoreError(
                    "checkpoint_scope_binding_conflict",
                    "checkpoint or scope identity is already bound to different bytes",
                )
            return
        self._conn.execute(
            "INSERT INTO checkpoint_scope "
            "(checkpoint_sha256, envelope_sha256, namespace, namespace_sha256, "
            "scope_envelope_sha256, scope_envelope_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                checkpoint_sha256,
                scope.trust_envelope_sha256,
                self._namespace,
                scope.namespace_sha256,
                scope_sha256,
                canonical_json_bytes(scope.envelope),
            ),
        )

    def _assert_unscoped_mode(self, checkpoint_sha256: str) -> None:
        if self._namespace_has_scope_rows() or self._scope_row(checkpoint_sha256) is not None:
            raise CheckpointStoreError(
                "checkpoint_scope_envelope_required",
                "a scope-bound checkpoint lineage cannot be changed through the legacy unscoped API",
            )

    def _owner_row(self, checkpoint_sha256: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT checkpoint_sha256, envelope_sha256, namespace, sequence "
            "FROM checkpoint_ownership WHERE checkpoint_sha256 = ?",
            (checkpoint_sha256,),
        ).fetchone()

    def _assert_pair_ownership(self, pair: Mapping[str, Any]) -> None:
        receipt = pair.get("receipt")
        if not isinstance(receipt, Mapping):
            raise CheckpointStoreError("checkpoint_store_corrupt_state", "stored checkpoint receipt missing")
        checkpoint_sha256 = str(pair.get("head_sha256"))
        owner = self._owner_row(checkpoint_sha256)
        if owner is None:
            raise CheckpointStoreError(
                "checkpoint_store_corrupt_state",
                "stored checkpoint has no durable namespace owner",
            )
        namespace = str(pair.get("namespace"))
        if str(owner["namespace"]) != namespace:
            raise CheckpointStoreError(
                "checkpoint_store_namespace_replay",
                "checkpoint identity is owned by another namespace",
            )
        if str(owner["envelope_sha256"]) != str(receipt.get("envelope_sha256")):
            raise CheckpointStoreError(
                "checkpoint_store_corrupt_state",
                "checkpoint owner envelope differs from stored receipt",
            )
        if int(owner["sequence"]) != int(receipt.get("sequence", -1)):
            raise CheckpointStoreError(
                "checkpoint_store_corrupt_state",
                "checkpoint owner sequence differs from stored receipt",
            )

    def _row_pair(self, row: sqlite3.Row) -> dict[str, Any]:
        pair = self._decode_row_pair_unowned(row)
        self._assert_pair_ownership(pair)
        return pair

    def _claim_pair_ownership(self, receipt: Mapping[str, Any]) -> None:
        checkpoint_sha256 = str(receipt["checkpoint_sha256"])
        envelope_sha256 = str(receipt["envelope_sha256"])
        sequence = int(receipt["sequence"])
        by_checkpoint = self._owner_row(checkpoint_sha256)
        by_envelope = self._conn.execute(
            "SELECT checkpoint_sha256, envelope_sha256, namespace, sequence "
            "FROM checkpoint_ownership WHERE envelope_sha256 = ?",
            (envelope_sha256,),
        ).fetchone()
        for owner in (by_checkpoint, by_envelope):
            if owner is None:
                continue
            if str(owner["namespace"]) != self._namespace:
                raise CheckpointStoreError(
                    "checkpoint_store_namespace_replay",
                    "checkpoint or envelope identity is already owned by another namespace",
                )
            if (
                str(owner["checkpoint_sha256"]) != checkpoint_sha256
                or str(owner["envelope_sha256"]) != envelope_sha256
                or int(owner["sequence"]) != sequence
            ):
                raise CheckpointStoreError(
                    "checkpoint_store_head_collision",
                    "namespace owner identifies different checkpoint bytes",
                )
        if by_checkpoint is None and by_envelope is None:
            self._conn.execute(
                "INSERT INTO checkpoint_ownership "
                "(checkpoint_sha256, envelope_sha256, namespace, sequence) VALUES (?, ?, ?, ?)",
                (checkpoint_sha256, envelope_sha256, self._namespace, sequence),
            )

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
                current, _ = self._validated_namespace_state()
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            return None if current is None else deepcopy(current)

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            self._ensure_open()
            try:
                _, history = self._validated_namespace_state()
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            return deepcopy(history)

    def load_guard(
        self,
        *,
        authority_roots: Sequence[Mapping[str, Any]],
        expected_checkpoint_sha256: str,
    ) -> ProvenanceTrustStateGuard:
        """Restore an explicitly legacy, unscoped durable lineage."""

        if not _is_hex64(expected_checkpoint_sha256):
            raise CheckpointStoreError(
                "invalid_checkpoint_store_head",
                "expected checkpoint head must be 64 lowercase hexadecimal characters",
            )
        with self._lock:
            self._ensure_open()
            try:
                current, history = self._validated_namespace_state()
                if current is not None:
                    self._assert_unscoped_mode(current["head_sha256"])
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            if current is None:
                raise CheckpointStoreError("checkpoint_store_empty", "checkpoint store has no current state")
            if current["head_sha256"] != expected_checkpoint_sha256:
                raise CheckpointStoreError(
                    "checkpoint_store_head_mismatch",
                    "durable head does not match the host-controlled expected head",
                )
            self._authenticate_history(history, authority_roots=authority_roots)
            try:
                return ProvenanceTrustStateGuard.from_checkpoint(
                    authority_roots=authority_roots,
                    checkpoint_receipt=current["receipt"],
                    trust_envelope=current["envelope"],
                    expected_checkpoint_sha256=expected_checkpoint_sha256,
                )
            except TrustSnapshotStateError as exc:
                raise CheckpointStoreError("checkpoint_store_corrupt_state", str(exc)) from exc

    def get_scope_binding(self, *, checkpoint_sha256: str) -> dict[str, Any] | None:
        """Return one exact stored scope envelope for inspection."""

        if not _is_hex64(checkpoint_sha256):
            raise CheckpointStoreError(
                "invalid_checkpoint_store_head",
                "checkpoint head must be 64 lowercase hexadecimal characters",
            )
        with self._lock:
            self._ensure_open()
            try:
                row = self._scope_row(checkpoint_sha256)
                if row is None:
                    return None
                return deepcopy(self._decode_scope_row(row))
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc

    def load_guard_scoped(
        self,
        *,
        authority_roots: Sequence[Mapping[str, Any]],
        expected_checkpoint_sha256: str,
        trusted_evaluation_tick: int,
    ) -> ProvenanceTrustStateGuard:
        """Restore a complete scope-bound lineage under host time and head anchors."""

        if not _is_hex64(expected_checkpoint_sha256):
            raise CheckpointStoreError(
                "invalid_checkpoint_store_head",
                "expected checkpoint head must be 64 lowercase hexadecimal characters",
            )
        if type(trusted_evaluation_tick) is not int or trusted_evaluation_tick < 0:
            raise CheckpointStoreError(
                "invalid_checkpoint_scope_time",
                "trusted evaluation tick must be an integer >= 0",
            )
        with self._lock:
            self._ensure_open()
            try:
                current, history = self._validated_namespace_state()
            except sqlite3.Error as exc:
                raise CheckpointStoreError("checkpoint_store_io_error", str(exc)) from exc
            if current is None:
                raise CheckpointStoreError("checkpoint_store_empty", "checkpoint store has no current state")
            if current["head_sha256"] != expected_checkpoint_sha256:
                raise CheckpointStoreError(
                    "checkpoint_store_head_mismatch",
                    "durable head does not match the host-controlled expected head",
                )
            self._authenticate_history(history, authority_roots=authority_roots)
            self._authenticate_scope_history(
                history,
                authority_roots=authority_roots,
                current_scope_tick=trusted_evaluation_tick,
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
        """Commit through the retained legacy unscoped API.

        Once any checkpoint in this namespace is scope-bound, this entry point
        fails closed and callers must use :meth:`commit_scoped`.
        """

        receipt, envelope, _ = self._validated_pair(
            checkpoint_receipt=checkpoint_receipt,
            trust_envelope=trust_envelope,
            authority_roots=authority_roots,
        )
        return self._commit_validated(
            receipt=receipt,
            envelope=envelope,
            authority_roots=authority_roots,
            expected_previous_head=expected_previous_head,
            checkpoint_scope=None,
        )

    def commit_scoped(
        self,
        *,
        checkpoint_receipt: Mapping[str, Any],
        trust_envelope: Mapping[str, Any],
        checkpoint_scope_envelope: Mapping[str, Any] | None,
        authority_roots: Sequence[Mapping[str, Any]],
        expected_previous_head: str | None,
        trusted_evaluation_tick: int,
    ) -> str:
        """Atomically commit one exact authority-scoped checkpoint pair."""

        receipt, envelope, _ = self._validated_pair(
            checkpoint_receipt=checkpoint_receipt,
            trust_envelope=trust_envelope,
            authority_roots=authority_roots,
        )
        if type(trusted_evaluation_tick) is not int or trusted_evaluation_tick < 0:
            raise CheckpointStoreError(
                "invalid_checkpoint_scope_time",
                "trusted evaluation tick must be an integer >= 0",
            )
        try:
            scope = verify_checkpoint_scope_envelope(
                checkpoint_scope_envelope,
                namespace=self._namespace,
                checkpoint_sha256=str(receipt["checkpoint_sha256"]),
                trust_envelope_sha256=str(envelope["envelope_sha256"]),
                authority_roots=authority_roots,
                trusted_evaluation_tick=trusted_evaluation_tick,
            )
        except CheckpointScopeError as exc:
            raise CheckpointStoreError(exc.code, str(exc)) from exc
        if trusted_evaluation_tick != receipt["evaluation_tick"]:
            raise CheckpointStoreError(
                "checkpoint_scope_time_mismatch",
                "trusted evaluation tick must equal the checkpoint evaluation tick at commit",
            )
        return self._commit_validated(
            receipt=receipt,
            envelope=envelope,
            authority_roots=authority_roots,
            expected_previous_head=expected_previous_head,
            checkpoint_scope=scope,
        )

    def _commit_validated(
        self,
        *,
        receipt: dict[str, Any],
        envelope: dict[str, Any],
        authority_roots: Sequence[Mapping[str, Any]],
        expected_previous_head: str | None,
        checkpoint_scope: AuthenticatedCheckpointScope | None,
    ) -> str:
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
                current_state, history_state = self._validated_namespace_state(current_row=row)
                if checkpoint_scope is None:
                    self._assert_unscoped_mode(new_head)
                elif history_state:
                    # A scoped successor may not silently upgrade an older
                    # unscoped prefix. Every prior checkpoint needs its own
                    # independently signed namespace intent.
                    self._authenticate_scope_history(
                        history_state,
                        authority_roots=authority_roots,
                    )

                if row is None:
                    if current_state is not None or history_state:
                        raise CheckpointStoreError(
                            "checkpoint_store_corrupt_state",
                            "empty durable state validation returned unexpected rows",
                        )
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
                    if current_state is None:
                        raise CheckpointStoreError(
                            "checkpoint_store_corrupt_state",
                            "non-empty durable row has no validated current state",
                        )
                    current = current_state
                    self._authenticate_history(history_state, authority_roots=authority_roots)

                    # Unknown-outcome reconciliation: if the exact requested
                    # pair is already the durable head, validate its immutable
                    # history position and exact predecessor claim, then return
                    # without appending or updating anything.
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
                        if checkpoint_scope is not None:
                            self._claim_scope_binding(checkpoint_scope)
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

                self._claim_pair_ownership(receipt)
                if checkpoint_scope is not None:
                    self._claim_scope_binding(checkpoint_scope)
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
