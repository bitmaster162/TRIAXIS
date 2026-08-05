"""TRIAXIS v3.8 external trust-registry head witness.

A local registry database cannot prove that an older copy of itself was not
restored. This module requires a fresh, separately signed witness for the exact
accepted registry sequence and snapshot digest before operational keys are
loaded.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
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

# v3.9 challenge-bound anchor freshness.
TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID = "TRIAXIS_TRUST_REGISTRY_CHALLENGE_WITNESS_v1"


def _challenge_digest(challenge: str) -> str:
    import hashlib
    if not isinstance(challenge, str) or len(challenge) < 32:
        raise ValueError("challenge must be an unpredictable string of at least 32 characters")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def make_challenge_bound_head_witness(
    *,
    anchor_id: str,
    registry_id: str,
    sequence: int,
    snapshot_sha256: str,
    verifier_id: str,
    challenge_sha256: str,
    requested_at: int,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return seal_mapping(
        {
            "contract_id": TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID,
            "anchor_id": anchor_id,
            "registry_id": registry_id,
            "sequence": sequence,
            "snapshot_sha256": snapshot_sha256,
            "verifier_id": verifier_id,
            "challenge_sha256": challenge_sha256,
            "requested_at": requested_at,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def validate_challenge_bound_head_witness(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "anchor", "mapping required")]}
    try:
        witness = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "anchor", type(exc).__name__)]}
    if not isinstance(witness, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "anchor", "object required")]}
    if witness.get("contract_id") != TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "anchor.contract_id", "unexpected challenge witness contract"))
    if not verify_sealed_mapping(witness, "witness_sha256"):
        errors.append(_error("digest_mismatch", "anchor.witness_sha256", "canonical digest mismatch"))
    for field in ("anchor_id", "registry_id", "verifier_id"):
        if not isinstance(witness.get(field), str) or not witness.get(field):
            errors.append(_error("missing_required", f"anchor.{field}", f"{field} required"))
    if type(witness.get("sequence")) is not int or witness.get("sequence", -1) < 1:
        errors.append(_error("invalid_sequence", "anchor.sequence", "integer >= 1 required"))
    for field in ("snapshot_sha256", "challenge_sha256"):
        if not _is_sha256(witness.get(field)):
            errors.append(_error("invalid_digest", f"anchor.{field}", "lowercase SHA-256 required"))
    requested_at, issued_at, valid_until = witness.get("requested_at"), witness.get("issued_at"), witness.get("valid_until")
    for field, item in (("requested_at", requested_at), ("issued_at", issued_at), ("valid_until", valid_until)):
        if type(item) is not int or item < 0:
            errors.append(_error("invalid_time", f"anchor.{field}", "integer >= 0 required"))
    if type(requested_at) is int and type(issued_at) is int and issued_at < requested_at:
        errors.append(_error("issued_before_request", "anchor.issued_at", "must not predate request"))
    if type(issued_at) is int and type(valid_until) is int and valid_until <= issued_at:
        errors.append(_error("invalid_anchor_window", "anchor.valid_until", "must be after issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_anchor", "anchor.issued_at", "anchor from the future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("stale_anchor", "anchor.valid_until", "anchor expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "witness": witness}


class SQLiteAnchorChallengeLedger:
    """Durable single-use verifier challenges for anchor freshness."""

    def __init__(self, path: str | Path) -> None:
        import sqlite3
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS anchor_challenges (
                challenge_sha256 TEXT PRIMARY KEY,
                verifier_id TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                consumed_at INTEGER
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteAnchorChallengeLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def issue(self, verifier_id: str, issued_at: int, expires_at: int) -> str:
        import secrets
        if not isinstance(verifier_id, str) or not verifier_id:
            raise TrustRegistryAnchorError("invalid_verifier_id", "non-empty verifier_id required")
        if type(issued_at) is not int or type(expires_at) is not int or expires_at <= issued_at:
            raise TrustRegistryAnchorError("invalid_challenge_window", "expires_at must be after issued_at")
        challenge = secrets.token_urlsafe(32)
        digest = _challenge_digest(challenge)
        self._conn.execute(
            "INSERT INTO anchor_challenges(challenge_sha256,verifier_id,issued_at,expires_at,state) VALUES(?,?,?,?,?)",
            (digest, verifier_id, issued_at, expires_at, "ISSUED"),
        )
        return challenge

    def inspect_issued(self, challenge: str, verifier_id: str, evaluation_tick: int) -> dict[str, Any]:
        digest = _challenge_digest(challenge)
        row = self._conn.execute(
            "SELECT verifier_id,issued_at,expires_at,state,consumed_at FROM anchor_challenges WHERE challenge_sha256=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise TrustRegistryAnchorError("unknown_challenge", digest)
        if row[0] != verifier_id:
            raise TrustRegistryAnchorError("challenge_verifier_mismatch", str(row[0]))
        if evaluation_tick < row[1]:
            raise TrustRegistryAnchorError("challenge_not_yet_valid", str(row[1]))
        if evaluation_tick >= row[2]:
            raise TrustRegistryAnchorError("challenge_expired", str(row[2]))
        if row[3] != "ISSUED":
            raise TrustRegistryAnchorError("challenge_replay", str(row[3]))
        return {
            "challenge_sha256": digest,
            "verifier_id": row[0],
            "issued_at": row[1],
            "expires_at": row[2],
            "state": row[3],
            "consumed_at": row[4],
        }

    def consume(self, challenge: str, verifier_id: str, evaluation_tick: int) -> None:
        digest = _challenge_digest(challenge)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT verifier_id,issued_at,expires_at,state FROM anchor_challenges WHERE challenge_sha256=?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TrustRegistryAnchorError("unknown_challenge", digest)
            if row[0] != verifier_id:
                raise TrustRegistryAnchorError("challenge_verifier_mismatch", str(row[0]))
            if evaluation_tick < row[1]:
                raise TrustRegistryAnchorError("challenge_not_yet_valid", str(row[1]))
            if evaluation_tick >= row[2]:
                raise TrustRegistryAnchorError("challenge_expired", str(row[2]))
            if row[3] != "ISSUED":
                raise TrustRegistryAnchorError("challenge_replay", str(row[3]))
            updated = self._conn.execute(
                "UPDATE anchor_challenges SET state='CONSUMED', consumed_at=? "
                "WHERE challenge_sha256=? AND state='ISSUED'",
                (evaluation_tick, digest),
            ).rowcount
            if updated != 1:
                raise TrustRegistryAnchorError("challenge_replay", "challenge consumed concurrently")
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise


def load_registry_with_challenge_bound_anchor(
    store: SQLiteTrustRegistryStore,
    signed_anchor_value: Mapping[str, Any],
    *,
    anchor_registry: TrustKeyRegistry,
    challenge_ledger: SQLiteAnchorChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    expected_verifier_id: str,
    expected_anchor_signer_id: str,
    expected_anchor_trust_domain: str,
    expected_anchor_id: str,
    max_anchor_age: int = 5,
) -> TrustKeyRegistry:
    """Verify a one-time challenge response and exact local registry head."""
    signed_result = verify_contract_envelope(
        signed_anchor_value,
        registry=anchor_registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_TRUST_REGISTRY_ANCHOR,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID,
        expected_signer_id=expected_anchor_signer_id,
        expected_trust_domain=expected_anchor_trust_domain,
    )
    if signed_result["status"] != "PASS":
        raise TrustRegistryAnchorError("invalid_external_anchor_signature", str(signed_result["errors"]))
    witness_result = validate_challenge_bound_head_witness(signed_result["inner_contract"], evaluation_tick)
    if witness_result["status"] != "PASS":
        raise TrustRegistryAnchorError("invalid_external_anchor", str(witness_result["errors"]))
    witness = witness_result["witness"]
    if witness["anchor_id"] != expected_anchor_id:
        raise TrustRegistryAnchorError("anchor_id_mismatch", str(witness["anchor_id"]))
    if witness["registry_id"] != store.registry_id:
        raise TrustRegistryAnchorError("anchor_registry_id_mismatch", str(witness["registry_id"]))
    if witness["verifier_id"] != expected_verifier_id:
        raise TrustRegistryAnchorError("anchor_verifier_mismatch", str(witness["verifier_id"]))
    challenge_record = challenge_ledger.inspect_issued(
        expected_challenge, expected_verifier_id, evaluation_tick
    )
    if witness["challenge_sha256"] != challenge_record["challenge_sha256"]:
        raise TrustRegistryAnchorError("anchor_challenge_mismatch", "response not bound to verifier challenge")
    if witness["requested_at"] != challenge_record["issued_at"]:
        raise TrustRegistryAnchorError(
            "anchor_request_time_mismatch",
            f"witness={witness['requested_at']} ledger={challenge_record['issued_at']}",
        )
    if type(max_anchor_age) is not int or max_anchor_age < 0:
        raise TrustRegistryAnchorError("invalid_max_anchor_age", str(max_anchor_age))
    if evaluation_tick - witness["issued_at"] > max_anchor_age:
        raise TrustRegistryAnchorError("anchor_response_too_old", str(witness["issued_at"]))
    head = store.head()
    if head is None:
        raise TrustRegistryAnchorError("local_registry_missing", store.registry_id)
    if head["sequence"] < witness["sequence"]:
        raise TrustRegistryAnchorError("local_registry_rollback", f"local={head['sequence']} anchor={witness['sequence']}")
    if head["sequence"] > witness["sequence"]:
        raise TrustRegistryAnchorError("stale_external_anchor", f"local={head['sequence']} anchor={witness['sequence']}")
    if head["snapshot_sha256"] != witness["snapshot_sha256"]:
        raise TrustRegistryAnchorError("local_registry_fork", "sequence matches but snapshot digest differs")
    # Materialize the registry before burning the single-use challenge. The
    # final consume is transactional, so concurrent verifiers cannot both pass.
    registry = store.load_registry(evaluation_tick)
    challenge_ledger.consume(expected_challenge, expected_verifier_id, evaluation_tick)
    return registry


__all__ += [
    "SQLiteAnchorChallengeLedger",
    "TRUST_REGISTRY_CHALLENGE_WITNESS_CONTRACT_ID",
    "load_registry_with_challenge_bound_anchor",
    "make_challenge_bound_head_witness",
    "validate_challenge_bound_head_witness",
]
