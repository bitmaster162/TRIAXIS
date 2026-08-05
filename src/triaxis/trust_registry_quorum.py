"""TRIAXIS v3.10 verifier epochs and distinct-anchor quorum witnesses.

v3.9 binds an external registry witness to a fresh single-use challenge, but a
restored challenge database can revive an old challenge and one trusted anchor
can equivocate across verifiers. This module adds:

* an ephemeral verifier epoch that is not recovered from the challenge DB;
* challenge rows and witnesses bound to that epoch;
* threshold agreement by distinct anchor identities and trust domains.

The reference implementation does not claim protection against compromise of a
threshold of anchors, process-memory capture, or a hostile administrator that
can replace both code and live process state.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import secrets
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_TRUST_REGISTRY_ANCHOR,
    TrustKeyRegistry,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_anchor import TrustRegistryAnchorError
from .trust_registry_state import SQLiteTrustRegistryStore

TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID = (
    "TRIAXIS_TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_v1"
)


def _sha256_text(value: str) -> str:
    if not isinstance(value, str) or len(value) < 32:
        raise ValueError("unpredictable string of at least 32 characters required")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


@dataclass(frozen=True)
class VerifierFreshnessSession:
    """Ephemeral verifier epoch.

    The token is generated at process/session start and is intentionally not
    reconstructed from the challenge ledger. Only its digest is disclosed.
    """

    verifier_id: str
    started_at: int
    _epoch_token: str = field(repr=False)

    @classmethod
    def create(cls, verifier_id: str, started_at: int) -> "VerifierFreshnessSession":
        if not isinstance(verifier_id, str) or not verifier_id:
            raise TrustRegistryAnchorError("invalid_verifier_id", "non-empty verifier_id required")
        if type(started_at) is not int or started_at < 0:
            raise TrustRegistryAnchorError("invalid_session_start", "integer >= 0 required")
        return cls(verifier_id=verifier_id, started_at=started_at, _epoch_token=secrets.token_urlsafe(32))

    @property
    def epoch_sha256(self) -> str:
        return _sha256_text(self._epoch_token)


class SQLiteEpochChallengeLedger:
    """Single-use challenges bound to one non-persistent verifier epoch."""

    def __init__(self, path: str | Path, session: VerifierFreshnessSession) -> None:
        self.path = str(path)
        self.session = session
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS anchor_challenges_v2 (
                challenge_sha256 TEXT PRIMARY KEY,
                verifier_id TEXT NOT NULL,
                verifier_epoch_sha256 TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                consumed_at INTEGER
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteEpochChallengeLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def issue(self, issued_at: int, expires_at: int) -> str:
        if type(issued_at) is not int or type(expires_at) is not int or expires_at <= issued_at:
            raise TrustRegistryAnchorError("invalid_challenge_window", "expires_at must be after issued_at")
        if issued_at < self.session.started_at:
            raise TrustRegistryAnchorError("challenge_predates_session", str(self.session.started_at))
        challenge = secrets.token_urlsafe(32)
        digest = _sha256_text(challenge)
        self._conn.execute(
            "INSERT INTO anchor_challenges_v2(" 
            "challenge_sha256,verifier_id,verifier_epoch_sha256,issued_at,expires_at,state" 
            ") VALUES(?,?,?,?,?,?)",
            (
                digest,
                self.session.verifier_id,
                self.session.epoch_sha256,
                issued_at,
                expires_at,
                "ISSUED",
            ),
        )
        return challenge

    def inspect_issued(self, challenge: str, evaluation_tick: int) -> dict[str, Any]:
        digest = _sha256_text(challenge)
        row = self._conn.execute(
            "SELECT verifier_id,verifier_epoch_sha256,issued_at,expires_at,state,consumed_at "
            "FROM anchor_challenges_v2 WHERE challenge_sha256=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise TrustRegistryAnchorError("unknown_challenge", digest)
        if row[0] != self.session.verifier_id:
            raise TrustRegistryAnchorError("challenge_verifier_mismatch", str(row[0]))
        if row[1] != self.session.epoch_sha256:
            raise TrustRegistryAnchorError("challenge_epoch_mismatch", str(row[1]))
        if evaluation_tick < row[2]:
            raise TrustRegistryAnchorError("challenge_not_yet_valid", str(row[2]))
        if evaluation_tick >= row[3]:
            raise TrustRegistryAnchorError("challenge_expired", str(row[3]))
        if row[4] != "ISSUED":
            raise TrustRegistryAnchorError("challenge_replay", str(row[4]))
        return {
            "challenge_sha256": digest,
            "verifier_id": row[0],
            "verifier_epoch_sha256": row[1],
            "issued_at": row[2],
            "expires_at": row[3],
            "state": row[4],
            "consumed_at": row[5],
        }

    def consume(self, challenge: str, evaluation_tick: int) -> None:
        digest = _sha256_text(challenge)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT verifier_id,verifier_epoch_sha256,issued_at,expires_at,state "
                "FROM anchor_challenges_v2 WHERE challenge_sha256=?",
                (digest,),
            ).fetchone()
            if row is None:
                raise TrustRegistryAnchorError("unknown_challenge", digest)
            if row[0] != self.session.verifier_id:
                raise TrustRegistryAnchorError("challenge_verifier_mismatch", str(row[0]))
            if row[1] != self.session.epoch_sha256:
                raise TrustRegistryAnchorError("challenge_epoch_mismatch", str(row[1]))
            if evaluation_tick < row[2]:
                raise TrustRegistryAnchorError("challenge_not_yet_valid", str(row[2]))
            if evaluation_tick >= row[3]:
                raise TrustRegistryAnchorError("challenge_expired", str(row[3]))
            if row[4] != "ISSUED":
                raise TrustRegistryAnchorError("challenge_replay", str(row[4]))
            updated = self._conn.execute(
                "UPDATE anchor_challenges_v2 SET state='CONSUMED', consumed_at=? "
                "WHERE challenge_sha256=? AND state='ISSUED' AND verifier_epoch_sha256=?",
                (evaluation_tick, digest, self.session.epoch_sha256),
            ).rowcount
            if updated != 1:
                raise TrustRegistryAnchorError("challenge_replay", "challenge consumed concurrently")
            self._conn.execute("COMMIT")
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise


def make_quorum_member_witness(
    *,
    anchor_set_id: str,
    anchor_id: str,
    registry_id: str,
    sequence: int,
    snapshot_sha256: str,
    verifier_id: str,
    verifier_epoch_sha256: str,
    challenge_sha256: str,
    requested_at: int,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return seal_mapping(
        {
            "contract_id": TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID,
            "anchor_set_id": anchor_set_id,
            "anchor_id": anchor_id,
            "registry_id": registry_id,
            "sequence": sequence,
            "snapshot_sha256": snapshot_sha256,
            "verifier_id": verifier_id,
            "verifier_epoch_sha256": verifier_epoch_sha256,
            "challenge_sha256": challenge_sha256,
            "requested_at": requested_at,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def validate_quorum_member_witness(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "witness", "mapping required")]}
    try:
        witness = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "witness", type(exc).__name__)]}
    if not isinstance(witness, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "witness", "object required")]}
    if witness.get("contract_id") != TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "witness.contract_id", "unexpected quorum witness"))
    if not verify_sealed_mapping(witness, "witness_sha256"):
        errors.append(_error("digest_mismatch", "witness.witness_sha256", "canonical digest mismatch"))
    for name in ("anchor_set_id", "anchor_id", "registry_id", "verifier_id"):
        if not isinstance(witness.get(name), str) or not witness.get(name):
            errors.append(_error("missing_required", f"witness.{name}", f"{name} required"))
    if type(witness.get("sequence")) is not int or witness.get("sequence", -1) < 1:
        errors.append(_error("invalid_sequence", "witness.sequence", "integer >= 1 required"))
    for name in ("snapshot_sha256", "verifier_epoch_sha256", "challenge_sha256"):
        if not _is_sha256(witness.get(name)):
            errors.append(_error("invalid_digest", f"witness.{name}", "lowercase SHA-256 required"))
    requested_at = witness.get("requested_at")
    issued_at = witness.get("issued_at")
    valid_until = witness.get("valid_until")
    for name, item in (("requested_at", requested_at), ("issued_at", issued_at), ("valid_until", valid_until)):
        if type(item) is not int or item < 0:
            errors.append(_error("invalid_time", f"witness.{name}", "integer >= 0 required"))
    if type(requested_at) is int and type(issued_at) is int and issued_at < requested_at:
        errors.append(_error("issued_before_request", "witness.issued_at", "must not predate request"))
    if type(issued_at) is int and type(valid_until) is int and valid_until <= issued_at:
        errors.append(_error("invalid_witness_window", "witness.valid_until", "must be after issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_witness", "witness.issued_at", "witness from future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("stale_witness", "witness.valid_until", "witness expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "witness": witness}


def _core_statement(witness: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        witness["anchor_set_id"],
        witness["registry_id"],
        witness["sequence"],
        witness["snapshot_sha256"],
        witness["verifier_id"],
        witness["verifier_epoch_sha256"],
        witness["challenge_sha256"],
        witness["requested_at"],
    )


def load_registry_with_quorum_anchors(
    store: SQLiteTrustRegistryStore,
    signed_witnesses: Sequence[Mapping[str, Any]],
    *,
    anchor_registry: TrustKeyRegistry,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    trusted_anchor_authorities: Mapping[str, Mapping[str, str]],
    expected_anchor_set_id: str,
    threshold: int,
    max_anchor_age: int = 5,
) -> TrustKeyRegistry:
    """Require one matching statement signed by a distinct-anchor quorum."""
    if type(threshold) is not int or threshold < 2:
        raise TrustRegistryAnchorError("invalid_anchor_threshold", "threshold must be >= 2")
    if threshold > len(trusted_anchor_authorities):
        raise TrustRegistryAnchorError("impossible_anchor_threshold", str(threshold))
    if not isinstance(signed_witnesses, Sequence) or isinstance(signed_witnesses, (str, bytes)):
        raise TrustRegistryAnchorError("invalid_anchor_witnesses", "sequence required")
    challenge_record = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    valid_by_statement: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    seen_signers: dict[str, tuple[Any, ...]] = {}
    seen_keys: set[str] = set()
    invalid_rows: list[dict[str, Any]] = []

    for index, signed in enumerate(signed_witnesses):
        result = verify_contract_envelope(
            signed,
            registry=anchor_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_TRUST_REGISTRY_ANCHOR,
            expected_digest_field="witness_sha256",
            expected_inner_contract_id=TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID,
        )
        if result["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "signature", "errors": result["errors"]})
            continue
        signer = result["verified_signer"]
        assert signer is not None
        authority = trusted_anchor_authorities.get(signer.signer_id)
        if not isinstance(authority, Mapping):
            invalid_rows.append({"index": index, "reason": "untrusted_anchor", "signer_id": signer.signer_id})
            continue
        if authority.get("trust_domain") != signer.trust_domain:
            invalid_rows.append({"index": index, "reason": "authority_domain_mismatch", "signer_id": signer.signer_id})
            continue
        witness_result = validate_quorum_member_witness(result["inner_contract"], evaluation_tick)
        if witness_result["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "witness", "errors": witness_result["errors"]})
            continue
        witness = witness_result["witness"]
        if witness["anchor_id"] != authority.get("anchor_id"):
            invalid_rows.append({"index": index, "reason": "anchor_id_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["anchor_set_id"] != expected_anchor_set_id:
            invalid_rows.append({"index": index, "reason": "anchor_set_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["registry_id"] != store.registry_id:
            invalid_rows.append({"index": index, "reason": "registry_id_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["verifier_id"] != challenge_ledger.session.verifier_id:
            invalid_rows.append({"index": index, "reason": "verifier_id_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["verifier_epoch_sha256"] != challenge_ledger.session.epoch_sha256:
            invalid_rows.append({"index": index, "reason": "verifier_epoch_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["challenge_sha256"] != challenge_record["challenge_sha256"]:
            invalid_rows.append({"index": index, "reason": "challenge_mismatch", "signer_id": signer.signer_id})
            continue
        if witness["requested_at"] != challenge_record["issued_at"]:
            invalid_rows.append({"index": index, "reason": "request_time_mismatch", "signer_id": signer.signer_id})
            continue
        if type(max_anchor_age) is not int or max_anchor_age < 0:
            raise TrustRegistryAnchorError("invalid_max_anchor_age", str(max_anchor_age))
        if evaluation_tick - witness["issued_at"] > max_anchor_age:
            invalid_rows.append({"index": index, "reason": "response_too_old", "signer_id": signer.signer_id})
            continue
        statement = _core_statement(witness)
        previous = seen_signers.get(signer.signer_id)
        if previous is not None:
            if previous != statement:
                raise TrustRegistryAnchorError("anchor_signer_equivocation", signer.signer_id)
            continue
        if signer.key_id in seen_keys:
            raise TrustRegistryAnchorError("duplicate_anchor_key", signer.key_id)
        seen_signers[signer.signer_id] = statement
        seen_keys.add(signer.key_id)
        valid_by_statement[statement].append(
            {
                "signer_id": signer.signer_id,
                "trust_domain": signer.trust_domain,
                "anchor_id": witness["anchor_id"],
                "witness": witness,
            }
        )

    quorum_groups: list[tuple[tuple[Any, ...], list[dict[str, Any]]]] = []
    for statement, members in valid_by_statement.items():
        distinct_domains = {member["trust_domain"] for member in members}
        distinct_anchors = {member["anchor_id"] for member in members}
        if len(members) >= threshold and len(distinct_domains) >= threshold and len(distinct_anchors) >= threshold:
            quorum_groups.append((statement, members))
    if not quorum_groups:
        raise TrustRegistryAnchorError(
            "anchor_quorum_not_met",
            f"threshold={threshold} valid_signers={len(seen_signers)} invalid={len(invalid_rows)}",
        )
    if len(quorum_groups) > 1:
        raise TrustRegistryAnchorError("multiple_anchor_quorums", str(len(quorum_groups)))

    statement, _members = quorum_groups[0]
    sequence = int(statement[2])
    snapshot_sha256 = str(statement[3])
    head = store.head()
    if head is None:
        raise TrustRegistryAnchorError("local_registry_missing", store.registry_id)
    if head["sequence"] < sequence:
        raise TrustRegistryAnchorError("local_registry_rollback", f"local={head['sequence']} quorum={sequence}")
    if head["sequence"] > sequence:
        raise TrustRegistryAnchorError("stale_anchor_quorum", f"local={head['sequence']} quorum={sequence}")
    if head["snapshot_sha256"] != snapshot_sha256:
        raise TrustRegistryAnchorError("local_registry_fork", "quorum sequence matches but digest differs")

    registry = store.load_registry(evaluation_tick)
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return registry


__all__ = [
    "SQLiteEpochChallengeLedger",
    "TRUST_REGISTRY_QUORUM_MEMBER_WITNESS_CONTRACT_ID",
    "VerifierFreshnessSession",
    "load_registry_with_quorum_anchors",
    "make_quorum_member_witness",
    "validate_quorum_member_witness",
]
