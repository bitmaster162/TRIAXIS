"""TRIAXIS v3.28 external monotonic execution-ledger head authority.

v3.27 keeps mutating-effect state in a ledger outside the local queue rollback
boundary, but the ledger cannot prove freshness after rollback of its own SQLite
file.  This module anchors the exact signed ledger head in another monotonic
state domain and requires a fresh challenge-bound authority response before a
mutating effect can proceed.

The authority accepts only a contiguous signed event advance from its currently
stored head.  A rolled-back ledger may still possess its signing key, but it
cannot build a different event chain whose first event references the authority's
remembered head.  The reference is executable, not production-qualified, and
claims neither physical nor administrative independence.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_RECEIPT,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .external_execution_ledger import (
    EXECUTION_LEDGER_EVENT_CONTRACT_ID,
    EXECUTION_LEDGER_HEAD_CONTRACT_ID,
    SQLiteExternalExecutionLedger,
    verify_external_effect_guard,
)
from .integrity import materialize_json, seal_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID = "TRIAXIS_EXECUTION_LEDGER_HEAD_RESPONSE_v1"
ZERO_SHA256 = "0" * 64


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise ExecutionLedgerHeadError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


class ExecutionLedgerHeadError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _verify_signed_ledger_head(
    signed_head: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_signer_id: str,
    expected_trust_domain: str,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_head,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_RECEIPT,
        expected_digest_field="head_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_HEAD_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise ExecutionLedgerHeadError("invalid_ledger_head_signature", str(verified["errors"]))
    head = verified["inner_contract"]
    if not isinstance(head, dict):
        raise ExecutionLedgerHeadError("invalid_ledger_head", "object required")
    for field in ("ledger_id", "authority_id"):
        if not isinstance(head.get(field), str) or not head[field]:
            raise ExecutionLedgerHeadError("invalid_ledger_head", field)
    if type(head.get("sequence")) is not int or head["sequence"] < 0:
        raise ExecutionLedgerHeadError("invalid_ledger_head_sequence", str(head.get("sequence")))
    for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
        if not _is_sha256(head.get(field)):
            raise ExecutionLedgerHeadError("invalid_ledger_head_digest", field)
    if head["sequence"] == 0 and head["head_event_sha256"] != ZERO_SHA256:
        raise ExecutionLedgerHeadError("invalid_genesis_head", head["head_event_sha256"])
    if head["sequence"] > 0 and head["head_event_sha256"] == ZERO_SHA256:
        raise ExecutionLedgerHeadError("invalid_non_genesis_head", ZERO_SHA256)
    return head


def _verify_signed_event(
    signed_event: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_signer_id: str,
    expected_trust_domain: str,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_event,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_RECEIPT,
        expected_digest_field="event_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_EVENT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise ExecutionLedgerHeadError("invalid_ledger_event_signature", str(verified["errors"]))
    event = verified["inner_contract"]
    if not isinstance(event, dict):
        raise ExecutionLedgerHeadError("invalid_ledger_event", "object required")
    if type(event.get("sequence")) is not int or event["sequence"] < 1:
        raise ExecutionLedgerHeadError("invalid_ledger_event_sequence", str(event.get("sequence")))
    for field in ("previous_event_sha256", "event_sha256"):
        if not _is_sha256(event.get(field)):
            raise ExecutionLedgerHeadError("invalid_ledger_event_digest", field)
    return event


class SQLiteExecutionLedgerHeadAuthority:
    """Independent monotonic memory for one or more execution-ledger heads.

    The authority accepts a new head only with every missing signed event from
    its current sequence to the incoming sequence.  This prevents a ledger that
    was restored to an older database image from silently overtaking the stored
    head with a different fork.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        authority_id: str,
        service_id: str,
        ledger_registry: TrustKeyRegistry,
        expected_ledger_signer_id: str,
        expected_ledger_trust_domain: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        response_ttl: int = 15,
    ) -> None:
        for name, value in (
            ("authority_id", authority_id),
            ("service_id", service_id),
            ("expected_ledger_signer_id", expected_ledger_signer_id),
            ("expected_ledger_trust_domain", expected_ledger_trust_domain),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise ExecutionLedgerHeadError("invalid_configuration", name)
        if type(response_ttl) is not int or response_ttl < 1:
            raise ExecutionLedgerHeadError("invalid_configuration", "response_ttl")
        self.path = str(path)
        self.authority_id = authority_id
        self.service_id = service_id
        self.ledger_registry = ledger_registry
        self.expected_ledger_signer_id = expected_ledger_signer_id
        self.expected_ledger_trust_domain = expected_ledger_trust_domain
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self.response_ttl = response_ttl
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS accepted_execution_ledger_heads (
              ledger_id TEXT PRIMARY KEY,
              ledger_authority_id TEXT NOT NULL,
              ledger_sequence INTEGER NOT NULL,
              ledger_head_event_sha256 TEXT NOT NULL,
              ledger_state_root_sha256 TEXT NOT NULL,
              ledger_head_sha256 TEXT UNIQUE NOT NULL,
              signed_head_json TEXT NOT NULL,
              accepted_at_tick INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accepted_execution_ledger_events (
              ledger_id TEXT NOT NULL,
              sequence INTEGER NOT NULL,
              event_sha256 TEXT UNIQUE NOT NULL,
              previous_event_sha256 TEXT NOT NULL,
              signed_event_json TEXT NOT NULL,
              accepted_at_tick INTEGER NOT NULL,
              PRIMARY KEY (ledger_id, sequence)
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteExecutionLedgerHeadAuthority":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def current(self, ledger_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT signed_head_json FROM accepted_execution_ledger_heads WHERE ledger_id=?",
            (ledger_id,),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def health_snapshot(self) -> list[dict[str, Any]]:
        """Return public operational metadata without exposing keys or tokens."""
        rows = self._conn.execute(
            "SELECT ledger_id,ledger_sequence,ledger_head_event_sha256,accepted_at_tick "
            "FROM accepted_execution_ledger_heads ORDER BY ledger_id"
        ).fetchall()
        return [
            {
                "ledger_id": row[0],
                "ledger_sequence": row[1],
                "ledger_head_event_sha256": row[2],
                "accepted_at_tick": row[3],
            }
            for row in rows
        ]

    def install_advance(
        self,
        signed_head: Mapping[str, Any],
        signed_events: Sequence[Mapping[str, Any]],
        *,
        evaluation_tick: int,
    ) -> dict[str, Any]:
        if type(evaluation_tick) is not int or evaluation_tick < 0:
            raise ExecutionLedgerHeadError("invalid_evaluation_tick", str(evaluation_tick))
        if not isinstance(signed_events, Sequence) or isinstance(signed_events, (str, bytes, bytearray)):
            raise ExecutionLedgerHeadError("invalid_event_sequence", "array required")
        head = _verify_signed_ledger_head(
            signed_head,
            registry=self.ledger_registry,
            evaluation_tick=evaluation_tick,
            expected_signer_id=self.expected_ledger_signer_id,
            expected_trust_domain=self.expected_ledger_trust_domain,
        )
        events = [
            _verify_signed_event(
                item,
                registry=self.ledger_registry,
                evaluation_tick=evaluation_tick,
                expected_signer_id=self.expected_ledger_signer_id,
                expected_trust_domain=self.expected_ledger_trust_domain,
            )
            for item in signed_events
        ]
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT ledger_authority_id,ledger_sequence,ledger_head_event_sha256,"
                "ledger_state_root_sha256,ledger_head_sha256,signed_head_json "
                "FROM accepted_execution_ledger_heads WHERE ledger_id=?",
                (head["ledger_id"],),
            ).fetchone()
            if row is None:
                base_sequence = 0
                base_event = ZERO_SHA256
            else:
                if row[0] != head["authority_id"]:
                    raise ExecutionLedgerHeadError("ledger_authority_rebinding", head["authority_id"])
                current_sequence = int(row[1])
                current_event = str(row[2])
                current_state_root = str(row[3])
                current_head_sha = str(row[4])
                if head["sequence"] == current_sequence:
                    if (
                        head["head_event_sha256"] == current_event
                        and head["state_root_sha256"] == current_state_root
                    ):
                        if events:
                            raise ExecutionLedgerHeadError("idempotent_head_with_events", str(len(events)))
                        self._conn.commit()
                        return {
                            "status": "PASS",
                            "idempotent_replay": True,
                            "signed_head": json.loads(row[5]),
                        }
                    raise ExecutionLedgerHeadError(
                        "execution_ledger_same_sequence_fork",
                        f"sequence={current_sequence}",
                    )
                if head["sequence"] < current_sequence:
                    raise ExecutionLedgerHeadError(
                        "execution_ledger_head_rollback",
                        f"current={current_sequence} incoming={head['sequence']}",
                    )
                base_sequence = current_sequence
                base_event = current_event

            expected_count = head["sequence"] - base_sequence
            if len(events) != expected_count:
                raise ExecutionLedgerHeadError(
                    "execution_ledger_advance_length_mismatch",
                    f"expected={expected_count} observed={len(events)}",
                )
            previous = base_event
            expected_sequence = base_sequence + 1
            serialized_events: list[tuple[Any, ...]] = []
            for signed_raw, event in zip(signed_events, events):
                if event.get("ledger_id") != head["ledger_id"]:
                    raise ExecutionLedgerHeadError("ledger_event_ledger_mismatch", str(event.get("ledger_id")))
                if event.get("authority_id") != head["authority_id"]:
                    raise ExecutionLedgerHeadError("ledger_event_authority_mismatch", str(event.get("authority_id")))
                if event["sequence"] != expected_sequence:
                    raise ExecutionLedgerHeadError(
                        "execution_ledger_event_sequence_gap",
                        f"expected={expected_sequence} observed={event['sequence']}",
                    )
                if event["previous_event_sha256"] != previous:
                    raise ExecutionLedgerHeadError(
                        "execution_ledger_event_parent_mismatch",
                        f"sequence={event['sequence']}",
                    )
                serialized_events.append(
                    (
                        head["ledger_id"],
                        event["sequence"],
                        event["event_sha256"],
                        event["previous_event_sha256"],
                        json.dumps(materialize_json(signed_raw), sort_keys=True, separators=(",", ":")),
                        evaluation_tick,
                    )
                )
                previous = event["event_sha256"]
                expected_sequence += 1
            if previous != head["head_event_sha256"]:
                raise ExecutionLedgerHeadError(
                    "execution_ledger_head_event_mismatch",
                    f"expected={previous} observed={head['head_event_sha256']}",
                )
            if head["sequence"] == 0 and events:
                raise ExecutionLedgerHeadError("invalid_genesis_advance", str(len(events)))

            for payload in serialized_events:
                self._conn.execute(
                    "INSERT INTO accepted_execution_ledger_events(ledger_id,sequence,event_sha256,"
                    "previous_event_sha256,signed_event_json,accepted_at_tick) VALUES(?,?,?,?,?,?)",
                    payload,
                )
            signed_head_json = json.dumps(
                materialize_json(signed_head), sort_keys=True, separators=(",", ":")
            )
            self._conn.execute(
                "INSERT INTO accepted_execution_ledger_heads(ledger_id,ledger_authority_id,ledger_sequence,"
                "ledger_head_event_sha256,ledger_state_root_sha256,ledger_head_sha256,signed_head_json,accepted_at_tick) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(ledger_id) DO UPDATE SET "
                "ledger_authority_id=excluded.ledger_authority_id,ledger_sequence=excluded.ledger_sequence,"
                "ledger_head_event_sha256=excluded.ledger_head_event_sha256,"
                "ledger_state_root_sha256=excluded.ledger_state_root_sha256,"
                "ledger_head_sha256=excluded.ledger_head_sha256,signed_head_json=excluded.signed_head_json,"
                "accepted_at_tick=excluded.accepted_at_tick",
                (
                    head["ledger_id"],
                    head["authority_id"],
                    head["sequence"],
                    head["head_event_sha256"],
                    head["state_root_sha256"],
                    head["head_sha256"],
                    signed_head_json,
                    evaluation_tick,
                ),
            )
            self._conn.commit()
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "signed_head": materialize_json(signed_head),
                "accepted_event_count": len(events),
            }
        except sqlite3.IntegrityError as exc:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise ExecutionLedgerHeadError("head_authority_uniqueness_conflict", str(exc)) from exc
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def issue_head(
        self,
        *,
        ledger_id: str,
        challenge: str,
        verifier_id: str,
        verifier_epoch_sha256: str,
        requested_at: int,
        issued_at: int,
        valid_until: int | None = None,
    ) -> dict[str, Any]:
        if not isinstance(ledger_id, str) or not ledger_id:
            raise ExecutionLedgerHeadError("invalid_ledger_id", str(ledger_id))
        if not isinstance(verifier_id, str) or not verifier_id:
            raise ExecutionLedgerHeadError("invalid_verifier_id", str(verifier_id))
        if not _is_sha256(verifier_epoch_sha256):
            raise ExecutionLedgerHeadError("invalid_verifier_epoch", str(verifier_epoch_sha256))
        if type(requested_at) is not int or type(issued_at) is not int or requested_at < 0 or issued_at < requested_at:
            raise ExecutionLedgerHeadError("invalid_response_time", f"{requested_at}:{issued_at}")
        if valid_until is None:
            valid_until = issued_at + self.response_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise ExecutionLedgerHeadError("invalid_response_window", str(valid_until))
        row = self._conn.execute(
            "SELECT ledger_authority_id,ledger_sequence,ledger_head_event_sha256,ledger_state_root_sha256,"
            "ledger_head_sha256,accepted_at_tick FROM accepted_execution_ledger_heads WHERE ledger_id=?",
            (ledger_id,),
        ).fetchone()
        if row is None:
            raise ExecutionLedgerHeadError("unknown_execution_ledger", ledger_id)
        response = seal_mapping(
            {
                "contract_id": EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "ledger_id": ledger_id,
                "ledger_authority_id": row[0],
                "verifier_id": verifier_id,
                "verifier_epoch_sha256": verifier_epoch_sha256,
                "challenge_sha256": _challenge_sha256(challenge),
                "requested_at": requested_at,
                "ledger_sequence": row[1],
                "ledger_head_event_sha256": row[2],
                "ledger_state_root_sha256": row[3],
                "ledger_head_sha256": row[4],
                "accepted_at_tick": row[5],
                "issued_at": issued_at,
                "valid_until": valid_until,
                "response_sha256": "",
            },
            "response_sha256",
        )
        return sign_contract_envelope(
            response,
            digest_field="response_sha256",
            purpose=PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


def verify_external_execution_ledger_head(
    signed_local_head: Mapping[str, Any],
    signed_head_response: Mapping[str, Any],
    *,
    ledger_registry: TrustKeyRegistry,
    authority_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    expected_head_authority_id: str,
    expected_head_authority_signer_id: str,
    expected_head_authority_trust_domain: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    max_response_age: int = 5,
) -> dict[str, Any]:
    if type(evaluation_tick) is not int or evaluation_tick < 0:
        raise ExecutionLedgerHeadError("invalid_evaluation_tick", str(evaluation_tick))
    if type(max_response_age) is not int or max_response_age < 0:
        raise ExecutionLedgerHeadError("invalid_max_response_age", str(max_response_age))
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    head = _verify_signed_ledger_head(
        signed_local_head,
        registry=ledger_registry,
        evaluation_tick=evaluation_tick,
        expected_signer_id=expected_ledger_signer_id,
        expected_trust_domain=expected_ledger_trust_domain,
    )
    verified_response = verify_contract_envelope(
        signed_head_response,
        registry=authority_registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
        expected_digest_field="response_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID,
        expected_signer_id=expected_head_authority_signer_id,
        expected_trust_domain=expected_head_authority_trust_domain,
    )
    if verified_response["status"] != "PASS":
        raise ExecutionLedgerHeadError("invalid_head_authority_signature", str(verified_response["errors"]))
    response = verified_response["inner_contract"]
    if not isinstance(response, dict):
        raise ExecutionLedgerHeadError("invalid_head_authority_response", "object required")
    if response.get("authority_id") != expected_head_authority_id:
        raise ExecutionLedgerHeadError("head_authority_id_mismatch", str(response.get("authority_id")))
    if head.get("ledger_id") != expected_ledger_id or response.get("ledger_id") != expected_ledger_id:
        raise ExecutionLedgerHeadError("execution_ledger_id_mismatch", expected_ledger_id)
    if (
        head.get("authority_id") != expected_ledger_authority_id
        or response.get("ledger_authority_id") != expected_ledger_authority_id
    ):
        raise ExecutionLedgerHeadError("execution_ledger_authority_mismatch", expected_ledger_authority_id)
    if (
        response.get("verifier_id") != challenge_ledger.session.verifier_id
        or response.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
    ):
        raise ExecutionLedgerHeadError("head_verifier_binding_mismatch", str(response.get("verifier_id")))
    if (
        response.get("challenge_sha256") != challenge["challenge_sha256"]
        or response.get("requested_at") != challenge["issued_at"]
    ):
        raise ExecutionLedgerHeadError("head_challenge_binding_mismatch", str(response.get("challenge_sha256")))
    issued_at = response.get("issued_at")
    if type(issued_at) is not int or issued_at > evaluation_tick or evaluation_tick - issued_at > max_response_age:
        raise ExecutionLedgerHeadError("head_response_not_fresh", str(issued_at))
    bindings = (
        ("ledger_sequence", "sequence"),
        ("ledger_head_event_sha256", "head_event_sha256"),
        ("ledger_state_root_sha256", "state_root_sha256"),
    )
    mismatches: list[str] = []
    for response_field, head_field in bindings:
        if response.get(response_field) != head.get(head_field):
            mismatches.append(response_field)
    if mismatches:
        raise ExecutionLedgerHeadError(
            "execution_ledger_rollback_or_fork_detected",
            ",".join(mismatches),
        )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "local_head": head,
        "external_head": response,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def reserve_with_external_head_guard(
    ledger: SQLiteExternalExecutionLedger,
    intent: Mapping[str, Any],
    *,
    attempt_id: str,
    dispatch_id: str,
    now_tick: int,
    signed_local_head: Mapping[str, Any],
    signed_head_response: Mapping[str, Any],
    ledger_registry: TrustKeyRegistry,
    authority_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    expected_head_authority_id: str,
    expected_head_authority_signer_id: str,
    expected_head_authority_trust_domain: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
) -> dict[str, Any]:
    freshness = verify_external_execution_ledger_head(
        signed_local_head,
        signed_head_response,
        ledger_registry=ledger_registry,
        authority_registry=authority_registry,
        expected_ledger_id=expected_ledger_id,
        expected_ledger_authority_id=expected_ledger_authority_id,
        expected_ledger_signer_id=expected_ledger_signer_id,
        expected_ledger_trust_domain=expected_ledger_trust_domain,
        expected_head_authority_id=expected_head_authority_id,
        expected_head_authority_signer_id=expected_head_authority_signer_id,
        expected_head_authority_trust_domain=expected_head_authority_trust_domain,
        challenge_ledger=challenge_ledger,
        expected_challenge=expected_challenge,
        evaluation_tick=now_tick,
    )
    reserved = ledger.reserve(intent, attempt_id=attempt_id, dispatch_id=dispatch_id, now_tick=now_tick)
    return {"status": reserved["status"], "freshness": freshness, "reservation": reserved}


def verify_external_effect_guard_with_monotonic_head(
    intent: Mapping[str, Any],
    signed_in_flight_receipt: Mapping[str, Any],
    signed_local_head: Mapping[str, Any],
    signed_head_response: Mapping[str, Any],
    *,
    ledger_registry: TrustKeyRegistry,
    head_authority_registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    expected_head_authority_id: str,
    expected_head_authority_signer_id: str,
    expected_head_authority_trust_domain: str,
    expected_attempt_id: str,
    expected_dispatch_id: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
) -> dict[str, Any]:
    receipt_guard = verify_external_effect_guard(
        intent,
        signed_in_flight_receipt,
        registry=ledger_registry,
        evaluation_tick=evaluation_tick,
        expected_ledger_id=expected_ledger_id,
        expected_authority_id=expected_ledger_authority_id,
        expected_signer_id=expected_ledger_signer_id,
        expected_trust_domain=expected_ledger_trust_domain,
        expected_attempt_id=expected_attempt_id,
        expected_dispatch_id=expected_dispatch_id,
    )
    if receipt_guard["status"] != "PASS":
        return {
            "status": "BLOCK",
            "errors": receipt_guard["errors"],
            "authority_granted": False,
            "required_separate_authorization": True,
        }
    try:
        head_guard = verify_external_execution_ledger_head(
            signed_local_head,
            signed_head_response,
            ledger_registry=ledger_registry,
            authority_registry=head_authority_registry,
            expected_ledger_id=expected_ledger_id,
            expected_ledger_authority_id=expected_ledger_authority_id,
            expected_ledger_signer_id=expected_ledger_signer_id,
            expected_ledger_trust_domain=expected_ledger_trust_domain,
            expected_head_authority_id=expected_head_authority_id,
            expected_head_authority_signer_id=expected_head_authority_signer_id,
            expected_head_authority_trust_domain=expected_head_authority_trust_domain,
            challenge_ledger=challenge_ledger,
            expected_challenge=expected_challenge,
            evaluation_tick=evaluation_tick,
        )
    except ExecutionLedgerHeadError as exc:
        return {
            "status": "BLOCK",
            "errors": [{"code": exc.code, "path": "execution_ledger_head", "message": exc.detail}],
            "authority_granted": False,
            "required_separate_authorization": True,
        }
    return {
        "status": "PASS",
        "errors": [],
        "receipt_guard": receipt_guard,
        "head_guard": head_guard,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID",
    "ExecutionLedgerHeadError",
    "SQLiteExecutionLedgerHeadAuthority",
    "reserve_with_external_head_guard",
    "verify_external_execution_ledger_head",
    "verify_external_effect_guard_with_monotonic_head",
]
