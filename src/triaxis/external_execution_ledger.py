"""TRIAXIS v3.27 external execution-ledger contracts.

The v3.26 local dispatch queue cannot prove freshness after whole-file rollback.
This module introduces a separately persisted execution ledger whose stable
``effect_id`` is independent of volatile queue claim/dispatch identities.

A signed ledger receipt is a necessary anti-replay condition.  It is not action
authority and never replaces the separately verified TRIAXIS authorization,
policy, state, target, or payload bindings.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_EXECUTION_RECEIPT,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

EXECUTION_INTENT_CONTRACT_ID = "TRIAXIS_EXECUTION_INTENT_v1"
EXECUTION_LEDGER_EVENT_CONTRACT_ID = "TRIAXIS_EXECUTION_LEDGER_EVENT_v1"
EXECUTION_LEDGER_HEAD_CONTRACT_ID = "TRIAXIS_EXECUTION_LEDGER_HEAD_v1"
EFFECT_ID_DOMAIN = "TRIAXIS_EFFECT_ID_v1"
ZERO_SHA256 = "0" * 64

LEDGER_STATES = frozenset({"RESERVED", "IN_FLIGHT", "UNKNOWN", "COMPLETED", "NO_EFFECT"})
TERMINAL_BLOCKING_STATES = frozenset({"COMPLETED", "UNKNOWN", "IN_FLIGHT", "RESERVED"})


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def compute_effect_id(
    *,
    queue_id: str,
    queued_input_sha256: str,
    action_envelope_sha256: str,
    canonical_target_sha256: str,
) -> str:
    """Return the stable idempotency identity for one externally visible effect.

    Deliberately excluded: claim_id, dispatch_id, attempt_id, lease, process,
    provider request id, and local database version.
    """
    for name, value in (
        ("queue_id", queue_id),
        ("queued_input_sha256", queued_input_sha256),
        ("action_envelope_sha256", action_envelope_sha256),
        ("canonical_target_sha256", canonical_target_sha256),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{name} required")
    for name, value in (
        ("queued_input_sha256", queued_input_sha256),
        ("action_envelope_sha256", action_envelope_sha256),
        ("canonical_target_sha256", canonical_target_sha256),
    ):
        if not _is_sha256(value):
            raise ValueError(f"{name} must be lowercase SHA-256")
    return canonical_sha256(
        {
            "domain": EFFECT_ID_DOMAIN,
            "queue_id": queue_id,
            "queued_input_sha256": queued_input_sha256,
            "action_envelope_sha256": action_envelope_sha256,
            "canonical_target_sha256": canonical_target_sha256,
        }
    )


def seal_execution_intent(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("execution intent must be object")
    for field in ("queue_id", "queued_input_sha256", "action_envelope_sha256", "authorization_token_sha256", "canonical_target_sha256"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    for field in ("queued_input_sha256", "action_envelope_sha256", "authorization_token_sha256", "canonical_target_sha256"):
        if not _is_sha256(body[field]):
            raise ValueError(f"{field} invalid")
    if body.get("risk_class") != "MUTATING":
        raise ValueError("execution ledger is required for MUTATING effects")
    created = body.get("created_at_tick")
    if type(created) is not int or created < 0:
        raise ValueError("created_at_tick integer >= 0 required")
    expected_effect_id = compute_effect_id(
        queue_id=body["queue_id"],
        queued_input_sha256=body["queued_input_sha256"],
        action_envelope_sha256=body["action_envelope_sha256"],
        canonical_target_sha256=body["canonical_target_sha256"],
    )
    observed = body.get("effect_id")
    if observed not in (None, "", expected_effect_id):
        raise ValueError("effect_id does not match stable effect binding")
    body["effect_id"] = expected_effect_id
    metadata = body.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be object")
    body["metadata"] = metadata
    body.setdefault("contract_id", EXECUTION_INTENT_CONTRACT_ID)
    if body["contract_id"] != EXECUTION_INTENT_CONTRACT_ID:
        raise ValueError("unexpected intent contract_id")
    body.setdefault("intent_sha256", "")
    return seal_mapping(body, "intent_sha256")


def validate_execution_intent(value: Any) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "intent", "mapping required")]}
    try:
        intent = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "intent", type(exc).__name__)]}
    if not isinstance(intent, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "intent", "object required")]}
    if intent.get("contract_id") != EXECUTION_INTENT_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "intent.contract_id", EXECUTION_INTENT_CONTRACT_ID))
    if not verify_sealed_mapping(intent, "intent_sha256"):
        errors.append(_error("digest_mismatch", "intent.intent_sha256", "canonical digest mismatch"))
    try:
        expected = compute_effect_id(
            queue_id=intent.get("queue_id"),
            queued_input_sha256=intent.get("queued_input_sha256"),
            action_envelope_sha256=intent.get("action_envelope_sha256"),
            canonical_target_sha256=intent.get("canonical_target_sha256"),
        )
        if intent.get("effect_id") != expected:
            errors.append(_error("effect_id_mismatch", "intent.effect_id", "stable effect binding mismatch"))
    except (TypeError, ValueError) as exc:
        errors.append(_error("invalid_effect_binding", "intent", str(exc)))
    if intent.get("risk_class") != "MUTATING":
        errors.append(_error("invalid_risk_class", "intent.risk_class", "MUTATING required"))
    if type(intent.get("created_at_tick")) is not int or intent["created_at_tick"] < 0:
        errors.append(_error("invalid_created_at", "intent.created_at_tick", "integer >= 0 required"))
    if not isinstance(intent.get("metadata"), dict):
        errors.append(_error("invalid_metadata", "intent.metadata", "object required"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "intent": intent}


class ExecutionLedgerError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class SQLiteExternalExecutionLedger:
    """Separately persisted, signed idempotency ledger for mutating effects.

    The SQLite file must be outside the local queue's rollback domain.  This
    reference keeps the signing key in process memory and does not claim KMS/HSM
    custody, physical independence, or administrative independence.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        ledger_id: str,
        authority_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        receipt_ttl: int = 30,
    ) -> None:
        for name, value in (
            ("ledger_id", ledger_id),
            ("authority_id", authority_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise ExecutionLedgerError("invalid_configuration", name)
        if type(receipt_ttl) is not int or receipt_ttl < 1:
            raise ExecutionLedgerError("invalid_configuration", "receipt_ttl")
        self.path = str(path)
        self.ledger_id = ledger_id
        self.authority_id = authority_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self.receipt_ttl = receipt_ttl
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA foreign_keys=ON")
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_meta (
              ledger_id TEXT PRIMARY KEY,
              sequence INTEGER NOT NULL,
              head_event_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_effects (
              effect_id TEXT PRIMARY KEY,
              intent_sha256 TEXT NOT NULL,
              intent_json TEXT NOT NULL,
              state TEXT NOT NULL,
              generation INTEGER NOT NULL,
              current_attempt_id TEXT NOT NULL,
              current_dispatch_id TEXT NOT NULL,
              last_event_sha256 TEXT NOT NULL,
              created_at_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_attempts (
              attempt_id TEXT PRIMARY KEY,
              effect_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              dispatch_id TEXT UNIQUE NOT NULL,
              state TEXT NOT NULL,
              reservation_event_sha256 TEXT NOT NULL,
              start_event_sha256 TEXT,
              outcome_event_sha256 TEXT,
              evidence_sha256 TEXT,
              created_at_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL,
              FOREIGN KEY(effect_id) REFERENCES execution_effects(effect_id)
            );
            CREATE TABLE IF NOT EXISTS execution_events (
              sequence INTEGER PRIMARY KEY,
              event_sha256 TEXT UNIQUE NOT NULL,
              effect_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              attempt_id TEXT NOT NULL,
              dispatch_id TEXT NOT NULL,
              from_state TEXT,
              to_state TEXT NOT NULL,
              event_json TEXT NOT NULL,
              signed_event_json TEXT NOT NULL,
              created_at_tick INTEGER NOT NULL,
              FOREIGN KEY(effect_id) REFERENCES execution_effects(effect_id)
            );
            CREATE INDEX IF NOT EXISTS idx_execution_events_effect ON execution_events(effect_id, sequence);
            """
        )
        any_meta = self._conn.execute("SELECT ledger_id,sequence,head_event_sha256 FROM ledger_meta ORDER BY ledger_id LIMIT 1").fetchone()
        if any_meta is None:
            self._conn.execute("INSERT INTO ledger_meta(ledger_id,sequence,head_event_sha256) VALUES(?,?,?)", (ledger_id, 0, ZERO_SHA256))
        elif any_meta[0] != ledger_id:
            raise ExecutionLedgerError("ledger_id_conflict", str(any_meta[0]))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteExternalExecutionLedger":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _meta(self) -> tuple[int, str]:
        row = self._conn.execute("SELECT sequence,head_event_sha256 FROM ledger_meta WHERE ledger_id=?", (self.ledger_id,)).fetchone()
        if row is None:
            raise ExecutionLedgerError("ledger_meta_missing", self.ledger_id)
        return int(row[0]), str(row[1])

    def _signed_event(
        self,
        *,
        sequence: int,
        previous_event_sha256: str,
        effect_id: str,
        intent_sha256: str,
        generation: int,
        attempt_id: str,
        dispatch_id: str,
        from_state: str | None,
        to_state: str,
        evidence_sha256: str | None,
        issued_at_tick: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        event = seal_mapping(
            {
                "contract_id": EXECUTION_LEDGER_EVENT_CONTRACT_ID,
                "ledger_id": self.ledger_id,
                "authority_id": self.authority_id,
                "sequence": sequence,
                "previous_event_sha256": previous_event_sha256,
                "effect_id": effect_id,
                "intent_sha256": intent_sha256,
                "generation": generation,
                "attempt_id": attempt_id,
                "dispatch_id": dispatch_id,
                "from_state": from_state,
                "to_state": to_state,
                "evidence_sha256": evidence_sha256,
                "issued_at_tick": issued_at_tick,
                "event_sha256": "",
            },
            "event_sha256",
        )
        signed = sign_contract_envelope(
            event,
            digest_field="event_sha256",
            purpose=PURPOSE_EXECUTION_RECEIPT,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at_tick,
            valid_until=issued_at_tick + self.receipt_ttl,
        )
        return event, signed

    def _insert_event(self, event: Mapping[str, Any], signed: Mapping[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO execution_events(sequence,event_sha256,effect_id,generation,attempt_id,dispatch_id,from_state,to_state,event_json,signed_event_json,created_at_tick) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["sequence"],
                event["event_sha256"],
                event["effect_id"],
                event["generation"],
                event["attempt_id"],
                event["dispatch_id"],
                event["from_state"],
                event["to_state"],
                json.dumps(event, sort_keys=True, separators=(",", ":")),
                json.dumps(signed, sort_keys=True, separators=(",", ":")),
                event["issued_at_tick"],
            ),
        )
        self._conn.execute(
            "UPDATE ledger_meta SET sequence=?,head_event_sha256=? WHERE ledger_id=?",
            (event["sequence"], event["event_sha256"], self.ledger_id),
        )

    def _event_by_digest(self, event_sha256: str | None) -> dict[str, Any] | None:
        if not event_sha256:
            return None
        row = self._conn.execute("SELECT signed_event_json FROM execution_events WHERE event_sha256=?", (event_sha256,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def get_effect(self, effect_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT intent_json,state,generation,current_attempt_id,current_dispatch_id,last_event_sha256,created_at_tick,updated_at_tick FROM execution_effects WHERE effect_id=?",
            (effect_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "intent": json.loads(row[0]),
            "effect_id": effect_id,
            "state": row[1],
            "generation": row[2],
            "current_attempt_id": row[3],
            "current_dispatch_id": row[4],
            "last_event_sha256": row[5],
            "created_at_tick": row[6],
            "updated_at_tick": row[7],
            "signed_receipt": self._event_by_digest(row[5]),
        }

    def reserve(
        self,
        intent: Mapping[str, Any],
        *,
        attempt_id: str,
        dispatch_id: str,
        now_tick: int,
    ) -> dict[str, Any]:
        validated = validate_execution_intent(intent)
        if validated["status"] != "PASS":
            raise ExecutionLedgerError("invalid_execution_intent", str(validated["errors"]))
        obj = validated["intent"]
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ExecutionLedgerError("invalid_attempt_id", str(attempt_id))
        if not _is_sha256(dispatch_id):
            raise ExecutionLedgerError("invalid_dispatch_id", str(dispatch_id))
        if type(now_tick) is not int or now_tick < 0:
            raise ExecutionLedgerError("invalid_now_tick", str(now_tick))
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            replay = self._conn.execute(
                "SELECT effect_id,dispatch_id,reservation_event_sha256 FROM execution_attempts WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
            if replay is not None:
                if replay[0] != obj["effect_id"] or replay[1] != dispatch_id:
                    raise ExecutionLedgerError("attempt_id_replay_conflict", attempt_id)
                signed = self._event_by_digest(replay[2])
                self._conn.commit()
                return {"status": "PASS", "idempotent_replay": True, "signed_receipt": signed, "effect": self.get_effect(obj["effect_id"])}

            existing = self._conn.execute(
                "SELECT intent_sha256,state,generation,last_event_sha256 FROM execution_effects WHERE effect_id=?",
                (obj["effect_id"],),
            ).fetchone()
            if existing is None:
                generation = 1
                from_state = None
            else:
                if existing[1] in TERMINAL_BLOCKING_STATES:
                    receipt = self._event_by_digest(existing[3])
                    self._conn.rollback()
                    return {
                        "status": "BLOCK",
                        "reason": f"effect_{str(existing[1]).lower()}",
                        "effect_id": obj["effect_id"],
                        "current_state": existing[1],
                        "binding_match": existing[0] == obj["intent_sha256"],
                        "signed_receipt": receipt,
                    }
                if existing[0] != obj["intent_sha256"]:
                    raise ExecutionLedgerError("effect_binding_conflict", obj["effect_id"])
                if existing[1] != "NO_EFFECT":
                    raise ExecutionLedgerError("invalid_effect_state", str(existing[1]))
                generation = int(existing[2]) + 1
                from_state = "NO_EFFECT"

            sequence, previous = self._meta()
            sequence += 1
            event, signed = self._signed_event(
                sequence=sequence,
                previous_event_sha256=previous,
                effect_id=obj["effect_id"],
                intent_sha256=obj["intent_sha256"],
                generation=generation,
                attempt_id=attempt_id,
                dispatch_id=dispatch_id,
                from_state=from_state,
                to_state="RESERVED",
                evidence_sha256=None,
                issued_at_tick=now_tick,
            )
            intent_json = json.dumps(obj, sort_keys=True, separators=(",", ":"))
            if existing is None:
                self._conn.execute(
                    "INSERT INTO execution_effects(effect_id,intent_sha256,intent_json,state,generation,current_attempt_id,current_dispatch_id,last_event_sha256,created_at_tick,updated_at_tick) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (obj["effect_id"], obj["intent_sha256"], intent_json, "RESERVED", generation, attempt_id, dispatch_id, event["event_sha256"], now_tick, now_tick),
                )
            else:
                self._conn.execute(
                    "UPDATE execution_effects SET state='RESERVED',generation=?,current_attempt_id=?,current_dispatch_id=?,last_event_sha256=?,updated_at_tick=? WHERE effect_id=? AND state='NO_EFFECT'",
                    (generation, attempt_id, dispatch_id, event["event_sha256"], now_tick, obj["effect_id"]),
                )
            self._conn.execute(
                "INSERT INTO execution_attempts(attempt_id,effect_id,generation,dispatch_id,state,reservation_event_sha256,created_at_tick,updated_at_tick) VALUES(?,?,?,?,?,?,?,?)",
                (attempt_id, obj["effect_id"], generation, dispatch_id, "RESERVED", event["event_sha256"], now_tick, now_tick),
            )
            self._insert_event(event, signed)
            self._conn.commit()
            return {"status": "PASS", "idempotent_replay": False, "signed_receipt": signed, "effect": self.get_effect(obj["effect_id"])}
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise ExecutionLedgerError("ledger_uniqueness_conflict", str(exc)) from exc
        except Exception:
            self._conn.rollback()
            raise

    def start(self, effect_id: str, *, attempt_id: str, dispatch_id: str, now_tick: int) -> dict[str, Any]:
        return self._transition(
            effect_id,
            attempt_id=attempt_id,
            dispatch_id=dispatch_id,
            expected_states=("RESERVED",),
            target_state="IN_FLIGHT",
            evidence_sha256=None,
            now_tick=now_tick,
            idempotent_digest_column="start_event_sha256",
        )

    def release_before_effect(
        self,
        effect_id: str,
        *,
        attempt_id: str,
        dispatch_id: str,
        evidence_sha256: str,
        now_tick: int,
    ) -> dict[str, Any]:
        return self._transition(
            effect_id,
            attempt_id=attempt_id,
            dispatch_id=dispatch_id,
            expected_states=("RESERVED",),
            target_state="NO_EFFECT",
            evidence_sha256=evidence_sha256,
            now_tick=now_tick,
            idempotent_digest_column="outcome_event_sha256",
        )

    def record_outcome(
        self,
        effect_id: str,
        *,
        attempt_id: str,
        dispatch_id: str,
        outcome: str,
        evidence_sha256: str,
        now_tick: int,
    ) -> dict[str, Any]:
        if outcome not in {"COMPLETED", "UNKNOWN"}:
            raise ExecutionLedgerError("invalid_outcome", outcome)
        return self._transition(
            effect_id,
            attempt_id=attempt_id,
            dispatch_id=dispatch_id,
            expected_states=("IN_FLIGHT",),
            target_state=outcome,
            evidence_sha256=evidence_sha256,
            now_tick=now_tick,
            idempotent_digest_column="outcome_event_sha256",
        )

    def reconcile_unknown(
        self,
        effect_id: str,
        *,
        attempt_id: str,
        dispatch_id: str,
        outcome: str,
        evidence_sha256: str,
        now_tick: int,
    ) -> dict[str, Any]:
        if outcome not in {"COMPLETED", "NO_EFFECT"}:
            raise ExecutionLedgerError("invalid_reconciliation_outcome", outcome)
        return self._transition(
            effect_id,
            attempt_id=attempt_id,
            dispatch_id=dispatch_id,
            expected_states=("UNKNOWN",),
            target_state=outcome,
            evidence_sha256=evidence_sha256,
            now_tick=now_tick,
            idempotent_digest_column="outcome_event_sha256",
            allow_second_outcome=True,
        )

    def _transition(
        self,
        effect_id: str,
        *,
        attempt_id: str,
        dispatch_id: str,
        expected_states: Sequence[str],
        target_state: str,
        evidence_sha256: str | None,
        now_tick: int,
        idempotent_digest_column: str,
        allow_second_outcome: bool = False,
    ) -> dict[str, Any]:
        if target_state not in LEDGER_STATES or any(state not in LEDGER_STATES for state in expected_states):
            raise ExecutionLedgerError("invalid_transition", f"{expected_states}->{target_state}")
        if evidence_sha256 is not None and not _is_sha256(evidence_sha256):
            raise ExecutionLedgerError("invalid_evidence_sha256", str(evidence_sha256))
        if not _is_sha256(effect_id) or not isinstance(attempt_id, str) or not attempt_id or not _is_sha256(dispatch_id):
            raise ExecutionLedgerError("invalid_transition_identity", effect_id)
        if type(now_tick) is not int or now_tick < 0:
            raise ExecutionLedgerError("invalid_now_tick", str(now_tick))
        if idempotent_digest_column not in {"start_event_sha256", "outcome_event_sha256"}:
            raise ExecutionLedgerError("invalid_digest_column", idempotent_digest_column)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT e.intent_sha256,e.state,e.generation,e.current_attempt_id,e.current_dispatch_id,a.state,a.start_event_sha256,a.outcome_event_sha256,a.evidence_sha256 "
                "FROM execution_effects e JOIN execution_attempts a ON a.attempt_id=e.current_attempt_id WHERE e.effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise ExecutionLedgerError("unknown_effect_id", effect_id)
            intent_sha256, effect_state, generation, current_attempt, current_dispatch, attempt_state, start_digest, outcome_digest, stored_evidence = row
            if current_attempt != attempt_id or current_dispatch != dispatch_id:
                raise ExecutionLedgerError("current_attempt_mismatch", f"{attempt_id}:{dispatch_id}")

            existing_digest = start_digest if idempotent_digest_column == "start_event_sha256" else outcome_digest
            if effect_state == target_state and existing_digest:
                if evidence_sha256 is not None and stored_evidence not in (None, evidence_sha256):
                    raise ExecutionLedgerError("idempotent_replay_conflict", effect_id)
                signed = self._event_by_digest(existing_digest)
                self._conn.commit()
                return {"status": "PASS", "idempotent_replay": True, "signed_receipt": signed, "effect": self.get_effect(effect_id)}

            if effect_state not in set(expected_states) or attempt_state not in set(expected_states):
                # UNKNOWN reconciliation writes a second outcome event.  The first
                # UNKNOWN event remains immutable while the attempt state advances.
                if not (allow_second_outcome and effect_state == "UNKNOWN" and attempt_state == "UNKNOWN"):
                    raise ExecutionLedgerError("ledger_state_mismatch", f"expected={expected_states} observed={effect_state}/{attempt_state}")

            sequence, previous = self._meta()
            sequence += 1
            event, signed = self._signed_event(
                sequence=sequence,
                previous_event_sha256=previous,
                effect_id=effect_id,
                intent_sha256=intent_sha256,
                generation=int(generation),
                attempt_id=attempt_id,
                dispatch_id=dispatch_id,
                from_state=effect_state,
                to_state=target_state,
                evidence_sha256=evidence_sha256,
                issued_at_tick=now_tick,
            )
            self._conn.execute(
                "UPDATE execution_effects SET state=?,last_event_sha256=?,updated_at_tick=? WHERE effect_id=? AND state=?",
                (target_state, event["event_sha256"], now_tick, effect_id, effect_state),
            )
            if idempotent_digest_column == "start_event_sha256":
                self._conn.execute(
                    "UPDATE execution_attempts SET state=?,start_event_sha256=?,updated_at_tick=? WHERE attempt_id=? AND state=?",
                    (target_state, event["event_sha256"], now_tick, attempt_id, attempt_state),
                )
            else:
                self._conn.execute(
                    "UPDATE execution_attempts SET state=?,outcome_event_sha256=?,evidence_sha256=?,updated_at_tick=? WHERE attempt_id=? AND state=?",
                    (target_state, event["event_sha256"], evidence_sha256, now_tick, attempt_id, attempt_state),
                )
            self._insert_event(event, signed)
            self._conn.commit()
            return {"status": "PASS", "idempotent_replay": False, "signed_receipt": signed, "effect": self.get_effect(effect_id)}
        except Exception:
            self._conn.rollback()
            raise

    def events(self, effect_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT signed_event_json FROM execution_events WHERE effect_id=? ORDER BY sequence",
            (effect_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def events_since(self, sequence: int) -> list[dict[str, Any]]:
        """Return every globally ordered signed event after ``sequence``.

        This is the contiguous advance material consumed by the v3.28 external
        monotonic head authority.  The method is read-only and grants no action
        authority.
        """
        if type(sequence) is not int or sequence < 0:
            raise ExecutionLedgerError("invalid_event_sequence", str(sequence))
        rows = self._conn.execute(
            "SELECT signed_event_json FROM execution_events WHERE sequence>? ORDER BY sequence",
            (sequence,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def head(self, *, now_tick: int) -> dict[str, Any]:
        if type(now_tick) is not int or now_tick < 0:
            raise ExecutionLedgerError("invalid_now_tick", str(now_tick))
        sequence, head_event = self._meta()
        rows = self._conn.execute(
            "SELECT effect_id,intent_sha256,state,generation,current_attempt_id,current_dispatch_id,last_event_sha256 FROM execution_effects ORDER BY effect_id"
        ).fetchall()
        state_root = canonical_sha256(
            [
                {
                    "effect_id": row[0],
                    "intent_sha256": row[1],
                    "state": row[2],
                    "generation": row[3],
                    "current_attempt_id": row[4],
                    "current_dispatch_id": row[5],
                    "last_event_sha256": row[6],
                }
                for row in rows
            ]
        )
        head = seal_mapping(
            {
                "contract_id": EXECUTION_LEDGER_HEAD_CONTRACT_ID,
                "ledger_id": self.ledger_id,
                "authority_id": self.authority_id,
                "sequence": sequence,
                "head_event_sha256": head_event,
                "state_root_sha256": state_root,
                "issued_at_tick": now_tick,
                "head_sha256": "",
            },
            "head_sha256",
        )
        return sign_contract_envelope(
            head,
            digest_field="head_sha256",
            purpose=PURPOSE_EXECUTION_RECEIPT,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=now_tick,
            valid_until=now_tick + self.receipt_ttl,
        )


def verify_execution_ledger_receipt(
    signed_receipt: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_ledger_id: str,
    expected_authority_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_effect_id: str | None = None,
    expected_intent_sha256: str | None = None,
    expected_attempt_id: str | None = None,
    expected_dispatch_id: str | None = None,
    allowed_to_states: Sequence[str] | None = None,
    max_receipt_age: int = 10,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_receipt,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_RECEIPT,
        expected_digest_field="event_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_EVENT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    errors = list(verified.get("errors", []))
    event = verified.get("inner_contract")
    if verified.get("status") == "PASS" and isinstance(event, dict):
        if event.get("ledger_id") != expected_ledger_id:
            errors.append(_error("ledger_id_mismatch", "receipt.ledger_id", expected_ledger_id))
        if event.get("authority_id") != expected_authority_id:
            errors.append(_error("authority_id_mismatch", "receipt.authority_id", expected_authority_id))
        for field, expected in (
            ("effect_id", expected_effect_id),
            ("intent_sha256", expected_intent_sha256),
            ("attempt_id", expected_attempt_id),
            ("dispatch_id", expected_dispatch_id),
        ):
            if expected is not None and event.get(field) != expected:
                errors.append(_error(f"{field}_mismatch", f"receipt.{field}", expected))
        allowed = set(allowed_to_states or LEDGER_STATES)
        if event.get("to_state") not in allowed:
            errors.append(_error("ledger_state_not_allowed", "receipt.to_state", str(event.get("to_state"))))
        issued = event.get("issued_at_tick")
        if type(issued) is not int or issued > evaluation_tick or evaluation_tick - issued > max_receipt_age:
            errors.append(_error("receipt_not_fresh", "receipt.issued_at_tick", str(issued)))
    return {
        "status": "PASS" if verified.get("status") == "PASS" and not errors else "BLOCK",
        "errors": errors,
        "event": event,
        "verified_signer": verified.get("verified_signer"),
    }


def verify_external_effect_guard(
    intent: Mapping[str, Any],
    signed_in_flight_receipt: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_ledger_id: str,
    expected_authority_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_attempt_id: str,
    expected_dispatch_id: str,
) -> dict[str, Any]:
    """Verify the ledger precondition for an external call.

    PASS means only that a current signed IN_FLIGHT ledger record is bound to the
    exact stable intent and attempt.  It does not grant action authority.
    """
    validated = validate_execution_intent(intent)
    if validated["status"] != "PASS":
        return {"status": "BLOCK", "errors": validated["errors"], "authority_granted": False}
    obj = validated["intent"]
    receipt = verify_execution_ledger_receipt(
        signed_in_flight_receipt,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_ledger_id=expected_ledger_id,
        expected_authority_id=expected_authority_id,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
        expected_effect_id=obj["effect_id"],
        expected_intent_sha256=obj["intent_sha256"],
        expected_attempt_id=expected_attempt_id,
        expected_dispatch_id=expected_dispatch_id,
        allowed_to_states=("IN_FLIGHT",),
    )
    return {
        "status": receipt["status"],
        "errors": receipt["errors"],
        "event": receipt.get("event"),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "EFFECT_ID_DOMAIN",
    "EXECUTION_INTENT_CONTRACT_ID",
    "EXECUTION_LEDGER_EVENT_CONTRACT_ID",
    "EXECUTION_LEDGER_HEAD_CONTRACT_ID",
    "ExecutionLedgerError",
    "LEDGER_STATES",
    "SQLiteExternalExecutionLedger",
    "compute_effect_id",
    "seal_execution_intent",
    "validate_execution_intent",
    "verify_execution_ledger_receipt",
    "verify_external_effect_guard",
]
