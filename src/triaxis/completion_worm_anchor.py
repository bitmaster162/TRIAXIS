"""TRIAXIS v3.30 logical WORM completion anchor reference.

This module ingests signed provider outcome receipts into an append-only,
hash-linked, Ed25519-signed event log.  The API exposes no update or delete
operation for evidence records and can therefore model a write-once retention
contract for integration testing.

The reference storage is SQLite.  Filesystem or database rollback remains
possible and this module does **not** establish physical WORM media, independent
administration, hardware monotonicity or production exactly-once execution.
Anchor evidence never grants action authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_COMPLETION_WORM_ANCHOR,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .idempotent_effect_provider import (
    PROVIDER_OUTCOME_RECEIPT_CONTRACT_ID,
    ProviderEffectError,
    verify_provider_outcome_receipt,
)
from .integrity import canonical_sha256, materialize_json, seal_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_WORM_ANCHOR_EVENT_CONTRACT_ID = "TRIAXIS_COMPLETION_WORM_ANCHOR_EVENT_v1"
COMPLETION_WORM_ANCHOR_HEAD_CONTRACT_ID = "TRIAXIS_COMPLETION_WORM_ANCHOR_HEAD_v1"
COMPLETION_WORM_ANCHOR_STATUS_CONTRACT_ID = "TRIAXIS_COMPLETION_WORM_ANCHOR_STATUS_v1"
COMPLETION_WORM_ANCHOR_STATES = frozenset({"ABSENT", "UNKNOWN", "COMPLETED", "NO_EFFECT"})
COMPLETION_WORM_ANCHOR_BLOCKING_STATES = frozenset({"UNKNOWN", "COMPLETED"})
ZERO_SHA256 = "0" * 64


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise CompletionWORMAnchorError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


class CompletionWORMAnchorError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class SQLiteCompletionWORMAnchor:
    """Append-only provider-outcome anchor keyed by stable ``effect_id``."""

    def __init__(
        self,
        path: str | Path,
        *,
        anchor_id: str,
        authority_id: str,
        service_id: str,
        provider_id: str,
        provider_service_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        receipt_ttl: int = 30,
    ) -> None:
        for name, value in (
            ("anchor_id", anchor_id),
            ("authority_id", authority_id),
            ("service_id", service_id),
            ("provider_id", provider_id),
            ("provider_service_id", provider_service_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise CompletionWORMAnchorError("invalid_configuration", name)
        if type(receipt_ttl) is not int or receipt_ttl < 1:
            raise CompletionWORMAnchorError("invalid_configuration", "receipt_ttl")
        self.path = str(path)
        self.anchor_id = anchor_id
        self.authority_id = authority_id
        self.service_id = service_id
        self.provider_id = provider_id
        self.provider_service_id = provider_service_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self.receipt_ttl = receipt_ttl
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS completion_worm_anchor_meta (
              anchor_id TEXT PRIMARY KEY,
              provider_id TEXT NOT NULL,
              provider_service_id TEXT NOT NULL,
              sequence INTEGER NOT NULL,
              head_event_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS completion_worm_effects (
              effect_id TEXT PRIMARY KEY,
              payload_sha256 TEXT NOT NULL,
              state TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT NOT NULL,
              provider_receipt_sha256 TEXT NOT NULL,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT NOT NULL,
              outcome_at_tick INTEGER NOT NULL,
              last_event_sha256 TEXT NOT NULL,
              first_seen_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS completion_worm_events (
              sequence INTEGER PRIMARY KEY,
              event_sha256 TEXT UNIQUE NOT NULL,
              previous_event_sha256 TEXT NOT NULL,
              effect_id TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              state TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT NOT NULL,
              provider_receipt_sha256 TEXT NOT NULL,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT NOT NULL,
              outcome_at_tick INTEGER NOT NULL,
              from_state TEXT,
              event_json TEXT NOT NULL,
              signed_event_json TEXT NOT NULL,
              anchored_at_tick INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_completion_worm_events_effect
              ON completion_worm_events(effect_id, sequence);
            """
        )
        meta = self._conn.execute(
            "SELECT anchor_id,provider_id,provider_service_id,sequence,head_event_sha256 "
            "FROM completion_worm_anchor_meta ORDER BY anchor_id LIMIT 1"
        ).fetchone()
        if meta is None:
            self._conn.execute(
                "INSERT INTO completion_worm_anchor_meta("
                "anchor_id,provider_id,provider_service_id,sequence,head_event_sha256"
                ") VALUES(?,?,?,?,?)",
                (anchor_id, provider_id, provider_service_id, 0, ZERO_SHA256),
            )
        elif meta[0] != anchor_id or meta[1] != provider_id or meta[2] != provider_service_id:
            raise CompletionWORMAnchorError(
                "anchor_identity_conflict", f"{meta[0]}:{meta[1]}:{meta[2]}"
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteCompletionWORMAnchor":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _meta(self) -> tuple[int, str]:
        row = self._conn.execute(
            "SELECT sequence,head_event_sha256 FROM completion_worm_anchor_meta WHERE anchor_id=?",
            (self.anchor_id,),
        ).fetchone()
        if row is None:
            raise CompletionWORMAnchorError("anchor_meta_missing", self.anchor_id)
        return int(row[0]), str(row[1])

    def event_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM completion_worm_events").fetchone()
        return int(row[0])

    def effect_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM completion_worm_effects").fetchone()
        return int(row[0])

    def _state_root(self) -> str:
        rows = self._conn.execute(
            "SELECT effect_id,payload_sha256,state,generation,provider_request_id,"
            "provider_receipt_sha256,provider_response_sha256,evidence_sha256,outcome_at_tick,"
            "last_event_sha256 FROM completion_worm_effects ORDER BY effect_id"
        ).fetchall()
        return canonical_sha256(
            [
                {
                    "effect_id": row[0],
                    "payload_sha256": row[1],
                    "state": row[2],
                    "generation": row[3],
                    "provider_request_id": row[4],
                    "provider_receipt_sha256": row[5],
                    "provider_response_sha256": row[6],
                    "evidence_sha256": row[7],
                    "outcome_at_tick": row[8],
                    "last_event_sha256": row[9],
                }
                for row in rows
            ]
        )

    def health_snapshot(self) -> dict[str, Any]:
        sequence, head_event = self._meta()
        return {
            "anchor_id": self.anchor_id,
            "provider_id": self.provider_id,
            "provider_service_id": self.provider_service_id,
            "sequence": sequence,
            "head_event_sha256": head_event,
            "event_count": self.event_count(),
            "effect_count": self.effect_count(),
        }

    def get(self, effect_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload_sha256,state,generation,provider_request_id,provider_receipt_sha256,"
            "provider_response_sha256,evidence_sha256,outcome_at_tick,last_event_sha256,"
            "first_seen_tick,updated_at_tick FROM completion_worm_effects WHERE effect_id=?",
            (effect_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "effect_id": effect_id,
            "payload_sha256": row[0],
            "provider_id": self.provider_id,
            "provider_service_id": self.provider_service_id,
            "state": row[1],
            "generation": int(row[2]),
            "provider_request_id": row[3],
            "provider_receipt_sha256": row[4],
            "provider_response_sha256": row[5],
            "evidence_sha256": row[6],
            "outcome_at_tick": int(row[7]),
            "last_event_sha256": row[8],
            "first_seen_tick": int(row[9]),
            "updated_at_tick": int(row[10]),
        }

    def _signed_event(
        self,
        *,
        sequence: int,
        previous_event_sha256: str,
        receipt: Mapping[str, Any],
        from_state: str | None,
        anchored_at_tick: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        event = seal_mapping(
            {
                "contract_id": COMPLETION_WORM_ANCHOR_EVENT_CONTRACT_ID,
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "sequence": sequence,
                "previous_event_sha256": previous_event_sha256,
                "effect_id": receipt["effect_id"],
                "payload_sha256": receipt["payload_sha256"],
                "state": receipt["state"],
                "generation": receipt["generation"],
                "provider_request_id": receipt["provider_request_id"],
                "provider_receipt_sha256": receipt["receipt_sha256"],
                "provider_response_sha256": receipt["provider_response_sha256"],
                "evidence_sha256": receipt["evidence_sha256"],
                "outcome_at_tick": receipt["outcome_at_tick"],
                "from_state": from_state,
                "anchored_at_tick": anchored_at_tick,
                "event_sha256": "",
            },
            "event_sha256",
        )
        signed = sign_contract_envelope(
            event,
            digest_field="event_sha256",
            purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=anchored_at_tick,
            valid_until=anchored_at_tick + self.receipt_ttl,
        )
        return event, signed

    def ingest_provider_outcome(
        self,
        signed_provider_receipt: Mapping[str, Any],
        *,
        provider_registry: TrustKeyRegistry,
        expected_provider_signer_id: str,
        expected_provider_trust_domain: str,
        evaluation_tick: int,
        max_provider_receipt_age: int = 30,
    ) -> dict[str, Any]:
        if not isinstance(signed_provider_receipt, Mapping):
            raise CompletionWORMAnchorError(
                "invalid_provider_outcome_receipt", "mapping required"
            )
        inner = signed_provider_receipt.get("inner_contract")
        if not isinstance(inner, Mapping):
            raise CompletionWORMAnchorError(
                "invalid_provider_outcome_receipt", "inner contract required"
            )
        effect_id = inner.get("effect_id")
        payload_sha256 = inner.get("payload_sha256")
        if not _is_sha256(effect_id) or not _is_sha256(payload_sha256):
            raise CompletionWORMAnchorError(
                "invalid_provider_outcome_identity", f"{effect_id}:{payload_sha256}"
            )
        try:
            verified = verify_provider_outcome_receipt(
                signed_provider_receipt,
                registry=provider_registry,
                expected_provider_id=self.provider_id,
                expected_service_id=self.provider_service_id,
                expected_signer_id=expected_provider_signer_id,
                expected_trust_domain=expected_provider_trust_domain,
                expected_effect_id=effect_id,
                expected_payload_sha256=payload_sha256,
                evaluation_tick=evaluation_tick,
                max_receipt_age=max_provider_receipt_age,
            )
        except ProviderEffectError as exc:
            raise CompletionWORMAnchorError(exc.code, exc.detail) from exc
        receipt = verified["provider_receipt"]
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            sequence, previous = self._meta()
            row = self._conn.execute(
                "SELECT payload_sha256,state,generation,provider_request_id,provider_receipt_sha256,"
                "provider_response_sha256,evidence_sha256,outcome_at_tick FROM completion_worm_effects "
                "WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            from_state: str | None = None
            if row is not None:
                if row[0] != payload_sha256:
                    raise CompletionWORMAnchorError("worm_anchor_payload_conflict", effect_id)
                current_state = str(row[1])
                current_generation = int(row[2])
                current_request = str(row[3])
                exact_statement = (
                    current_state == receipt["state"]
                    and current_generation == receipt["generation"]
                    and current_request == receipt["provider_request_id"]
                    and row[5] == receipt["provider_response_sha256"]
                    and row[6] == receipt["evidence_sha256"]
                    and int(row[7]) == receipt["outcome_at_tick"]
                )
                if exact_statement:
                    self._conn.commit()
                    return {
                        "status": "PASS",
                        "idempotent_replay": True,
                        "effect": self.get(effect_id),
                        "provider_receipt": receipt,
                    }
                if receipt["generation"] < current_generation:
                    raise CompletionWORMAnchorError(
                        "worm_anchor_generation_rollback",
                        f"current={current_generation} observed={receipt['generation']}",
                    )
                if receipt["generation"] == current_generation:
                    if (
                        current_state == "UNKNOWN"
                        and receipt["state"] in {"COMPLETED", "NO_EFFECT"}
                        and receipt["provider_request_id"] == current_request
                    ):
                        from_state = current_state
                    else:
                        raise CompletionWORMAnchorError(
                            "worm_anchor_outcome_conflict",
                            f"current={current_state} observed={receipt['state']}",
                        )
                elif receipt["generation"] == current_generation + 1:
                    if current_state != "NO_EFFECT":
                        raise CompletionWORMAnchorError(
                            "worm_anchor_generation_without_no_effect", current_state
                        )
                    from_state = current_state
                else:
                    raise CompletionWORMAnchorError(
                        "worm_anchor_generation_gap",
                        f"current={current_generation} observed={receipt['generation']}",
                    )
            event, signed = self._signed_event(
                sequence=sequence + 1,
                previous_event_sha256=previous,
                receipt=receipt,
                from_state=from_state,
                anchored_at_tick=evaluation_tick,
            )
            self._conn.execute(
                "INSERT INTO completion_worm_events("
                "sequence,event_sha256,previous_event_sha256,effect_id,payload_sha256,state,generation,"
                "provider_request_id,provider_receipt_sha256,provider_response_sha256,evidence_sha256,"
                "outcome_at_tick,from_state,event_json,signed_event_json,anchored_at_tick"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event["sequence"],
                    event["event_sha256"],
                    event["previous_event_sha256"],
                    event["effect_id"],
                    event["payload_sha256"],
                    event["state"],
                    event["generation"],
                    event["provider_request_id"],
                    event["provider_receipt_sha256"],
                    event["provider_response_sha256"],
                    event["evidence_sha256"],
                    event["outcome_at_tick"],
                    event["from_state"],
                    json.dumps(materialize_json(event), sort_keys=True, separators=(",", ":")),
                    json.dumps(materialize_json(signed), sort_keys=True, separators=(",", ":")),
                    evaluation_tick,
                ),
            )
            if row is None:
                self._conn.execute(
                    "INSERT INTO completion_worm_effects("
                    "effect_id,payload_sha256,state,generation,provider_request_id,provider_receipt_sha256,"
                    "provider_response_sha256,evidence_sha256,outcome_at_tick,last_event_sha256,"
                    "first_seen_tick,updated_at_tick"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        effect_id,
                        payload_sha256,
                        receipt["state"],
                        receipt["generation"],
                        receipt["provider_request_id"],
                        receipt["receipt_sha256"],
                        receipt["provider_response_sha256"],
                        receipt["evidence_sha256"],
                        receipt["outcome_at_tick"],
                        event["event_sha256"],
                        evaluation_tick,
                        evaluation_tick,
                    ),
                )
            else:
                self._conn.execute(
                    "UPDATE completion_worm_effects SET state=?,generation=?,provider_request_id=?,"
                    "provider_receipt_sha256=?,provider_response_sha256=?,evidence_sha256=?,"
                    "outcome_at_tick=?,last_event_sha256=?,updated_at_tick=? WHERE effect_id=?",
                    (
                        receipt["state"],
                        receipt["generation"],
                        receipt["provider_request_id"],
                        receipt["receipt_sha256"],
                        receipt["provider_response_sha256"],
                        receipt["evidence_sha256"],
                        receipt["outcome_at_tick"],
                        event["event_sha256"],
                        evaluation_tick,
                        effect_id,
                    ),
                )
            self._conn.execute(
                "UPDATE completion_worm_anchor_meta SET sequence=?,head_event_sha256=? WHERE anchor_id=?",
                (event["sequence"], event["event_sha256"], self.anchor_id),
            )
            self._conn.commit()
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "effect": self.get(effect_id),
                "provider_receipt": receipt,
                "signed_anchor_event": signed,
            }
        except sqlite3.IntegrityError as exc:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise CompletionWORMAnchorError("worm_anchor_uniqueness_conflict", str(exc)) from exc
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def events_since(self, sequence: int) -> list[dict[str, Any]]:
        if type(sequence) is not int or sequence < 0:
            raise CompletionWORMAnchorError("invalid_sequence", str(sequence))
        rows = self._conn.execute(
            "SELECT signed_event_json FROM completion_worm_events WHERE sequence>? ORDER BY sequence",
            (sequence,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def head(self, *, now_tick: int) -> dict[str, Any]:
        if type(now_tick) is not int or now_tick < 0:
            raise CompletionWORMAnchorError("invalid_now_tick", str(now_tick))
        sequence, head_event = self._meta()
        head = seal_mapping(
            {
                "contract_id": COMPLETION_WORM_ANCHOR_HEAD_CONTRACT_ID,
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "sequence": sequence,
                "head_event_sha256": head_event,
                "state_root_sha256": self._state_root(),
                "issued_at_tick": now_tick,
                "authority_granted": False,
                "head_sha256": "",
            },
            "head_sha256",
        )
        return sign_contract_envelope(
            head,
            digest_field="head_sha256",
            purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=now_tick,
            valid_until=now_tick + self.receipt_ttl,
        )

    def issue_status(
        self,
        *,
        effect_id: str,
        expected_payload_sha256: str,
        challenge: str,
        verifier_id: str,
        verifier_epoch_sha256: str,
        requested_at: int,
        issued_at: int,
        valid_until: int | None = None,
    ) -> dict[str, Any]:
        if not _is_sha256(effect_id):
            raise CompletionWORMAnchorError("invalid_effect_id", str(effect_id))
        if not _is_sha256(expected_payload_sha256):
            raise CompletionWORMAnchorError(
                "invalid_payload_sha256", str(expected_payload_sha256)
            )
        if not isinstance(verifier_id, str) or not verifier_id:
            raise CompletionWORMAnchorError("invalid_verifier_id", str(verifier_id))
        if not _is_sha256(verifier_epoch_sha256):
            raise CompletionWORMAnchorError(
                "invalid_verifier_epoch", str(verifier_epoch_sha256)
            )
        if (
            type(requested_at) is not int
            or type(issued_at) is not int
            or requested_at < 0
            or issued_at < requested_at
        ):
            raise CompletionWORMAnchorError(
                "invalid_response_time", f"{requested_at}:{issued_at}"
            )
        if valid_until is None:
            valid_until = issued_at + self.receipt_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise CompletionWORMAnchorError("invalid_response_window", str(valid_until))
        current = self.get(effect_id)
        if current is None:
            state = "ABSENT"
            payload_sha256 = expected_payload_sha256
            generation = 0
            provider_request_id = None
            provider_receipt_sha256 = None
            provider_response_sha256 = None
            evidence_sha256 = None
            outcome_at_tick = None
        else:
            state = current["state"]
            payload_sha256 = current["payload_sha256"]
            generation = current["generation"]
            provider_request_id = current["provider_request_id"]
            provider_receipt_sha256 = current["provider_receipt_sha256"]
            provider_response_sha256 = current["provider_response_sha256"]
            evidence_sha256 = current["evidence_sha256"]
            outcome_at_tick = current["outcome_at_tick"]
        sequence, head_event = self._meta()
        status = seal_mapping(
            {
                "contract_id": COMPLETION_WORM_ANCHOR_STATUS_CONTRACT_ID,
                "anchor_id": self.anchor_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "provider_id": self.provider_id,
                "provider_service_id": self.provider_service_id,
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "state": state,
                "generation": generation,
                "provider_request_id": provider_request_id,
                "provider_receipt_sha256": provider_receipt_sha256,
                "provider_response_sha256": provider_response_sha256,
                "evidence_sha256": evidence_sha256,
                "outcome_at_tick": outcome_at_tick,
                "anchor_sequence": sequence,
                "anchor_head_event_sha256": head_event,
                "anchor_state_root_sha256": self._state_root(),
                "verifier_id": verifier_id,
                "verifier_epoch_sha256": verifier_epoch_sha256,
                "challenge_sha256": _challenge_sha256(challenge),
                "requested_at": requested_at,
                "issued_at": issued_at,
                "valid_until": valid_until,
                "authority_granted": False,
                "status_sha256": "",
            },
            "status_sha256",
        )
        return sign_contract_envelope(
            status,
            digest_field="status_sha256",
            purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


def verify_completion_worm_anchor_event(
    signed_event: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
    expected_effect_id: str | None = None,
    expected_payload_sha256: str | None = None,
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_event,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
        expected_digest_field="event_sha256",
        expected_inner_contract_id=COMPLETION_WORM_ANCHOR_EVENT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_event_signature", str(verified["errors"])
        )
    event = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(event, dict) or not isinstance(envelope, dict):
        raise CompletionWORMAnchorError("invalid_worm_anchor_event", "object required")
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
    ):
        if event.get(field) != expected:
            raise CompletionWORMAnchorError(
                f"worm_anchor_{field}_mismatch", str(event.get(field))
            )
    if expected_effect_id is not None and event.get("effect_id") != expected_effect_id:
        raise CompletionWORMAnchorError(
            "worm_anchor_effect_id_mismatch", str(event.get("effect_id"))
        )
    if expected_payload_sha256 is not None and event.get("payload_sha256") != expected_payload_sha256:
        raise CompletionWORMAnchorError(
            "worm_anchor_payload_mismatch", str(event.get("payload_sha256"))
        )
    if type(event.get("sequence")) is not int or event["sequence"] < 1:
        raise CompletionWORMAnchorError("invalid_worm_anchor_sequence", str(event.get("sequence")))
    for field in (
        "previous_event_sha256",
        "effect_id",
        "payload_sha256",
        "provider_receipt_sha256",
        "evidence_sha256",
        "event_sha256",
    ):
        if not _is_sha256(event.get(field)):
            raise CompletionWORMAnchorError(
                "invalid_worm_anchor_digest", f"{field}={event.get(field)}"
            )
    if event.get("state") not in {"UNKNOWN", "COMPLETED", "NO_EFFECT"}:
        raise CompletionWORMAnchorError("invalid_worm_anchor_state", str(event.get("state")))
    if type(event.get("generation")) is not int or event["generation"] < 1:
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_generation", str(event.get("generation"))
        )
    if not isinstance(event.get("provider_request_id"), str) or not event["provider_request_id"]:
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_provider_request_id", str(event.get("provider_request_id"))
        )
    if event["state"] == "COMPLETED" and not _is_sha256(event.get("provider_response_sha256")):
        raise CompletionWORMAnchorError(
            "worm_anchor_provider_response_required", str(event.get("provider_response_sha256"))
        )
    if event["state"] != "COMPLETED" and event.get("provider_response_sha256") is not None and not _is_sha256(event.get("provider_response_sha256")):
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_provider_response", str(event.get("provider_response_sha256"))
        )
    for field in ("outcome_at_tick", "anchored_at_tick"):
        if type(event.get(field)) is not int or event[field] < 0:
            raise CompletionWORMAnchorError(f"invalid_{field}", str(event.get(field)))
    if event["anchored_at_tick"] < event["outcome_at_tick"]:
        raise CompletionWORMAnchorError(
            "worm_anchor_predates_outcome", str(event["anchored_at_tick"])
        )
    if event["anchored_at_tick"] != envelope.get("issued_at"):
        raise CompletionWORMAnchorError(
            "worm_anchor_event_time_binding_mismatch", str(event["anchored_at_tick"])
        )
    return {
        "status": "PASS",
        "event": event,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_worm_anchor_event_chain(
    signed_events: Sequence[Mapping[str, Any]],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
) -> dict[str, Any]:
    previous = ZERO_SHA256
    expected_sequence = 1
    effects: dict[str, dict[str, Any]] = {}
    verified_events: list[dict[str, Any]] = []
    for signed_event in signed_events:
        result = verify_completion_worm_anchor_event(
            signed_event,
            registry=registry,
            expected_anchor_id=expected_anchor_id,
            expected_authority_id=expected_authority_id,
            expected_service_id=expected_service_id,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            expected_signer_id=expected_signer_id,
            expected_trust_domain=expected_trust_domain,
            evaluation_tick=evaluation_tick,
        )
        event = result["event"]
        if event["sequence"] != expected_sequence:
            raise CompletionWORMAnchorError(
                "worm_anchor_chain_sequence_gap",
                f"expected={expected_sequence} observed={event['sequence']}",
            )
        if event["previous_event_sha256"] != previous:
            raise CompletionWORMAnchorError(
                "worm_anchor_chain_parent_mismatch", str(event["sequence"])
            )
        current = effects.get(event["effect_id"])
        if current is None:
            if event["from_state"] is not None or event["generation"] != 1:
                raise CompletionWORMAnchorError(
                    "worm_anchor_chain_invalid_genesis", event["effect_id"]
                )
        else:
            if event["payload_sha256"] != current["payload_sha256"]:
                raise CompletionWORMAnchorError(
                    "worm_anchor_chain_payload_conflict", event["effect_id"]
                )
            if event["from_state"] != current["state"]:
                raise CompletionWORMAnchorError(
                    "worm_anchor_chain_state_discontinuity", event["effect_id"]
                )
            if event["generation"] == current["generation"]:
                if not (
                    current["state"] == "UNKNOWN"
                    and event["state"] in {"COMPLETED", "NO_EFFECT"}
                    and event["provider_request_id"] == current["provider_request_id"]
                ):
                    raise CompletionWORMAnchorError(
                        "worm_anchor_chain_invalid_reconciliation", event["effect_id"]
                    )
            elif event["generation"] == current["generation"] + 1:
                if current["state"] != "NO_EFFECT":
                    raise CompletionWORMAnchorError(
                        "worm_anchor_chain_generation_without_no_effect", event["effect_id"]
                    )
            else:
                raise CompletionWORMAnchorError(
                    "worm_anchor_chain_generation_gap", event["effect_id"]
                )
        effects[event["effect_id"]] = {
            "payload_sha256": event["payload_sha256"],
            "state": event["state"],
            "generation": event["generation"],
            "provider_request_id": event["provider_request_id"],
            "provider_receipt_sha256": event["provider_receipt_sha256"],
            "provider_response_sha256": event["provider_response_sha256"],
            "evidence_sha256": event["evidence_sha256"],
            "outcome_at_tick": event["outcome_at_tick"],
            "last_event_sha256": event["event_sha256"],
        }
        previous = event["event_sha256"]
        expected_sequence += 1
        verified_events.append(event)
    return {
        "status": "PASS",
        "event_count": len(verified_events),
        "head_sequence": len(verified_events),
        "head_event_sha256": previous,
        "effects": materialize_json(effects),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_worm_anchor_head(
    signed_head: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
    expected_sequence: int | None = None,
    expected_head_event_sha256: str | None = None,
    expected_state_root_sha256: str | None = None,
    max_head_age: int = 30,
) -> dict[str, Any]:
    if type(max_head_age) is not int or max_head_age < 0:
        raise CompletionWORMAnchorError("invalid_max_head_age", str(max_head_age))
    verified = verify_contract_envelope(
        signed_head,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
        expected_digest_field="head_sha256",
        expected_inner_contract_id=COMPLETION_WORM_ANCHOR_HEAD_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_head_signature", str(verified["errors"])
        )
    head = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(head, dict) or not isinstance(envelope, dict):
        raise CompletionWORMAnchorError("invalid_worm_anchor_head", "object required")
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
    ):
        if head.get(field) != expected:
            raise CompletionWORMAnchorError(
                f"worm_anchor_{field}_mismatch", str(head.get(field))
            )
    if type(head.get("sequence")) is not int or head["sequence"] < 0:
        raise CompletionWORMAnchorError("invalid_worm_anchor_sequence", str(head.get("sequence")))
    for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
        if not _is_sha256(head.get(field)):
            raise CompletionWORMAnchorError(
                "invalid_worm_anchor_head_digest", f"{field}={head.get(field)}"
            )
    issued_at = head.get("issued_at_tick")
    if (
        type(issued_at) is not int
        or issued_at < 0
        or issued_at != envelope.get("issued_at")
        or issued_at > evaluation_tick
        or evaluation_tick - issued_at > max_head_age
    ):
        raise CompletionWORMAnchorError("worm_anchor_head_not_fresh", str(issued_at))
    for field, observed, expected in (
        ("sequence", head["sequence"], expected_sequence),
        ("head_event_sha256", head["head_event_sha256"], expected_head_event_sha256),
        ("state_root_sha256", head["state_root_sha256"], expected_state_root_sha256),
    ):
        if expected is not None and observed != expected:
            raise CompletionWORMAnchorError(
                f"worm_anchor_{field}_mismatch", f"expected={expected} observed={observed}"
            )
    if head.get("authority_granted") is not False:
        raise CompletionWORMAnchorError(
            "worm_anchor_authority_expansion", str(head.get("authority_granted"))
        )
    return {
        "status": "PASS",
        "head": head,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_worm_anchor_status(
    signed_status: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_anchor_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
    max_response_age: int = 5,
) -> dict[str, Any]:
    allowed = set(allowed_states)
    if not allowed or not allowed.issubset(COMPLETION_WORM_ANCHOR_STATES):
        raise CompletionWORMAnchorError(
            "invalid_allowed_worm_anchor_states", str(tuple(allowed_states))
        )
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    verified = verify_contract_envelope(
        signed_status,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_WORM_ANCHOR,
        expected_digest_field="status_sha256",
        expected_inner_contract_id=COMPLETION_WORM_ANCHOR_STATUS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_status_signature", str(verified["errors"])
        )
    status = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(status, dict) or not isinstance(envelope, dict):
        raise CompletionWORMAnchorError("invalid_worm_anchor_status", "object required")
    for field, expected in (
        ("anchor_id", expected_anchor_id),
        ("authority_id", expected_authority_id),
        ("service_id", expected_service_id),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
    ):
        if status.get(field) != expected:
            raise CompletionWORMAnchorError(
                f"worm_anchor_{field}_mismatch", str(status.get(field))
            )
    if status.get("state") not in allowed:
        raise CompletionWORMAnchorError(
            "worm_anchor_state_blocks_retry", str(status.get("state"))
        )
    if (
        status.get("verifier_id") != challenge_ledger.session.verifier_id
        or status.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
        or status.get("challenge_sha256") != challenge["challenge_sha256"]
        or status.get("requested_at") != challenge["issued_at"]
    ):
        raise CompletionWORMAnchorError(
            "worm_anchor_challenge_binding_mismatch", str(status.get("challenge_sha256"))
        )
    issued_at = status.get("issued_at")
    if (
        type(issued_at) is not int
        or issued_at != envelope.get("issued_at")
        or issued_at > evaluation_tick
        or evaluation_tick - issued_at > max_response_age
        or status.get("valid_until") != envelope.get("valid_until")
    ):
        raise CompletionWORMAnchorError("worm_anchor_status_not_fresh", str(issued_at))
    if type(status.get("anchor_sequence")) is not int or status["anchor_sequence"] < 0:
        raise CompletionWORMAnchorError(
            "invalid_worm_anchor_sequence", str(status.get("anchor_sequence"))
        )
    for field in ("anchor_head_event_sha256", "anchor_state_root_sha256"):
        if not _is_sha256(status.get(field)):
            raise CompletionWORMAnchorError(
                "invalid_worm_anchor_head", f"{field}={status.get(field)}"
            )
    if status.get("authority_granted") is not False:
        raise CompletionWORMAnchorError(
            "worm_anchor_authority_expansion", str(status.get("authority_granted"))
        )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "worm_anchor_status": status,
        "external_effect_permitted": status["state"] in {"ABSENT", "NO_EFFECT"},
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "COMPLETION_WORM_ANCHOR_BLOCKING_STATES",
    "COMPLETION_WORM_ANCHOR_EVENT_CONTRACT_ID",
    "COMPLETION_WORM_ANCHOR_HEAD_CONTRACT_ID",
    "COMPLETION_WORM_ANCHOR_STATES",
    "COMPLETION_WORM_ANCHOR_STATUS_CONTRACT_ID",
    "CompletionWORMAnchorError",
    "SQLiteCompletionWORMAnchor",
    "verify_completion_worm_anchor_event",
    "verify_completion_worm_anchor_event_chain",
    "verify_completion_worm_anchor_head",
    "verify_completion_worm_anchor_status",
]
