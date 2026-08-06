"""TRIAXIS v3.29 external completion witness.

The provider-side idempotency database from v3.28 is one logical state domain.
This module records the exact provider request and signed provider outcome in a
separate append-only, hash-chained and signed state domain.  A current witness
can therefore block a duplicate after rollback or loss of the provider's local
idempotency database.

The reference uses SQLite and an in-process Ed25519 key.  It does not claim WORM
storage, physical independence, independent administration or production
exactly-once execution.  Witness evidence never grants action authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .idempotent_effect_provider import ProviderEffectError, verify_provider_outcome_receipt
from .integrity import canonical_sha256, materialize_json, seal_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_WITNESS_EVENT_CONTRACT_ID = "TRIAXIS_EXTERNAL_COMPLETION_WITNESS_EVENT_v1"
COMPLETION_WITNESS_HEAD_CONTRACT_ID = "TRIAXIS_EXTERNAL_COMPLETION_WITNESS_HEAD_v1"
COMPLETION_WITNESS_STATUS_CONTRACT_ID = "TRIAXIS_EXTERNAL_COMPLETION_WITNESS_STATUS_v1"
COMPLETION_WITNESS_STATES = frozenset({"ABSENT", "RESERVED", "UNKNOWN", "COMPLETED", "NO_EFFECT"})
COMPLETION_WITNESS_BLOCKING_STATES = frozenset({"RESERVED", "UNKNOWN", "COMPLETED"})
ZERO_SHA256 = "0" * 64


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise CompletionWitnessError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


class CompletionWitnessError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class SQLiteExternalCompletionWitness:
    """Separately persisted completion memory keyed by stable ``effect_id``."""

    def __init__(
        self,
        path: str | Path,
        *,
        witness_id: str,
        authority_id: str,
        service_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        receipt_ttl: int = 30,
    ) -> None:
        for name, value in (
            ("witness_id", witness_id),
            ("authority_id", authority_id),
            ("service_id", service_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise CompletionWitnessError("invalid_configuration", name)
        if type(receipt_ttl) is not int or receipt_ttl < 1:
            raise CompletionWitnessError("invalid_configuration", "receipt_ttl")
        self.path = str(path)
        self.witness_id = witness_id
        self.authority_id = authority_id
        self.service_id = service_id
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
            CREATE TABLE IF NOT EXISTS completion_witness_meta (
              witness_id TEXT PRIMARY KEY,
              sequence INTEGER NOT NULL,
              head_event_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS completion_effects (
              effect_id TEXT PRIMARY KEY,
              payload_sha256 TEXT NOT NULL,
              provider_id TEXT NOT NULL,
              provider_service_id TEXT NOT NULL,
              state TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT NOT NULL,
              provider_receipt_sha256 TEXT,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT,
              last_event_sha256 TEXT NOT NULL,
              created_at_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS completion_events (
              sequence INTEGER PRIMARY KEY,
              event_sha256 TEXT UNIQUE NOT NULL,
              previous_event_sha256 TEXT NOT NULL,
              effect_id TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              provider_id TEXT NOT NULL,
              provider_service_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT NOT NULL,
              from_state TEXT,
              to_state TEXT NOT NULL,
              provider_receipt_sha256 TEXT,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT,
              event_json TEXT NOT NULL,
              signed_event_json TEXT NOT NULL,
              created_at_tick INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_completion_events_effect
              ON completion_events(effect_id, sequence);
            """
        )
        meta = self._conn.execute(
            "SELECT witness_id,sequence,head_event_sha256 FROM completion_witness_meta ORDER BY witness_id LIMIT 1"
        ).fetchone()
        if meta is None:
            self._conn.execute(
                "INSERT INTO completion_witness_meta(witness_id,sequence,head_event_sha256) VALUES(?,?,?)",
                (witness_id, 0, ZERO_SHA256),
            )
        elif meta[0] != witness_id:
            raise CompletionWitnessError("witness_id_conflict", str(meta[0]))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteExternalCompletionWitness":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _meta(self) -> tuple[int, str]:
        row = self._conn.execute(
            "SELECT sequence,head_event_sha256 FROM completion_witness_meta WHERE witness_id=?",
            (self.witness_id,),
        ).fetchone()
        if row is None:
            raise CompletionWitnessError("witness_meta_missing", self.witness_id)
        return int(row[0]), str(row[1])

    def effect_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM completion_effects").fetchone()
        return int(row[0])

    def _state_root(self) -> str:
        rows = self._conn.execute(
            "SELECT effect_id,payload_sha256,provider_id,provider_service_id,state,generation,"
            "provider_request_id,provider_receipt_sha256,last_event_sha256 "
            "FROM completion_effects ORDER BY effect_id"
        ).fetchall()
        return canonical_sha256(
            [
                {
                    "effect_id": row[0],
                    "payload_sha256": row[1],
                    "provider_id": row[2],
                    "provider_service_id": row[3],
                    "state": row[4],
                    "generation": row[5],
                    "provider_request_id": row[6],
                    "provider_receipt_sha256": row[7],
                    "last_event_sha256": row[8],
                }
                for row in rows
            ]
        )

    def health_snapshot(self) -> dict[str, Any]:
        sequence, head = self._meta()
        return {
            "witness_id": self.witness_id,
            "sequence": sequence,
            "head_event_sha256": head,
            "effect_count": self.effect_count(),
        }

    def get(self, effect_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload_sha256,provider_id,provider_service_id,state,generation,provider_request_id,"
            "provider_receipt_sha256,provider_response_sha256,evidence_sha256,last_event_sha256,"
            "created_at_tick,updated_at_tick FROM completion_effects WHERE effect_id=?",
            (effect_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "effect_id": effect_id,
            "payload_sha256": row[0],
            "provider_id": row[1],
            "provider_service_id": row[2],
            "state": row[3],
            "generation": int(row[4]),
            "provider_request_id": row[5],
            "provider_receipt_sha256": row[6],
            "provider_response_sha256": row[7],
            "evidence_sha256": row[8],
            "last_event_sha256": row[9],
            "created_at_tick": int(row[10]),
            "updated_at_tick": int(row[11]),
        }

    @staticmethod
    def _validate_identity(
        *,
        effect_id: str,
        payload_sha256: str,
        provider_id: str,
        provider_service_id: str,
        provider_request_id: str,
        now_tick: int,
    ) -> None:
        if not _is_sha256(effect_id):
            raise CompletionWitnessError("invalid_effect_id", str(effect_id))
        if not _is_sha256(payload_sha256):
            raise CompletionWitnessError("invalid_payload_sha256", str(payload_sha256))
        for name, value in (
            ("provider_id", provider_id),
            ("provider_service_id", provider_service_id),
            ("provider_request_id", provider_request_id),
        ):
            if not isinstance(value, str) or not value:
                raise CompletionWitnessError(f"invalid_{name}", str(value))
        if type(now_tick) is not int or now_tick < 0:
            raise CompletionWitnessError("invalid_now_tick", str(now_tick))

    def _signed_event(
        self,
        *,
        sequence: int,
        previous_event_sha256: str,
        effect_id: str,
        payload_sha256: str,
        provider_id: str,
        provider_service_id: str,
        generation: int,
        provider_request_id: str,
        from_state: str | None,
        to_state: str,
        provider_receipt_sha256: str | None,
        provider_response_sha256: str | None,
        evidence_sha256: str | None,
        issued_at_tick: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        event = seal_mapping(
            {
                "contract_id": COMPLETION_WITNESS_EVENT_CONTRACT_ID,
                "witness_id": self.witness_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "sequence": sequence,
                "previous_event_sha256": previous_event_sha256,
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "provider_id": provider_id,
                "provider_service_id": provider_service_id,
                "generation": generation,
                "provider_request_id": provider_request_id,
                "from_state": from_state,
                "to_state": to_state,
                "provider_receipt_sha256": provider_receipt_sha256,
                "provider_response_sha256": provider_response_sha256,
                "evidence_sha256": evidence_sha256,
                "issued_at_tick": issued_at_tick,
                "event_sha256": "",
            },
            "event_sha256",
        )
        signed = sign_contract_envelope(
            event,
            digest_field="event_sha256",
            purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at_tick,
            valid_until=issued_at_tick + self.receipt_ttl,
        )
        return event, signed

    def _append_event(self, event: Mapping[str, Any], signed: Mapping[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO completion_events(sequence,event_sha256,previous_event_sha256,effect_id,payload_sha256,"
            "provider_id,provider_service_id,generation,provider_request_id,from_state,to_state,"
            "provider_receipt_sha256,provider_response_sha256,evidence_sha256,event_json,signed_event_json,created_at_tick) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event["sequence"],
                event["event_sha256"],
                event["previous_event_sha256"],
                event["effect_id"],
                event["payload_sha256"],
                event["provider_id"],
                event["provider_service_id"],
                event["generation"],
                event["provider_request_id"],
                event["from_state"],
                event["to_state"],
                event["provider_receipt_sha256"],
                event["provider_response_sha256"],
                event["evidence_sha256"],
                json.dumps(materialize_json(event), sort_keys=True, separators=(",", ":")),
                json.dumps(materialize_json(signed), sort_keys=True, separators=(",", ":")),
                event["issued_at_tick"],
            ),
        )
        self._conn.execute(
            "UPDATE completion_witness_meta SET sequence=?,head_event_sha256=? WHERE witness_id=?",
            (event["sequence"], event["event_sha256"], self.witness_id),
        )

    def reserve(
        self,
        *,
        effect_id: str,
        payload_sha256: str,
        provider_id: str,
        provider_service_id: str,
        provider_request_id: str,
        now_tick: int,
    ) -> dict[str, Any]:
        """Reserve the independent witness before the provider call."""
        self._validate_identity(
            effect_id=effect_id,
            payload_sha256=payload_sha256,
            provider_id=provider_id,
            provider_service_id=provider_service_id,
            provider_request_id=provider_request_id,
            now_tick=now_tick,
        )
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            sequence, previous = self._meta()
            row = self._conn.execute(
                "SELECT payload_sha256,provider_id,provider_service_id,state,generation,provider_request_id,"
                "provider_receipt_sha256,provider_response_sha256,evidence_sha256 FROM completion_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is not None:
                if row[0] != payload_sha256:
                    raise CompletionWitnessError("completion_witness_payload_conflict", effect_id)
                if row[1] != provider_id or row[2] != provider_service_id:
                    raise CompletionWitnessError("completion_witness_provider_conflict", effect_id)
                if row[3] != "NO_EFFECT":
                    self._conn.commit()
                    return {
                        "status": "PASS",
                        "idempotent_replay": True,
                        "external_effect_permitted": False,
                        "current_state": row[3],
                        "effect": self.get(effect_id),
                    }
                generation = int(row[4]) + 1
                from_state = "NO_EFFECT"
            else:
                generation = 1
                from_state = None
            event, signed = self._signed_event(
                sequence=sequence + 1,
                previous_event_sha256=previous,
                effect_id=effect_id,
                payload_sha256=payload_sha256,
                provider_id=provider_id,
                provider_service_id=provider_service_id,
                generation=generation,
                provider_request_id=provider_request_id,
                from_state=from_state,
                to_state="RESERVED",
                provider_receipt_sha256=None,
                provider_response_sha256=None,
                evidence_sha256=None,
                issued_at_tick=now_tick,
            )
            if row is None:
                self._conn.execute(
                    "INSERT INTO completion_effects(effect_id,payload_sha256,provider_id,provider_service_id,state,"
                    "generation,provider_request_id,last_event_sha256,created_at_tick,updated_at_tick) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        effect_id,
                        payload_sha256,
                        provider_id,
                        provider_service_id,
                        "RESERVED",
                        generation,
                        provider_request_id,
                        event["event_sha256"],
                        now_tick,
                        now_tick,
                    ),
                )
            else:
                self._conn.execute(
                    "UPDATE completion_effects SET state='RESERVED',generation=?,provider_request_id=?,"
                    "provider_receipt_sha256=NULL,provider_response_sha256=NULL,evidence_sha256=NULL,"
                    "last_event_sha256=?,updated_at_tick=? WHERE effect_id=? AND state='NO_EFFECT'",
                    (generation, provider_request_id, event["event_sha256"], now_tick, effect_id),
                )
            self._append_event(event, signed)
            self._conn.commit()
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "external_effect_permitted": True,
                "effect": self.get(effect_id),
                "signed_witness_event": signed,
            }
        except sqlite3.IntegrityError as exc:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise CompletionWitnessError("completion_witness_uniqueness_conflict", str(exc)) from exc
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def record_provider_outcome(
        self,
        signed_provider_receipt: Mapping[str, Any],
        *,
        provider_registry: TrustKeyRegistry,
        expected_provider_signer_id: str,
        expected_provider_trust_domain: str,
        evaluation_tick: int,
        max_provider_receipt_age: int = 30,
    ) -> dict[str, Any]:
        """Verify and append one provider outcome receipt.

        ``RESERVED`` may become ``COMPLETED``, ``UNKNOWN`` or ``NO_EFFECT``.
        ``UNKNOWN`` may later become ``COMPLETED`` or ``NO_EFFECT`` through a
        newer signed provider receipt for the same generation and request.
        """
        if not isinstance(signed_provider_receipt, Mapping):
            raise CompletionWitnessError("invalid_provider_receipt", "mapping required")
        inner = signed_provider_receipt.get("inner_contract")
        if not isinstance(inner, Mapping):
            raise CompletionWitnessError("invalid_provider_receipt", "inner_contract required")
        effect_id = inner.get("effect_id")
        if not _is_sha256(effect_id):
            raise CompletionWitnessError("invalid_effect_id", str(effect_id))
        current = self.get(effect_id)
        if current is None:
            raise CompletionWitnessError("completion_witness_reservation_missing", effect_id)
        try:
            verified = verify_provider_outcome_receipt(
                signed_provider_receipt,
                registry=provider_registry,
                expected_provider_id=current["provider_id"],
                expected_service_id=current["provider_service_id"],
                expected_signer_id=expected_provider_signer_id,
                expected_trust_domain=expected_provider_trust_domain,
                expected_effect_id=effect_id,
                expected_payload_sha256=current["payload_sha256"],
                evaluation_tick=evaluation_tick,
                max_receipt_age=max_provider_receipt_age,
            )
        except ProviderEffectError as exc:
            raise CompletionWitnessError(exc.code, exc.detail) from exc
        receipt = verified["provider_receipt"]
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            sequence, previous = self._meta()
            row = self._conn.execute(
                "SELECT payload_sha256,provider_id,provider_service_id,state,generation,provider_request_id,"
                "provider_receipt_sha256,provider_response_sha256,evidence_sha256 FROM completion_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise CompletionWitnessError("completion_witness_reservation_missing", effect_id)
            if row[0] != receipt["payload_sha256"] or row[1] != receipt["provider_id"] or row[2] != receipt["service_id"]:
                raise CompletionWitnessError("completion_witness_provider_binding_mismatch", effect_id)
            if int(row[4]) != receipt["generation"]:
                raise CompletionWitnessError(
                    "completion_witness_generation_mismatch",
                    f"expected={row[4]} observed={receipt['generation']}",
                )
            if row[5] != receipt["provider_request_id"]:
                raise CompletionWitnessError("completion_witness_provider_request_mismatch", receipt["provider_request_id"])
            outcome = receipt["state"]
            receipt_sha = receipt["receipt_sha256"]
            if row[3] == outcome:
                if (
                    row[6] == receipt_sha
                    and row[7] == receipt["provider_response_sha256"]
                    and row[8] == receipt["evidence_sha256"]
                ):
                    self._conn.commit()
                    return {
                        "status": "PASS",
                        "idempotent_replay": True,
                        "effect": self.get(effect_id),
                    }
                raise CompletionWitnessError("completion_witness_outcome_replay_conflict", effect_id)
            allowed = row[3] == "RESERVED" or (row[3] == "UNKNOWN" and outcome in {"COMPLETED", "NO_EFFECT"})
            if not allowed:
                raise CompletionWitnessError(
                    "completion_witness_state_mismatch",
                    f"observed={row[3]} outcome={outcome}",
                )
            event, signed = self._signed_event(
                sequence=sequence + 1,
                previous_event_sha256=previous,
                effect_id=effect_id,
                payload_sha256=receipt["payload_sha256"],
                provider_id=receipt["provider_id"],
                provider_service_id=receipt["service_id"],
                generation=receipt["generation"],
                provider_request_id=receipt["provider_request_id"],
                from_state=row[3],
                to_state=outcome,
                provider_receipt_sha256=receipt_sha,
                provider_response_sha256=receipt["provider_response_sha256"],
                evidence_sha256=receipt["evidence_sha256"],
                issued_at_tick=evaluation_tick,
            )
            self._conn.execute(
                "UPDATE completion_effects SET state=?,provider_receipt_sha256=?,provider_response_sha256=?,"
                "evidence_sha256=?,last_event_sha256=?,updated_at_tick=? WHERE effect_id=?",
                (
                    outcome,
                    receipt_sha,
                    receipt["provider_response_sha256"],
                    receipt["evidence_sha256"],
                    event["event_sha256"],
                    evaluation_tick,
                    effect_id,
                ),
            )
            self._append_event(event, signed)
            self._conn.commit()
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "effect": self.get(effect_id),
                "provider_receipt": receipt,
                "signed_witness_event": signed,
            }
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def events_since(self, sequence: int) -> list[dict[str, Any]]:
        if type(sequence) is not int or sequence < 0:
            raise CompletionWitnessError("invalid_sequence", str(sequence))
        rows = self._conn.execute(
            "SELECT signed_event_json FROM completion_events WHERE sequence>? ORDER BY sequence",
            (sequence,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def head(self, *, now_tick: int) -> dict[str, Any]:
        if type(now_tick) is not int or now_tick < 0:
            raise CompletionWitnessError("invalid_now_tick", str(now_tick))
        sequence, head_event = self._meta()
        state_root = self._state_root()
        head = seal_mapping(
            {
                "contract_id": COMPLETION_WITNESS_HEAD_CONTRACT_ID,
                "witness_id": self.witness_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
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
            purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
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
        expected_provider_id: str,
        expected_provider_service_id: str,
        challenge: str,
        verifier_id: str,
        verifier_epoch_sha256: str,
        requested_at: int,
        issued_at: int,
        valid_until: int | None = None,
    ) -> dict[str, Any]:
        if not _is_sha256(effect_id):
            raise CompletionWitnessError("invalid_effect_id", str(effect_id))
        if not _is_sha256(expected_payload_sha256):
            raise CompletionWitnessError("invalid_payload_sha256", str(expected_payload_sha256))
        for name, value in (
            ("expected_provider_id", expected_provider_id),
            ("expected_provider_service_id", expected_provider_service_id),
            ("verifier_id", verifier_id),
        ):
            if not isinstance(value, str) or not value:
                raise CompletionWitnessError(f"invalid_{name}", str(value))
        if not _is_sha256(verifier_epoch_sha256):
            raise CompletionWitnessError("invalid_verifier_epoch", str(verifier_epoch_sha256))
        if type(requested_at) is not int or type(issued_at) is not int or requested_at < 0 or issued_at < requested_at:
            raise CompletionWitnessError("invalid_response_time", f"{requested_at}:{issued_at}")
        if valid_until is None:
            valid_until = issued_at + self.receipt_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise CompletionWitnessError("invalid_response_window", str(valid_until))
        current = self.get(effect_id)
        if current is None:
            state = "ABSENT"
            payload_sha256 = expected_payload_sha256
            provider_id = expected_provider_id
            provider_service_id = expected_provider_service_id
            generation = 0
            provider_request_id = None
            provider_receipt_sha256 = None
            evidence_sha256 = None
            updated_at_tick = None
        else:
            state = current["state"]
            payload_sha256 = current["payload_sha256"]
            provider_id = current["provider_id"]
            provider_service_id = current["provider_service_id"]
            generation = current["generation"]
            provider_request_id = current["provider_request_id"]
            provider_receipt_sha256 = current["provider_receipt_sha256"]
            evidence_sha256 = current["evidence_sha256"]
            updated_at_tick = current["updated_at_tick"]
        sequence, head_event = self._meta()
        status = seal_mapping(
            {
                "contract_id": COMPLETION_WITNESS_STATUS_CONTRACT_ID,
                "witness_id": self.witness_id,
                "authority_id": self.authority_id,
                "service_id": self.service_id,
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "provider_id": provider_id,
                "provider_service_id": provider_service_id,
                "state": state,
                "generation": generation,
                "provider_request_id": provider_request_id,
                "provider_receipt_sha256": provider_receipt_sha256,
                "evidence_sha256": evidence_sha256,
                "updated_at_tick": updated_at_tick,
                "witness_sequence": sequence,
                "witness_head_event_sha256": head_event,
                "witness_state_root_sha256": self._state_root(),
                "verifier_id": verifier_id,
                "verifier_epoch_sha256": verifier_epoch_sha256,
                "challenge_sha256": _challenge_sha256(challenge),
                "requested_at": requested_at,
                "issued_at": issued_at,
                "valid_until": valid_until,
                "status_sha256": "",
            },
            "status_sha256",
        )
        return sign_contract_envelope(
            status,
            digest_field="status_sha256",
            purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


def verify_completion_witness_event(
    signed_event: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_witness_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
    expected_effect_id: str | None = None,
    expected_payload_sha256: str | None = None,
    allowed_to_states: Sequence[str] = ("RESERVED", "UNKNOWN", "COMPLETED", "NO_EFFECT"),
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_event,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
        expected_digest_field="event_sha256",
        expected_inner_contract_id=COMPLETION_WITNESS_EVENT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWitnessError(
            "invalid_completion_witness_signature", str(verified["errors"])
        )
    event = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(event, dict) or not isinstance(envelope, dict):
        raise CompletionWitnessError("invalid_completion_witness_event", "object required")
    if (
        event.get("witness_id") != expected_witness_id
        or event.get("authority_id") != expected_authority_id
        or event.get("service_id") != expected_service_id
    ):
        raise CompletionWitnessError(
            "completion_witness_identity_mismatch", str(event.get("witness_id"))
        )
    if expected_effect_id is not None and event.get("effect_id") != expected_effect_id:
        raise CompletionWitnessError(
            "completion_witness_effect_mismatch", str(event.get("effect_id"))
        )
    if expected_payload_sha256 is not None and event.get("payload_sha256") != expected_payload_sha256:
        raise CompletionWitnessError(
            "completion_witness_payload_mismatch", str(event.get("payload_sha256"))
        )
    if type(event.get("sequence")) is not int or event["sequence"] < 1:
        raise CompletionWitnessError(
            "invalid_completion_witness_sequence", str(event.get("sequence"))
        )
    for field in ("previous_event_sha256", "effect_id", "payload_sha256", "event_sha256"):
        if not _is_sha256(event.get(field)):
            raise CompletionWitnessError(
                "invalid_completion_witness_digest", f"{field}={event.get(field)}"
            )
    for field in ("provider_id", "provider_service_id", "provider_request_id"):
        if not isinstance(event.get(field), str) or not event[field]:
            raise CompletionWitnessError(
                "invalid_completion_witness_field", f"{field}={event.get(field)}"
            )
    if type(event.get("generation")) is not int or event["generation"] < 1:
        raise CompletionWitnessError(
            "invalid_completion_witness_generation", str(event.get("generation"))
        )
    if type(event.get("issued_at_tick")) is not int or event["issued_at_tick"] < 0:
        raise CompletionWitnessError(
            "invalid_completion_witness_event_time", str(event.get("issued_at_tick"))
        )
    if event["issued_at_tick"] != envelope.get("issued_at"):
        raise CompletionWitnessError(
            "completion_witness_event_time_binding_mismatch",
            f"inner={event['issued_at_tick']} envelope={envelope.get('issued_at')}",
        )
    allowed = set(allowed_to_states)
    if not allowed or not allowed.issubset(COMPLETION_WITNESS_STATES - {"ABSENT"}):
        raise CompletionWitnessError(
            "invalid_allowed_witness_state", str(tuple(allowed_to_states))
        )
    from_state = event.get("from_state")
    to_state = event.get("to_state")
    valid_transitions = {
        (None, "RESERVED"),
        ("NO_EFFECT", "RESERVED"),
        ("RESERVED", "UNKNOWN"),
        ("RESERVED", "COMPLETED"),
        ("RESERVED", "NO_EFFECT"),
        ("UNKNOWN", "COMPLETED"),
        ("UNKNOWN", "NO_EFFECT"),
    }
    if to_state not in allowed:
        raise CompletionWitnessError(
            "completion_witness_state_not_allowed", str(to_state)
        )
    if (from_state, to_state) not in valid_transitions:
        raise CompletionWitnessError(
            "invalid_completion_witness_transition", f"{from_state}->{to_state}"
        )
    provider_receipt = event.get("provider_receipt_sha256")
    provider_response = event.get("provider_response_sha256")
    evidence = event.get("evidence_sha256")
    if to_state == "RESERVED":
        if any(value is not None for value in (provider_receipt, provider_response, evidence)):
            raise CompletionWitnessError(
                "unexpected_completion_witness_outcome_evidence", str(event["effect_id"])
            )
    else:
        if not _is_sha256(provider_receipt) or not _is_sha256(evidence):
            raise CompletionWitnessError(
                "invalid_completion_witness_outcome_evidence", str(event["effect_id"])
            )
        if to_state == "COMPLETED" and not _is_sha256(provider_response):
            raise CompletionWitnessError(
                "completion_witness_provider_response_required", str(event["effect_id"])
            )
        if to_state != "COMPLETED" and provider_response is not None and not _is_sha256(provider_response):
            raise CompletionWitnessError(
                "invalid_completion_witness_provider_response", str(provider_response)
            )
    return {
        "status": "PASS",
        "event": event,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_completion_witness_event_chain(
    signed_events: Sequence[Mapping[str, Any]],
    *,
    registry: TrustKeyRegistry,
    expected_witness_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
) -> dict[str, Any]:
    if not isinstance(signed_events, Sequence) or isinstance(signed_events, (str, bytes)):
        raise CompletionWitnessError("invalid_completion_witness_chain", "sequence required")
    previous = ZERO_SHA256
    expected_sequence = 1
    effects: dict[str, dict[str, Any]] = {}
    verified_events: list[dict[str, Any]] = []
    for signed_event in signed_events:
        result = verify_completion_witness_event(
            signed_event,
            registry=registry,
            expected_witness_id=expected_witness_id,
            expected_authority_id=expected_authority_id,
            expected_service_id=expected_service_id,
            expected_signer_id=expected_signer_id,
            expected_trust_domain=expected_trust_domain,
            evaluation_tick=evaluation_tick,
        )
        event = result["event"]
        if event["sequence"] != expected_sequence:
            raise CompletionWitnessError(
                "completion_witness_chain_sequence_gap",
                f"expected={expected_sequence} observed={event['sequence']}",
            )
        if event["previous_event_sha256"] != previous:
            raise CompletionWitnessError(
                "completion_witness_chain_parent_mismatch",
                f"sequence={event['sequence']}",
            )
        current = effects.get(event["effect_id"])
        if current is None:
            if event["from_state"] is not None or event["to_state"] != "RESERVED" or event["generation"] != 1:
                raise CompletionWitnessError(
                    "completion_witness_chain_invalid_genesis", event["effect_id"]
                )
        else:
            for field in ("payload_sha256", "provider_id", "provider_service_id"):
                if event[field] != current[field]:
                    raise CompletionWitnessError(
                        "completion_witness_chain_identity_conflict", f"{event['effect_id']}:{field}"
                    )
            if event["from_state"] != current["state"]:
                raise CompletionWitnessError(
                    "completion_witness_chain_state_discontinuity",
                    f"expected={current['state']} observed={event['from_state']}",
                )
            if event["to_state"] == "RESERVED":
                if current["state"] != "NO_EFFECT" or event["generation"] != current["generation"] + 1:
                    raise CompletionWitnessError(
                        "completion_witness_chain_generation_discontinuity", event["effect_id"]
                    )
            elif event["generation"] != current["generation"]:
                raise CompletionWitnessError(
                    "completion_witness_chain_generation_mismatch", event["effect_id"]
                )
            if event["to_state"] != "RESERVED" and event["provider_request_id"] != current["provider_request_id"]:
                raise CompletionWitnessError(
                    "completion_witness_chain_provider_request_mismatch", event["effect_id"]
                )
        effects[event["effect_id"]] = {
            "payload_sha256": event["payload_sha256"],
            "provider_id": event["provider_id"],
            "provider_service_id": event["provider_service_id"],
            "provider_request_id": event["provider_request_id"],
            "generation": event["generation"],
            "state": event["to_state"],
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


def verify_completion_witness_head(
    signed_head: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_witness_id: str,
    expected_authority_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    evaluation_tick: int,
    expected_sequence: int | None = None,
    expected_head_event_sha256: str | None = None,
    expected_state_root_sha256: str | None = None,
    max_head_age: int = 30,
) -> dict[str, Any]:
    if type(max_head_age) is not int or max_head_age < 0:
        raise CompletionWitnessError("invalid_max_head_age", str(max_head_age))
    verified = verify_contract_envelope(
        signed_head,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
        expected_digest_field="head_sha256",
        expected_inner_contract_id=COMPLETION_WITNESS_HEAD_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWitnessError(
            "invalid_completion_witness_head_signature", str(verified["errors"])
        )
    head = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(head, dict) or not isinstance(envelope, dict):
        raise CompletionWitnessError("invalid_completion_witness_head", "object required")
    if (
        head.get("witness_id") != expected_witness_id
        or head.get("authority_id") != expected_authority_id
        or head.get("service_id") != expected_service_id
    ):
        raise CompletionWitnessError(
            "completion_witness_identity_mismatch", str(head.get("witness_id"))
        )
    if type(head.get("sequence")) is not int or head["sequence"] < 0:
        raise CompletionWitnessError(
            "invalid_completion_witness_sequence", str(head.get("sequence"))
        )
    for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
        if not _is_sha256(head.get(field)):
            raise CompletionWitnessError(
                "invalid_completion_witness_head_digest", f"{field}={head.get(field)}"
            )
    issued_at = head.get("issued_at_tick")
    if type(issued_at) is not int or issued_at < 0 or issued_at != envelope.get("issued_at"):
        raise CompletionWitnessError(
            "completion_witness_head_time_binding_mismatch", str(issued_at)
        )
    if issued_at > evaluation_tick or evaluation_tick - issued_at > max_head_age:
        raise CompletionWitnessError("completion_witness_head_not_fresh", str(issued_at))
    for field, observed, expected in (
        ("sequence", head["sequence"], expected_sequence),
        ("head_event_sha256", head["head_event_sha256"], expected_head_event_sha256),
        ("state_root_sha256", head["state_root_sha256"], expected_state_root_sha256),
    ):
        if expected is not None and observed != expected:
            raise CompletionWitnessError(
                f"completion_witness_{field}_mismatch", f"expected={expected} observed={observed}"
            )
    return {
        "status": "PASS",
        "head": head,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_external_completion_witness_status(
    signed_status: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_witness_id: str,
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
    if not allowed or not allowed.issubset(COMPLETION_WITNESS_STATES):
        raise CompletionWitnessError("invalid_allowed_witness_state", str(tuple(allowed_states)))
    if type(max_response_age) is not int or max_response_age < 0:
        raise CompletionWitnessError("invalid_max_response_age", str(max_response_age))
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    verified = verify_contract_envelope(
        signed_status,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
        expected_digest_field="status_sha256",
        expected_inner_contract_id=COMPLETION_WITNESS_STATUS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWitnessError(
            "invalid_completion_witness_status_signature", str(verified["errors"])
        )
    status = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(status, dict) or not isinstance(envelope, dict):
        raise CompletionWitnessError("invalid_completion_witness_status", "object required")
    if (
        status.get("witness_id") != expected_witness_id
        or status.get("authority_id") != expected_authority_id
        or status.get("service_id") != expected_service_id
    ):
        raise CompletionWitnessError(
            "completion_witness_identity_mismatch", str(status.get("witness_id"))
        )
    for field, expected in (
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
    ):
        if status.get(field) != expected:
            raise CompletionWitnessError(
                f"completion_witness_{field}_mismatch", str(status.get(field))
            )
    if status.get("state") not in allowed:
        raise CompletionWitnessError(
            "completion_witness_state_blocks_retry", str(status.get("state"))
        )
    if (
        status.get("verifier_id") != challenge_ledger.session.verifier_id
        or status.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
    ):
        raise CompletionWitnessError(
            "completion_witness_verifier_binding_mismatch", str(status.get("verifier_id"))
        )
    if (
        status.get("challenge_sha256") != challenge["challenge_sha256"]
        or status.get("requested_at") != challenge["issued_at"]
    ):
        raise CompletionWitnessError(
            "completion_witness_challenge_binding_mismatch", str(status.get("challenge_sha256"))
        )
    issued_at = status.get("issued_at")
    if (
        type(issued_at) is not int
        or issued_at != envelope.get("issued_at")
        or issued_at > evaluation_tick
        or evaluation_tick - issued_at > max_response_age
    ):
        raise CompletionWitnessError("completion_witness_status_not_fresh", str(issued_at))
    if status.get("valid_until") != envelope.get("valid_until"):
        raise CompletionWitnessError(
            "completion_witness_status_window_binding_mismatch", str(status.get("valid_until"))
        )
    if type(status.get("witness_sequence")) is not int or status["witness_sequence"] < 0:
        raise CompletionWitnessError(
            "invalid_completion_witness_sequence", str(status.get("witness_sequence"))
        )
    for field in ("witness_head_event_sha256", "witness_state_root_sha256"):
        if not _is_sha256(status.get(field)):
            raise CompletionWitnessError(
                "invalid_completion_witness_head", f"{field}={status.get(field)}"
            )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "completion_witness_status": status,
        "external_effect_permitted": status["state"] in {"ABSENT", "NO_EFFECT"},
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "COMPLETION_WITNESS_BLOCKING_STATES",
    "COMPLETION_WITNESS_EVENT_CONTRACT_ID",
    "COMPLETION_WITNESS_HEAD_CONTRACT_ID",
    "COMPLETION_WITNESS_STATES",
    "COMPLETION_WITNESS_STATUS_CONTRACT_ID",
    "CompletionWitnessError",
    "SQLiteExternalCompletionWitness",
    "verify_completion_witness_event",
    "verify_completion_witness_event_chain",
    "verify_completion_witness_head",
    "verify_external_completion_witness_status",
]
