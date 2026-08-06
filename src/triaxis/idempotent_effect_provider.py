"""TRIAXIS v3.28 reference provider-side effect idempotency and reconciliation.

The external execution ledger is not the provider.  A provider that accepts the
stable TRIAXIS ``effect_id`` as its idempotency key can independently prevent a
second effect even if local governance state is stale.  This module models the
minimum provider contract: payload-bound idempotency, explicit UNKNOWN state,
authoritative NO_EFFECT/COMPLETED reconciliation, and fresh signed status
responses.

This is a reference provider, not an adapter for any real vendor and not action
authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

PROVIDER_EFFECT_STATUS_CONTRACT_ID = "TRIAXIS_PROVIDER_EFFECT_STATUS_v1"
PROVIDER_OUTCOME_RECEIPT_CONTRACT_ID = "TRIAXIS_PROVIDER_OUTCOME_RECEIPT_v1"
PROVIDER_EFFECT_STATES = frozenset({"ABSENT", "IN_FLIGHT", "UNKNOWN", "COMPLETED", "NO_EFFECT"})
PROVIDER_BLOCKING_STATES = frozenset({"IN_FLIGHT", "UNKNOWN", "COMPLETED"})


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise ProviderEffectError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


class ProviderEffectError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class SQLiteIdempotentEffectProvider:
    """Reference provider persistence keyed by stable ``effect_id``."""

    def __init__(
        self,
        path: str | Path,
        *,
        provider_id: str,
        service_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
        response_ttl: int = 15,
    ) -> None:
        for name, value in (
            ("provider_id", provider_id),
            ("service_id", service_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise ProviderEffectError("invalid_configuration", name)
        if type(response_ttl) is not int or response_ttl < 1:
            raise ProviderEffectError("invalid_configuration", "response_ttl")
        self.path = str(path)
        self.provider_id = provider_id
        self.service_id = service_id
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
            CREATE TABLE IF NOT EXISTS provider_effects (
              effect_id TEXT PRIMARY KEY,
              payload_sha256 TEXT NOT NULL,
              state TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT UNIQUE NOT NULL,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT,
              created_at_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_effect_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              effect_id TEXT NOT NULL,
              generation INTEGER NOT NULL,
              provider_request_id TEXT NOT NULL,
              from_state TEXT,
              to_state TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              provider_response_sha256 TEXT,
              evidence_sha256 TEXT,
              created_at_tick INTEGER NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteIdempotentEffectProvider":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    @staticmethod
    def _validate_identity(effect_id: str, payload_sha256: str, provider_request_id: str, now_tick: int) -> None:
        if not _is_sha256(effect_id):
            raise ProviderEffectError("invalid_effect_id", str(effect_id))
        if not _is_sha256(payload_sha256):
            raise ProviderEffectError("invalid_payload_sha256", str(payload_sha256))
        if not isinstance(provider_request_id, str) or not provider_request_id:
            raise ProviderEffectError("invalid_provider_request_id", str(provider_request_id))
        if type(now_tick) is not int or now_tick < 0:
            raise ProviderEffectError("invalid_now_tick", str(now_tick))

    def get(self, effect_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload_sha256,state,generation,provider_request_id,provider_response_sha256,"
            "evidence_sha256,created_at_tick,updated_at_tick FROM provider_effects WHERE effect_id=?",
            (effect_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "effect_id": effect_id,
            "payload_sha256": row[0],
            "state": row[1],
            "generation": row[2],
            "provider_request_id": row[3],
            "provider_response_sha256": row[4],
            "evidence_sha256": row[5],
            "created_at_tick": row[6],
            "updated_at_tick": row[7],
        }

    def effect_count(self) -> int:
        """Return the number of durable provider-side idempotency records."""
        row = self._conn.execute("SELECT COUNT(*) FROM provider_effects").fetchone()
        return int(row[0])

    def _insert_event(
        self,
        *,
        effect_id: str,
        generation: int,
        provider_request_id: str,
        from_state: str | None,
        to_state: str,
        payload_sha256: str,
        provider_response_sha256: str | None,
        evidence_sha256: str | None,
        now_tick: int,
    ) -> None:
        self._conn.execute(
            "INSERT INTO provider_effect_events(effect_id,generation,provider_request_id,from_state,to_state,"
            "payload_sha256,provider_response_sha256,evidence_sha256,created_at_tick) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                effect_id,
                generation,
                provider_request_id,
                from_state,
                to_state,
                payload_sha256,
                provider_response_sha256,
                evidence_sha256,
                now_tick,
            ),
        )

    def begin(
        self,
        *,
        effect_id: str,
        payload_sha256: str,
        provider_request_id: str,
        now_tick: int,
    ) -> dict[str, Any]:
        self._validate_identity(effect_id, payload_sha256, provider_request_id, now_tick)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._conn.execute(
                "SELECT payload_sha256,state,generation,provider_request_id FROM provider_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload_sha256:
                    raise ProviderEffectError("provider_idempotency_payload_conflict", effect_id)
                if existing[1] != "NO_EFFECT":
                    self._conn.commit()
                    return {
                        "status": "PASS",
                        "idempotent_replay": True,
                        "effect": self.get(effect_id),
                        "external_effect_permitted": False,
                    }
                generation = int(existing[2]) + 1
                self._conn.execute(
                    "UPDATE provider_effects SET state='IN_FLIGHT',generation=?,provider_request_id=?,"
                    "provider_response_sha256=NULL,evidence_sha256=NULL,updated_at_tick=? WHERE effect_id=? AND state='NO_EFFECT'",
                    (generation, provider_request_id, now_tick, effect_id),
                )
                self._insert_event(
                    effect_id=effect_id,
                    generation=generation,
                    provider_request_id=provider_request_id,
                    from_state="NO_EFFECT",
                    to_state="IN_FLIGHT",
                    payload_sha256=payload_sha256,
                    provider_response_sha256=None,
                    evidence_sha256=None,
                    now_tick=now_tick,
                )
            else:
                generation = 1
                self._conn.execute(
                    "INSERT INTO provider_effects(effect_id,payload_sha256,state,generation,provider_request_id,"
                    "created_at_tick,updated_at_tick) VALUES(?,?,?,?,?,?,?)",
                    (effect_id, payload_sha256, "IN_FLIGHT", generation, provider_request_id, now_tick, now_tick),
                )
                self._insert_event(
                    effect_id=effect_id,
                    generation=generation,
                    provider_request_id=provider_request_id,
                    from_state=None,
                    to_state="IN_FLIGHT",
                    payload_sha256=payload_sha256,
                    provider_response_sha256=None,
                    evidence_sha256=None,
                    now_tick=now_tick,
                )
            self._conn.commit()
            return {
                "status": "PASS",
                "idempotent_replay": False,
                "effect": self.get(effect_id),
                "external_effect_permitted": True,
            }
        except sqlite3.IntegrityError as exc:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise ProviderEffectError("provider_uniqueness_conflict", str(exc)) from exc
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def record_outcome(
        self,
        *,
        effect_id: str,
        provider_request_id: str,
        outcome: str,
        provider_response_sha256: str | None,
        evidence_sha256: str,
        now_tick: int,
    ) -> dict[str, Any]:
        if outcome not in {"COMPLETED", "UNKNOWN", "NO_EFFECT"}:
            raise ProviderEffectError("invalid_provider_outcome", outcome)
        if outcome == "COMPLETED" and not _is_sha256(provider_response_sha256):
            raise ProviderEffectError("provider_response_required", str(provider_response_sha256))
        if outcome != "COMPLETED" and provider_response_sha256 is not None and not _is_sha256(provider_response_sha256):
            raise ProviderEffectError("invalid_provider_response_sha256", str(provider_response_sha256))
        if not _is_sha256(evidence_sha256):
            raise ProviderEffectError("invalid_evidence_sha256", str(evidence_sha256))
        if type(now_tick) is not int or now_tick < 0:
            raise ProviderEffectError("invalid_now_tick", str(now_tick))
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT payload_sha256,state,generation,provider_request_id,provider_response_sha256,evidence_sha256 "
                "FROM provider_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise ProviderEffectError("unknown_provider_effect", effect_id)
            if row[3] != provider_request_id:
                raise ProviderEffectError("provider_request_mismatch", provider_request_id)
            if row[1] == outcome:
                if row[4] not in (None, provider_response_sha256) or row[5] not in (None, evidence_sha256):
                    raise ProviderEffectError("provider_outcome_replay_conflict", effect_id)
                self._conn.commit()
                return {"status": "PASS", "idempotent_replay": True, "effect": self.get(effect_id)}
            if row[1] != "IN_FLIGHT":
                raise ProviderEffectError("provider_state_mismatch", f"expected=IN_FLIGHT observed={row[1]}")
            self._conn.execute(
                "UPDATE provider_effects SET state=?,provider_response_sha256=?,evidence_sha256=?,updated_at_tick=? "
                "WHERE effect_id=? AND state='IN_FLIGHT'",
                (outcome, provider_response_sha256, evidence_sha256, now_tick, effect_id),
            )
            self._insert_event(
                effect_id=effect_id,
                generation=int(row[2]),
                provider_request_id=provider_request_id,
                from_state="IN_FLIGHT",
                to_state=outcome,
                payload_sha256=row[0],
                provider_response_sha256=provider_response_sha256,
                evidence_sha256=evidence_sha256,
                now_tick=now_tick,
            )
            self._conn.commit()
            return {"status": "PASS", "idempotent_replay": False, "effect": self.get(effect_id)}
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def reconcile_unknown(
        self,
        *,
        effect_id: str,
        provider_request_id: str,
        outcome: str,
        provider_response_sha256: str | None,
        evidence_sha256: str,
        now_tick: int,
    ) -> dict[str, Any]:
        if outcome not in {"COMPLETED", "NO_EFFECT"}:
            raise ProviderEffectError("invalid_reconciliation_outcome", outcome)
        if outcome == "COMPLETED" and not _is_sha256(provider_response_sha256):
            raise ProviderEffectError("provider_response_required", str(provider_response_sha256))
        if outcome == "NO_EFFECT" and provider_response_sha256 is not None and not _is_sha256(provider_response_sha256):
            raise ProviderEffectError("invalid_provider_response_sha256", str(provider_response_sha256))
        if not _is_sha256(evidence_sha256):
            raise ProviderEffectError("invalid_evidence_sha256", str(evidence_sha256))
        if type(now_tick) is not int or now_tick < 0:
            raise ProviderEffectError("invalid_now_tick", str(now_tick))
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute(
                "SELECT payload_sha256,state,generation,provider_request_id,provider_response_sha256,evidence_sha256 "
                "FROM provider_effects WHERE effect_id=?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise ProviderEffectError("unknown_provider_effect", effect_id)
            if row[3] != provider_request_id:
                raise ProviderEffectError("provider_request_mismatch", provider_request_id)
            if row[1] == outcome:
                if row[4] not in (None, provider_response_sha256) or row[5] not in (None, evidence_sha256):
                    raise ProviderEffectError("provider_reconciliation_replay_conflict", effect_id)
                self._conn.commit()
                return {"status": "PASS", "idempotent_replay": True, "effect": self.get(effect_id)}
            if row[1] != "UNKNOWN":
                raise ProviderEffectError("provider_state_mismatch", f"expected=UNKNOWN observed={row[1]}")
            self._conn.execute(
                "UPDATE provider_effects SET state=?,provider_response_sha256=?,evidence_sha256=?,updated_at_tick=? "
                "WHERE effect_id=? AND state='UNKNOWN'",
                (outcome, provider_response_sha256, evidence_sha256, now_tick, effect_id),
            )
            self._insert_event(
                effect_id=effect_id,
                generation=int(row[2]),
                provider_request_id=provider_request_id,
                from_state="UNKNOWN",
                to_state=outcome,
                payload_sha256=row[0],
                provider_response_sha256=provider_response_sha256,
                evidence_sha256=evidence_sha256,
                now_tick=now_tick,
            )
            self._conn.commit()
            return {"status": "PASS", "idempotent_replay": False, "effect": self.get(effect_id)}
        except Exception:
            if self._conn.in_transaction:
                self._conn.rollback()
            raise

    def events(self, effect_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT generation,provider_request_id,from_state,to_state,payload_sha256,"
            "provider_response_sha256,evidence_sha256,created_at_tick FROM provider_effect_events "
            "WHERE effect_id=? ORDER BY event_id",
            (effect_id,),
        ).fetchall()
        return [
            {
                "generation": row[0],
                "provider_request_id": row[1],
                "from_state": row[2],
                "to_state": row[3],
                "payload_sha256": row[4],
                "provider_response_sha256": row[5],
                "evidence_sha256": row[6],
                "created_at_tick": row[7],
            }
            for row in rows
        ]

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
            raise ProviderEffectError("invalid_effect_id", str(effect_id))
        if not _is_sha256(expected_payload_sha256):
            raise ProviderEffectError("invalid_payload_sha256", str(expected_payload_sha256))
        if not isinstance(verifier_id, str) or not verifier_id:
            raise ProviderEffectError("invalid_verifier_id", str(verifier_id))
        if not _is_sha256(verifier_epoch_sha256):
            raise ProviderEffectError("invalid_verifier_epoch", str(verifier_epoch_sha256))
        if type(requested_at) is not int or type(issued_at) is not int or requested_at < 0 or issued_at < requested_at:
            raise ProviderEffectError("invalid_response_time", f"{requested_at}:{issued_at}")
        if valid_until is None:
            valid_until = issued_at + self.response_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise ProviderEffectError("invalid_response_window", str(valid_until))
        current = self.get(effect_id)
        if current is None:
            state = "ABSENT"
            payload_sha256 = expected_payload_sha256
            generation = 0
            provider_request_id = None
            provider_response_sha256 = None
            evidence_sha256 = None
            updated_at_tick = None
        else:
            state = current["state"]
            payload_sha256 = current["payload_sha256"]
            generation = current["generation"]
            provider_request_id = current["provider_request_id"]
            provider_response_sha256 = current["provider_response_sha256"]
            evidence_sha256 = current["evidence_sha256"]
            updated_at_tick = current["updated_at_tick"]
        status = seal_mapping(
            {
                "contract_id": PROVIDER_EFFECT_STATUS_CONTRACT_ID,
                "provider_id": self.provider_id,
                "service_id": self.service_id,
                "effect_id": effect_id,
                "payload_sha256": payload_sha256,
                "state": state,
                "generation": generation,
                "provider_request_id": provider_request_id,
                "provider_response_sha256": provider_response_sha256,
                "evidence_sha256": evidence_sha256,
                "updated_at_tick": updated_at_tick,
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
            purpose=PURPOSE_PROVIDER_EFFECT_RECEIPT,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


    def issue_outcome_receipt(
        self,
        *,
        effect_id: str,
        issued_at: int,
        valid_until: int | None = None,
    ) -> dict[str, Any]:
        """Issue immutable signed evidence for a terminal or uncertain outcome.

        The receipt is not challenge-bound because it is intended for durable
        ingestion by an external completion witness.  It is still purpose-bound,
        time-bounded, payload-bound and provider-request-bound.  It never grants
        action authority.
        """
        if not _is_sha256(effect_id):
            raise ProviderEffectError("invalid_effect_id", str(effect_id))
        if type(issued_at) is not int or issued_at < 0:
            raise ProviderEffectError("invalid_issued_at", str(issued_at))
        current = self.get(effect_id)
        if current is None:
            raise ProviderEffectError("unknown_provider_effect", effect_id)
        if current["state"] not in {"COMPLETED", "UNKNOWN", "NO_EFFECT"}:
            raise ProviderEffectError("provider_outcome_not_receiptable", current["state"])
        if issued_at < current["updated_at_tick"]:
            raise ProviderEffectError(
                "provider_receipt_predates_outcome",
                f"issued={issued_at} updated={current['updated_at_tick']}",
            )
        if valid_until is None:
            valid_until = issued_at + self.response_ttl
        if type(valid_until) is not int or valid_until <= issued_at:
            raise ProviderEffectError("invalid_response_window", str(valid_until))
        receipt = seal_mapping(
            {
                "contract_id": PROVIDER_OUTCOME_RECEIPT_CONTRACT_ID,
                "provider_id": self.provider_id,
                "service_id": self.service_id,
                "effect_id": effect_id,
                "payload_sha256": current["payload_sha256"],
                "state": current["state"],
                "generation": current["generation"],
                "provider_request_id": current["provider_request_id"],
                "provider_response_sha256": current["provider_response_sha256"],
                "evidence_sha256": current["evidence_sha256"],
                "outcome_at_tick": current["updated_at_tick"],
                "issued_at": issued_at,
                "valid_until": valid_until,
                "receipt_sha256": "",
            },
            "receipt_sha256",
        )
        return sign_contract_envelope(
            receipt,
            digest_field="receipt_sha256",
            purpose=PURPOSE_PROVIDER_EFFECT_RECEIPT,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )


def verify_provider_outcome_receipt(
    signed_receipt: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_provider_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("COMPLETED", "UNKNOWN", "NO_EFFECT"),
    max_receipt_age: int = 30,
) -> dict[str, Any]:
    allowed = set(allowed_states)
    if not allowed or not allowed.issubset({"COMPLETED", "UNKNOWN", "NO_EFFECT"}):
        raise ProviderEffectError("invalid_allowed_provider_outcome", str(tuple(allowed_states)))
    if type(evaluation_tick) is not int or evaluation_tick < 0:
        raise ProviderEffectError("invalid_evaluation_tick", str(evaluation_tick))
    if type(max_receipt_age) is not int or max_receipt_age < 0:
        raise ProviderEffectError("invalid_max_receipt_age", str(max_receipt_age))
    verified = verify_contract_envelope(
        signed_receipt,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_PROVIDER_EFFECT_RECEIPT,
        expected_digest_field="receipt_sha256",
        expected_inner_contract_id=PROVIDER_OUTCOME_RECEIPT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise ProviderEffectError("invalid_provider_outcome_signature", str(verified["errors"]))
    receipt = verified["inner_contract"]
    if not isinstance(receipt, dict):
        raise ProviderEffectError("invalid_provider_outcome_receipt", "object required")
    if receipt.get("provider_id") != expected_provider_id or receipt.get("service_id") != expected_service_id:
        raise ProviderEffectError(
            "provider_identity_mismatch",
            f"{receipt.get('provider_id')}:{receipt.get('service_id')}",
        )
    if receipt.get("effect_id") != expected_effect_id:
        raise ProviderEffectError("provider_effect_id_mismatch", str(receipt.get("effect_id")))
    if receipt.get("payload_sha256") != expected_payload_sha256:
        raise ProviderEffectError("provider_payload_mismatch", str(receipt.get("payload_sha256")))
    if receipt.get("state") not in allowed:
        raise ProviderEffectError("provider_outcome_not_allowed", str(receipt.get("state")))
    if type(receipt.get("generation")) is not int or receipt["generation"] < 1:
        raise ProviderEffectError("invalid_provider_generation", str(receipt.get("generation")))
    if not isinstance(receipt.get("provider_request_id"), str) or not receipt["provider_request_id"]:
        raise ProviderEffectError("invalid_provider_request_id", str(receipt.get("provider_request_id")))
    if receipt["state"] == "COMPLETED" and not _is_sha256(receipt.get("provider_response_sha256")):
        raise ProviderEffectError("provider_response_required", str(receipt.get("provider_response_sha256")))
    if receipt["state"] != "COMPLETED" and receipt.get("provider_response_sha256") is not None and not _is_sha256(receipt.get("provider_response_sha256")):
        raise ProviderEffectError("invalid_provider_response_sha256", str(receipt.get("provider_response_sha256")))
    if not _is_sha256(receipt.get("evidence_sha256")):
        raise ProviderEffectError("invalid_evidence_sha256", str(receipt.get("evidence_sha256")))
    outcome_at = receipt.get("outcome_at_tick")
    issued_at = receipt.get("issued_at")
    valid_until = receipt.get("valid_until")
    if type(outcome_at) is not int or outcome_at < 0:
        raise ProviderEffectError("invalid_outcome_at_tick", str(outcome_at))
    if type(issued_at) is not int or issued_at < outcome_at or issued_at > evaluation_tick:
        raise ProviderEffectError("invalid_provider_receipt_time", str(issued_at))
    if type(valid_until) is not int or valid_until <= issued_at:
        raise ProviderEffectError("invalid_provider_receipt_window", str(valid_until))
    if evaluation_tick - issued_at > max_receipt_age:
        raise ProviderEffectError("provider_outcome_receipt_not_fresh", str(issued_at))
    return {
        "status": "PASS",
        "provider_receipt": receipt,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_provider_effect_status(
    signed_status: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_provider_id: str,
    expected_service_id: str,
    expected_signer_id: str,
    expected_trust_domain: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
    max_response_age: int = 5,
) -> dict[str, Any]:
    if any(state not in PROVIDER_EFFECT_STATES for state in allowed_states):
        raise ProviderEffectError("invalid_allowed_provider_state", str(tuple(allowed_states)))
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    verified = verify_contract_envelope(
        signed_status,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_PROVIDER_EFFECT_RECEIPT,
        expected_digest_field="status_sha256",
        expected_inner_contract_id=PROVIDER_EFFECT_STATUS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise ProviderEffectError("invalid_provider_status_signature", str(verified["errors"]))
    status = verified["inner_contract"]
    if not isinstance(status, dict):
        raise ProviderEffectError("invalid_provider_status", "object required")
    if status.get("provider_id") != expected_provider_id or status.get("service_id") != expected_service_id:
        raise ProviderEffectError("provider_identity_mismatch", f"{status.get('provider_id')}:{status.get('service_id')}")
    if status.get("effect_id") != expected_effect_id:
        raise ProviderEffectError("provider_effect_id_mismatch", str(status.get("effect_id")))
    if status.get("payload_sha256") != expected_payload_sha256:
        raise ProviderEffectError("provider_payload_mismatch", str(status.get("payload_sha256")))
    if status.get("state") not in set(allowed_states):
        raise ProviderEffectError("provider_effect_state_blocks_retry", str(status.get("state")))
    if (
        status.get("verifier_id") != challenge_ledger.session.verifier_id
        or status.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
    ):
        raise ProviderEffectError("provider_verifier_binding_mismatch", str(status.get("verifier_id")))
    if (
        status.get("challenge_sha256") != challenge["challenge_sha256"]
        or status.get("requested_at") != challenge["issued_at"]
    ):
        raise ProviderEffectError("provider_challenge_binding_mismatch", str(status.get("challenge_sha256")))
    issued_at = status.get("issued_at")
    if type(issued_at) is not int or issued_at > evaluation_tick or evaluation_tick - issued_at > max_response_age:
        raise ProviderEffectError("provider_status_not_fresh", str(issued_at))
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "provider_status": status,
        "external_effect_permitted": status["state"] in {"ABSENT", "NO_EFFECT"},
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "PROVIDER_BLOCKING_STATES",
    "PROVIDER_EFFECT_STATES",
    "PROVIDER_EFFECT_STATUS_CONTRACT_ID",
    "PROVIDER_OUTCOME_RECEIPT_CONTRACT_ID",
    "ProviderEffectError",
    "SQLiteIdempotentEffectProvider",
    "verify_provider_effect_status",
    "verify_provider_outcome_receipt",
]
