"""TRIAXIS v3.26 durable dispatch and provider provenance contracts.

Clean-room adaptation of durable queue/session patterns observed in current
agent harnesses. TRIAXIS adds side-effect-aware UNKNOWN handling: a dispatch
that may have reached an external system is never silently placed back in the
queue until an exact no-effect reconciliation exists.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import sqlite3
from typing import Any

from .integrity import canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

QUEUED_INPUT_CONTRACT_ID = "TRIAXIS_QUEUED_INPUT_v1"
DISPATCH_CLAIM_CONTRACT_ID = "TRIAXIS_DISPATCH_CLAIM_v1"
DISPATCH_TRANSITION_CONTRACT_ID = "TRIAXIS_DISPATCH_TRANSITION_v1"
PROVIDER_REQUEST_RECEIPT_CONTRACT_ID = "TRIAXIS_PROVIDER_REQUEST_RECEIPT_v1"

RISK_CLASSES = {"READ_ONLY", "MUTATING"}
QUEUE_STATES = {"QUEUED", "CLAIMED", "DISPATCHING", "UNKNOWN", "DELIVERED", "CANCELLED"}


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def seal_queued_input(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("queued input must be object")
    for field in ("queue_id", "thread_id", "content_ref", "content_sha256"):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    if not _is_sha(body["content_sha256"]):
        raise ValueError("content_sha256 required")
    if body.get("risk_class") not in RISK_CLASSES:
        raise ValueError("risk_class invalid")
    created = body.get("created_at_tick")
    if type(created) is not int or created < 0:
        raise ValueError("created_at_tick required")
    attachments = body.get("attachments", [])
    if not isinstance(attachments, list):
        raise ValueError("attachments must be array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(attachments):
        item = materialize_json(raw)
        if not isinstance(item, dict):
            raise ValueError(f"attachment {index} invalid")
        for field in ("artifact_id", "storage_ref", "media_type", "content_sha256"):
            if not isinstance(item.get(field), str) or not item.get(field):
                raise ValueError(f"attachment {index}.{field} required")
        if item["artifact_id"] in seen:
            raise ValueError("duplicate attachment artifact_id")
        seen.add(item["artifact_id"])
        if not _is_sha(item["content_sha256"]):
            raise ValueError("attachment digest invalid")
        if type(item.get("size_bytes")) is not int or item["size_bytes"] < 0:
            raise ValueError("attachment size invalid")
        normalized.append({
            "artifact_id": item["artifact_id"],
            "storage_ref": item["storage_ref"],
            "media_type": item["media_type"],
            "content_sha256": item["content_sha256"],
            "size_bytes": item["size_bytes"],
        })
    body["attachments"] = sorted(normalized, key=lambda row: row["artifact_id"])
    metadata = body.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be object")
    body["metadata"] = metadata
    body.setdefault("contract_id", QUEUED_INPUT_CONTRACT_ID)
    body.setdefault("queued_input_sha256", "")
    return seal_mapping(body, "queued_input_sha256")


def seal_provider_request_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    body = materialize_json(value)
    if not isinstance(body, dict):
        raise TypeError("provider receipt must be object")
    for field in (
        "provider_id", "model_id", "provider_request_id", "run_id", "trace_id",
        "internal_request_sha256", "provider_request_sha256", "provider_response_sha256",
    ):
        if not isinstance(body.get(field), str) or not body.get(field):
            raise ValueError(f"{field} required")
    for field in ("internal_request_sha256", "provider_request_sha256", "provider_response_sha256"):
        if not _is_sha(body[field]):
            raise ValueError(f"{field} invalid")
    started = body.get("started_at_tick")
    ended = body.get("ended_at_tick")
    if type(started) is not int or type(ended) is not int or started < 0 or ended < started:
        raise ValueError("provider timing invalid")
    if body.get("status") not in {"PASS", "ERROR", "CANCELLED"}:
        raise ValueError("provider status invalid")
    body.setdefault("contract_id", PROVIDER_REQUEST_RECEIPT_CONTRACT_ID)
    body.setdefault("provider_receipt_sha256", "")
    return seal_mapping(body, "provider_receipt_sha256")


class DispatchQueueError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SQLiteDurableDispatchQueue:
    """Atomic FIFO queue with leases, idempotency and UNKNOWN reconciliation."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS dispatch_queue (
              queue_id TEXT PRIMARY KEY,
              thread_id TEXT NOT NULL,
              rank INTEGER NOT NULL,
              state TEXT NOT NULL,
              version INTEGER NOT NULL,
              queued_input_sha256 TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              claim_id TEXT,
              dispatch_id TEXT,
              lease_until_tick INTEGER,
              created_at_tick INTEGER NOT NULL,
              updated_at_tick INTEGER NOT NULL,
              delivered_receipt_sha256 TEXT,
              reconciliation_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_dispatch_fifo ON dispatch_queue(thread_id, state, rank, created_at_tick, queue_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_claim ON dispatch_queue(claim_id) WHERE claim_id IS NOT NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_id ON dispatch_queue(dispatch_id) WHERE dispatch_id IS NOT NULL;
            CREATE TABLE IF NOT EXISTS dispatch_events (
              event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
              queue_id TEXT NOT NULL,
              from_state TEXT,
              to_state TEXT NOT NULL,
              version INTEGER NOT NULL,
              event_sha256 TEXT NOT NULL,
              event_json TEXT NOT NULL,
              created_at_tick INTEGER NOT NULL,
              FOREIGN KEY(queue_id) REFERENCES dispatch_queue(queue_id)
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _event(self, *, queue_id: str, from_state: str | None, to_state: str, version: int, tick: int, details: Mapping[str, Any]) -> dict[str, Any]:
        body = {
            "contract_id": DISPATCH_TRANSITION_CONTRACT_ID,
            "queue_id": queue_id,
            "from_state": from_state,
            "to_state": to_state,
            "version": version,
            "created_at_tick": tick,
            "details": materialize_json(details),
            "transition_sha256": "",
        }
        return seal_mapping(body, "transition_sha256")

    def _insert_event(self, event: Mapping[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO dispatch_events(queue_id,from_state,to_state,version,event_sha256,event_json,created_at_tick) VALUES(?,?,?,?,?,?,?)",
            (event["queue_id"], event["from_state"], event["to_state"], event["version"], event["transition_sha256"], json.dumps(event, sort_keys=True), event["created_at_tick"]),
        )

    def enqueue(self, queued_input: Mapping[str, Any], *, rank: int = 0) -> dict[str, Any]:
        obj = materialize_json(queued_input)
        if not isinstance(obj, dict) or not verify_sealed_mapping(obj, "queued_input_sha256"):
            raise DispatchQueueError("invalid_queued_input", "sealed queued input required")
        if type(rank) is not int:
            raise TypeError("rank must be integer")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO dispatch_queue(queue_id,thread_id,rank,state,version,queued_input_sha256,payload_json,created_at_tick,updated_at_tick) VALUES(?,?,?,?,?,?,?,?,?)",
                (obj["queue_id"], obj["thread_id"], rank, "QUEUED", 1, obj["queued_input_sha256"], json.dumps(obj, sort_keys=True), obj["created_at_tick"], obj["created_at_tick"]),
            )
            event = self._event(queue_id=obj["queue_id"], from_state=None, to_state="QUEUED", version=1, tick=obj["created_at_tick"], details={"queued_input_sha256": obj["queued_input_sha256"]})
            self._insert_event(event)
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise DispatchQueueError("queue_id_conflict", obj["queue_id"]) from exc
        return self.get(obj["queue_id"])

    def get(self, queue_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT payload_json,state,version,rank,claim_id,dispatch_id,lease_until_tick,delivered_receipt_sha256,reconciliation_sha256 FROM dispatch_queue WHERE queue_id=?",
            (queue_id,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row[0])
        return {
            **payload,
            "state": row[1], "version": row[2], "rank": row[3], "claim_id": row[4],
            "dispatch_id": row[5], "lease_until_tick": row[6],
            "delivered_receipt_sha256": row[7], "reconciliation_sha256": row[8],
        }

    def list_thread(self, thread_id: str, *, states: Sequence[str] | None = None) -> list[dict[str, Any]]:
        allowed = sorted(set(states or QUEUE_STATES))
        if not set(allowed).issubset(QUEUE_STATES):
            raise ValueError("unknown queue state")
        marks = ",".join("?" for _ in allowed)
        rows = self._conn.execute(
            f"SELECT queue_id FROM dispatch_queue WHERE thread_id=? AND state IN ({marks}) ORDER BY rank,created_at_tick,queue_id",
            (thread_id, *allowed),
        ).fetchall()
        return [self.get(row[0]) for row in rows]

    def reorder(self, queue_id: str, *, new_rank: int, expected_version: int, tick: int) -> dict[str, Any]:
        if type(new_rank) is not int:
            raise TypeError("new_rank integer required")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT state,version FROM dispatch_queue WHERE queue_id=?", (queue_id,)).fetchone()
            if row is None:
                raise DispatchQueueError("unknown_queue_id", queue_id)
            if row[0] != "QUEUED":
                raise DispatchQueueError("queue_item_not_editable", row[0])
            if row[1] != expected_version:
                raise DispatchQueueError("queue_cas_conflict", f"expected {expected_version}, observed {row[1]}")
            version = row[1] + 1
            self._conn.execute("UPDATE dispatch_queue SET rank=?,version=?,updated_at_tick=? WHERE queue_id=? AND version=?", (new_rank, version, tick, queue_id, row[1]))
            event = self._event(queue_id=queue_id, from_state="QUEUED", to_state="QUEUED", version=version, tick=tick, details={"new_rank": new_rank})
            self._insert_event(event)
            self._conn.commit()
            return self.get(queue_id)
        except Exception:
            self._conn.rollback()
            raise

    def claim_next(self, *, thread_id: str, thread_idle: bool, claim_id: str, now_tick: int, lease_ticks: int = 30) -> dict[str, Any]:
        if not thread_idle:
            return {"status": "HOLD", "errors": [_error("thread_not_idle", "thread_id", thread_id)]}
        if not isinstance(claim_id, str) or not claim_id or type(lease_ticks) is not int or lease_ticks <= 0:
            raise ValueError("claim_id and positive lease required")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            replay = self._conn.execute(
                "SELECT queue_id,state FROM dispatch_queue WHERE claim_id=? LIMIT 1",
                (claim_id,),
            ).fetchone()
            if replay is not None:
                raise DispatchQueueError("claim_id_replay", f"{claim_id}:{replay[0]}:{replay[1]}")
            row = self._conn.execute(
                "SELECT queue_id,queued_input_sha256,version FROM dispatch_queue WHERE thread_id=? AND state='QUEUED' ORDER BY rank,created_at_tick,queue_id LIMIT 1",
                (thread_id,),
            ).fetchone()
            if row is None:
                self._conn.rollback()
                return {"status": "EMPTY", "errors": []}
            queue_id, message_sha, old_version = row
            dispatch_id = canonical_sha256({"queue_id": queue_id, "queued_input_sha256": message_sha, "claim_id": claim_id})
            version = old_version + 1
            lease_until = now_tick + lease_ticks
            self._conn.execute(
                "UPDATE dispatch_queue SET state='CLAIMED',version=?,claim_id=?,dispatch_id=?,lease_until_tick=?,updated_at_tick=? WHERE queue_id=? AND state='QUEUED' AND version=?",
                (version, claim_id, dispatch_id, lease_until, now_tick, queue_id, old_version),
            )
            event = self._event(queue_id=queue_id, from_state="QUEUED", to_state="CLAIMED", version=version, tick=now_tick, details={"claim_id": claim_id, "dispatch_id": dispatch_id, "lease_until_tick": lease_until})
            self._insert_event(event)
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise DispatchQueueError("claim_id_replay", claim_id) from exc
        claim = {
            "contract_id": DISPATCH_CLAIM_CONTRACT_ID,
            "queue_id": queue_id,
            "thread_id": thread_id,
            "queued_input_sha256": message_sha,
            "claim_id": claim_id,
            "dispatch_id": dispatch_id,
            "lease_until_tick": lease_until,
            "claim_sha256": "",
        }
        return {"status": "PASS", "errors": [], "claim": seal_mapping(claim, "claim_sha256"), "item": self.get(queue_id)}

    def begin_dispatch(self, queue_id: str, *, claim_id: str, dispatch_id: str, now_tick: int) -> dict[str, Any]:
        return self._transition(queue_id, expected="CLAIMED", target="DISPATCHING", tick=now_tick, claim_id=claim_id, dispatch_id=dispatch_id, details={})

    def fail_before_dispatch(self, queue_id: str, *, claim_id: str, dispatch_id: str, now_tick: int, failure_sha256: str) -> dict[str, Any]:
        if not _is_sha(failure_sha256):
            raise ValueError("failure_sha256 required")
        return self._transition(queue_id, expected="CLAIMED", target="QUEUED", tick=now_tick, claim_id=claim_id, dispatch_id=dispatch_id, details={"failure_sha256": failure_sha256}, clear_claim=True)

    def mark_unknown(self, queue_id: str, *, claim_id: str, dispatch_id: str, now_tick: int, failure_sha256: str) -> dict[str, Any]:
        if not _is_sha(failure_sha256):
            raise ValueError("failure_sha256 required")
        return self._transition(queue_id, expected="DISPATCHING", target="UNKNOWN", tick=now_tick, claim_id=claim_id, dispatch_id=dispatch_id, details={"failure_sha256": failure_sha256})

    def acknowledge_persisted(self, queue_id: str, *, claim_id: str, dispatch_id: str, persisted_receipt_sha256: str, now_tick: int) -> dict[str, Any]:
        if not _is_sha(persisted_receipt_sha256):
            raise ValueError("persisted receipt required")
        return self._transition(queue_id, expected="DISPATCHING", target="DELIVERED", tick=now_tick, claim_id=claim_id, dispatch_id=dispatch_id, details={"persisted_receipt_sha256": persisted_receipt_sha256}, delivered_receipt_sha256=persisted_receipt_sha256)

    def reconcile_unknown(self, queue_id: str, *, dispatch_id: str, outcome: str, evidence_sha256: str, now_tick: int) -> dict[str, Any]:
        if outcome not in {"NO_EFFECT", "COMPLETED"} or not _is_sha(evidence_sha256):
            raise ValueError("valid reconciliation outcome and evidence required")
        target = "QUEUED" if outcome == "NO_EFFECT" else "DELIVERED"
        return self._transition(queue_id, expected="UNKNOWN", target=target, tick=now_tick, claim_id=None, dispatch_id=dispatch_id, details={"outcome": outcome, "evidence_sha256": evidence_sha256}, clear_claim=outcome == "NO_EFFECT", delivered_receipt_sha256=evidence_sha256 if outcome == "COMPLETED" else None, reconciliation_sha256=evidence_sha256)

    def recover_expired(self, *, now_tick: int) -> dict[str, int]:
        counts = {"requeued_claimed": 0, "unknown_dispatching": 0}
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            rows = self._conn.execute("SELECT queue_id,state,version,dispatch_id FROM dispatch_queue WHERE state IN ('CLAIMED','DISPATCHING') AND lease_until_tick<=?", (now_tick,)).fetchall()
            for queue_id, state, version, dispatch_id in rows:
                target = "QUEUED" if state == "CLAIMED" else "UNKNOWN"
                new_version = version + 1
                clear = target == "QUEUED"
                self._conn.execute(
                    "UPDATE dispatch_queue SET state=?,version=?,claim_id=?,dispatch_id=?,lease_until_tick=NULL,updated_at_tick=? WHERE queue_id=? AND version=?",
                    (target, new_version, None if clear else self.get(queue_id)["claim_id"], None if clear else dispatch_id, now_tick, queue_id, version),
                )
                event = self._event(queue_id=queue_id, from_state=state, to_state=target, version=new_version, tick=now_tick, details={"lease_expired": True})
                self._insert_event(event)
                counts["requeued_claimed" if state == "CLAIMED" else "unknown_dispatching"] += 1
            self._conn.commit()
            return counts
        except Exception:
            self._conn.rollback()
            raise

    def _transition(self, queue_id: str, *, expected: str, target: str, tick: int, claim_id: str | None, dispatch_id: str, details: Mapping[str, Any], clear_claim: bool = False, delivered_receipt_sha256: str | None = None, reconciliation_sha256: str | None = None) -> dict[str, Any]:
        if expected not in QUEUE_STATES or target not in QUEUE_STATES:
            raise ValueError("invalid queue transition")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT state,version,claim_id,dispatch_id FROM dispatch_queue WHERE queue_id=?", (queue_id,)).fetchone()
            if row is None:
                raise DispatchQueueError("unknown_queue_id", queue_id)
            state, old_version, stored_claim, stored_dispatch = row
            if state != expected:
                raise DispatchQueueError("queue_state_mismatch", f"expected {expected}, observed {state}")
            if stored_dispatch != dispatch_id:
                raise DispatchQueueError("dispatch_id_mismatch", dispatch_id)
            if claim_id is not None and stored_claim != claim_id:
                raise DispatchQueueError("claim_id_mismatch", claim_id)
            version = old_version + 1
            new_claim = None if clear_claim else stored_claim
            new_dispatch = None if clear_claim else stored_dispatch
            lease = None if target in {"QUEUED", "UNKNOWN", "DELIVERED", "CANCELLED"} else self.get(queue_id)["lease_until_tick"]
            self._conn.execute(
                "UPDATE dispatch_queue SET state=?,version=?,claim_id=?,dispatch_id=?,lease_until_tick=?,updated_at_tick=?,delivered_receipt_sha256=COALESCE(?,delivered_receipt_sha256),reconciliation_sha256=COALESCE(?,reconciliation_sha256) WHERE queue_id=? AND version=?",
                (target, version, new_claim, new_dispatch, lease, tick, delivered_receipt_sha256, reconciliation_sha256, queue_id, old_version),
            )
            event = self._event(queue_id=queue_id, from_state=state, to_state=target, version=version, tick=tick, details={"dispatch_id": dispatch_id, **materialize_json(details)})
            self._insert_event(event)
            self._conn.commit()
            return self.get(queue_id)
        except Exception:
            self._conn.rollback()
            raise

    def events(self, queue_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT event_json FROM dispatch_events WHERE queue_id=? ORDER BY event_seq", (queue_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]


__all__ = [
    "DISPATCH_CLAIM_CONTRACT_ID", "DISPATCH_TRANSITION_CONTRACT_ID", "DispatchQueueError",
    "PROVIDER_REQUEST_RECEIPT_CONTRACT_ID", "QUEUED_INPUT_CONTRACT_ID",
    "SQLiteDurableDispatchQueue", "seal_provider_request_receipt", "seal_queued_input",
]
