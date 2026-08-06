"""TRIAXIS v3.16 external policy-transparency gossip head.

A local gossip database can detect cross-session rollback only while its own
bytes remain current.  This module exports the exact local gossip state into a
verifier-signed checkpoint, installs checkpoints into an independently operated
monotonic authority, and verifies a fresh challenge-bound authority response
before the local state is trusted.

The protocol closes rollback of the verifier gossip database while the issuer
key and external authority remain uncompromised and independently current.  It
does not prove physical independence or survive coordinated rollback of the
verifier, checkpoint issuer, and external authority.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT,
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping
from .policy_head_authority import PolicyHeadAuthorityError
from .policy_transparency_floor import SQLitePolicyTransparencyGossipStore
from .trust_registry_quorum import SQLiteEpochChallengeLedger

GOSSIP_STATE_CONTRACT_ID = "TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_STATE_v1"
GOSSIP_CHECKPOINT_CONTRACT_ID = "TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT_v1"
GOSSIP_HEAD_RESPONSE_CONTRACT_ID = "TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_HEAD_RESPONSE_v1"
ZERO_SHA256 = "0" * 64


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise PolicyHeadAuthorityError("invalid_gossip_head_challenge", "minimum 16 characters required")
    import hashlib
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def export_gossip_state(store: SQLitePolicyTransparencyGossipStore, *, store_id: str) -> dict[str, Any]:
    if not isinstance(store_id, str) or not store_id:
        raise PolicyHeadAuthorityError("invalid_gossip_store_id", str(store_id))
    rows = store._conn.execute(
        "SELECT signer_id,witness_id,log_id,key_id,trust_domain,policy_id,minimum_policy_version,"
        "minimum_policy_sha256,response_sha256,observed_at FROM transparency_witness_pins ORDER BY signer_id"
    ).fetchall()
    pins = [
        {
            "signer_id": row[0], "witness_id": row[1], "log_id": row[2], "key_id": row[3],
            "trust_domain": row[4], "policy_id": row[5], "minimum_policy_version": row[6],
            "minimum_policy_sha256": row[7], "response_sha256": row[8], "observed_at": row[9],
        }
        for row in rows
    ]
    seq_row = store._conn.execute("SELECT COALESCE(MAX(event_id),0) FROM transparency_witness_pin_history").fetchone()
    gossip_sequence = int(seq_row[0])
    pins_root = canonical_sha256({"store_id": store_id, "gossip_sequence": gossip_sequence, "pins": pins})
    return seal_mapping({
        "contract_id": GOSSIP_STATE_CONTRACT_ID,
        "store_id": store_id,
        "gossip_sequence": gossip_sequence,
        "pin_count": len(pins),
        "pins_root_sha256": pins_root,
        "state_sha256": "",
    }, "state_sha256")


def validate_gossip_state(value: Any) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "state", "message": "mapping required"}]}
    try:
        state = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [{"code": "materialization_failed", "path": "state", "message": type(exc).__name__}]}
    if state.get("contract_id") != GOSSIP_STATE_CONTRACT_ID:
        errors.append({"code": "invalid_contract_id", "path": "state.contract_id", "message": GOSSIP_STATE_CONTRACT_ID})
    if not verify_sealed_mapping(state, "state_sha256"):
        errors.append({"code": "digest_mismatch", "path": "state.state_sha256", "message": "canonical digest mismatch"})
    if not isinstance(state.get("store_id"), str) or not state.get("store_id"):
        errors.append({"code": "invalid_store_id", "path": "state.store_id", "message": "non-empty string required"})
    for field in ("gossip_sequence", "pin_count"):
        if type(state.get(field)) is not int or state[field] < 0:
            errors.append({"code": f"invalid_{field}", "path": f"state.{field}", "message": "integer >= 0 required"})
    if not _is_sha256(state.get("pins_root_sha256")):
        errors.append({"code": "invalid_pins_root", "path": "state.pins_root_sha256", "message": "SHA-256 required"})
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "state": state}


def make_gossip_checkpoint(*, checkpoint_id: str, verifier_id: str, checkpoint_sequence: int,
                           parent_checkpoint_sha256: str, gossip_state: Mapping[str, Any], issued_at: int) -> dict[str, Any]:
    validated = validate_gossip_state(gossip_state)
    if validated["status"] != "PASS":
        raise PolicyHeadAuthorityError("invalid_gossip_state", str(validated["errors"]))
    state = validated["state"]
    if type(checkpoint_sequence) is not int or checkpoint_sequence < 1:
        raise PolicyHeadAuthorityError("invalid_gossip_checkpoint_sequence", str(checkpoint_sequence))
    if not _is_sha256(parent_checkpoint_sha256):
        raise PolicyHeadAuthorityError("invalid_gossip_checkpoint_parent", str(parent_checkpoint_sha256))
    return seal_mapping({
        "contract_id": GOSSIP_CHECKPOINT_CONTRACT_ID,
        "checkpoint_id": checkpoint_id,
        "verifier_id": verifier_id,
        "checkpoint_sequence": checkpoint_sequence,
        "parent_checkpoint_sha256": parent_checkpoint_sha256,
        "store_id": state["store_id"],
        "gossip_sequence": state["gossip_sequence"],
        "pin_count": state["pin_count"],
        "pins_root_sha256": state["pins_root_sha256"],
        "gossip_state_sha256": state["state_sha256"],
        "issued_at": issued_at,
        "checkpoint_sha256": "",
    }, "checkpoint_sha256")


class SQLiteGossipCheckpointIssuer:
    def __init__(self, path: str | Path, *, gossip_store: SQLitePolicyTransparencyGossipStore,
                 store_id: str, verifier_id: str, key_id: str, signer_id: str,
                 trust_domain: str, private_key_b64: str) -> None:
        self.gossip_store = gossip_store
        self.store_id = store_id; self.verifier_id = verifier_id
        self.key_id = key_id; self.signer_id = signer_id; self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL"); self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("CREATE TABLE IF NOT EXISTS gossip_checkpoints (checkpoint_sequence INTEGER PRIMARY KEY, gossip_state_sha256 TEXT UNIQUE NOT NULL, checkpoint_sha256 TEXT UNIQUE NOT NULL, signed_json TEXT NOT NULL)")
    def close(self): self._conn.close()
    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def current(self) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT signed_json FROM gossip_checkpoints ORDER BY checkpoint_sequence DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None
    def issue(self, *, issued_at: int, valid_until: int) -> dict[str, Any]:
        state = export_gossip_state(self.gossip_store, store_id=self.store_id)
        existing = self._conn.execute("SELECT signed_json FROM gossip_checkpoints WHERE gossip_state_sha256=?", (state["state_sha256"],)).fetchone()
        if existing: return json.loads(existing[0])
        current = self.current()
        sequence = 1 if current is None else current["inner_contract"]["checkpoint_sequence"] + 1
        parent = ZERO_SHA256 if current is None else current["inner_contract"]["checkpoint_sha256"]
        checkpoint = make_gossip_checkpoint(checkpoint_id=f"{self.store_id}:{sequence}", verifier_id=self.verifier_id,
            checkpoint_sequence=sequence, parent_checkpoint_sha256=parent, gossip_state=state, issued_at=issued_at)
        signed = sign_contract_envelope(checkpoint, digest_field="checkpoint_sha256",
            purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT, key_id=self.key_id,
            signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self._private_key_b64,
            issued_at=issued_at, valid_until=valid_until)
        self._conn.execute("INSERT INTO gossip_checkpoints VALUES(?,?,?,?)", (sequence, state["state_sha256"], checkpoint["checkpoint_sha256"], json.dumps(signed, sort_keys=True, separators=(",", ":"))))
        return signed


class SQLiteGossipHeadAuthority:
    def __init__(self, path: str | Path, *, authority_id: str, service_id: str,
                 checkpoint_registry: TrustKeyRegistry, expected_checkpoint_signer_id: str,
                 expected_checkpoint_trust_domain: str, key_id: str, signer_id: str,
                 trust_domain: str, private_key_b64: str) -> None:
        self.authority_id=authority_id; self.service_id=service_id
        self.checkpoint_registry=checkpoint_registry
        self.expected_checkpoint_signer_id=expected_checkpoint_signer_id
        self.expected_checkpoint_trust_domain=expected_checkpoint_trust_domain
        self.key_id=key_id; self.signer_id=signer_id; self.trust_domain=trust_domain; self._private_key_b64=private_key_b64
        self._conn=sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL"); self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("CREATE TABLE IF NOT EXISTS accepted_gossip_checkpoints (store_id TEXT PRIMARY KEY, checkpoint_sequence INTEGER NOT NULL, checkpoint_sha256 TEXT NOT NULL, signed_json TEXT NOT NULL)")
    def close(self): self._conn.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()
    def install(self, signed_checkpoint: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        verified=verify_contract_envelope(signed_checkpoint, registry=self.checkpoint_registry, evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT, expected_digest_field="checkpoint_sha256",
            expected_inner_contract_id=GOSSIP_CHECKPOINT_CONTRACT_ID, expected_signer_id=self.expected_checkpoint_signer_id,
            expected_trust_domain=self.expected_checkpoint_trust_domain)
        if verified["status"] != "PASS": raise PolicyHeadAuthorityError("invalid_gossip_checkpoint_signature", str(verified["errors"]))
        cp=verified["inner_contract"]
        row=self._conn.execute("SELECT checkpoint_sequence,checkpoint_sha256,signed_json FROM accepted_gossip_checkpoints WHERE store_id=?", (cp["store_id"],)).fetchone()
        if row:
            if cp["checkpoint_sequence"] == row[0] and cp["checkpoint_sha256"] == row[1]: return json.loads(row[2])
            if cp["checkpoint_sequence"] != row[0]+1: raise PolicyHeadAuthorityError("gossip_checkpoint_sequence_gap", f"current={row[0]} incoming={cp['checkpoint_sequence']}")
            if cp["parent_checkpoint_sha256"] != row[1]: raise PolicyHeadAuthorityError("gossip_checkpoint_parent_mismatch", cp["parent_checkpoint_sha256"])
        else:
            if cp["checkpoint_sequence"] != 1 or cp["parent_checkpoint_sha256"] != ZERO_SHA256:
                raise PolicyHeadAuthorityError("invalid_initial_gossip_checkpoint", cp["checkpoint_sha256"])
        payload=json.dumps(materialize_json(signed_checkpoint), sort_keys=True, separators=(",", ":"))
        self._conn.execute("INSERT INTO accepted_gossip_checkpoints VALUES(?,?,?,?) ON CONFLICT(store_id) DO UPDATE SET checkpoint_sequence=excluded.checkpoint_sequence,checkpoint_sha256=excluded.checkpoint_sha256,signed_json=excluded.signed_json", (cp["store_id"], cp["checkpoint_sequence"], cp["checkpoint_sha256"], payload))
        return materialize_json(signed_checkpoint)
    def current(self, store_id: str) -> dict[str, Any] | None:
        row=self._conn.execute("SELECT signed_json FROM accepted_gossip_checkpoints WHERE store_id=?", (store_id,)).fetchone()
        return json.loads(row[0]) if row else None
    def issue_head(self, *, store_id: str, challenge: str, verifier_id: str, verifier_epoch_sha256: str,
                   requested_at: int, issued_at: int, valid_until: int) -> dict[str, Any]:
        current=self.current(store_id)
        if current is None: raise PolicyHeadAuthorityError("unknown_gossip_store", store_id)
        cp=current["inner_contract"]
        response=seal_mapping({
            "contract_id": GOSSIP_HEAD_RESPONSE_CONTRACT_ID,
            "authority_id": self.authority_id, "service_id": self.service_id,
            "store_id": store_id, "verifier_id": verifier_id, "verifier_epoch_sha256": verifier_epoch_sha256,
            "challenge_sha256": _challenge_sha256(challenge), "requested_at": requested_at,
            "checkpoint_sequence": cp["checkpoint_sequence"], "checkpoint_sha256": cp["checkpoint_sha256"],
            "gossip_sequence": cp["gossip_sequence"], "gossip_state_sha256": cp["gossip_state_sha256"],
            "pins_root_sha256": cp["pins_root_sha256"], "issued_at": issued_at, "valid_until": valid_until,
            "response_sha256": "",
        }, "response_sha256")
        return sign_contract_envelope(response, digest_field="response_sha256",
            purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY, key_id=self.key_id,
            signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self._private_key_b64,
            issued_at=issued_at, valid_until=valid_until)


def enforce_external_gossip_head(*, gossip_store: SQLitePolicyTransparencyGossipStore, store_id: str,
    signed_checkpoint: Mapping[str, Any], signed_head_response: Mapping[str, Any],
    checkpoint_registry: TrustKeyRegistry, authority_registry: TrustKeyRegistry,
    expected_checkpoint_signer_id: str, expected_checkpoint_trust_domain: str,
    expected_authority_id: str, expected_authority_signer_id: str, expected_authority_trust_domain: str,
    challenge_ledger: SQLiteEpochChallengeLedger, expected_challenge: str, evaluation_tick: int,
    max_response_age: int = 5) -> dict[str, Any]:
    challenge=challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    cpv=verify_contract_envelope(signed_checkpoint, registry=checkpoint_registry, evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT, expected_digest_field="checkpoint_sha256",
        expected_inner_contract_id=GOSSIP_CHECKPOINT_CONTRACT_ID, expected_signer_id=expected_checkpoint_signer_id,
        expected_trust_domain=expected_checkpoint_trust_domain)
    if cpv["status"] != "PASS": raise PolicyHeadAuthorityError("invalid_local_gossip_checkpoint", str(cpv["errors"]))
    hv=verify_contract_envelope(signed_head_response, registry=authority_registry, evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY, expected_digest_field="response_sha256",
        expected_inner_contract_id=GOSSIP_HEAD_RESPONSE_CONTRACT_ID, expected_signer_id=expected_authority_signer_id,
        expected_trust_domain=expected_authority_trust_domain)
    if hv["status"] != "PASS": raise PolicyHeadAuthorityError("invalid_gossip_head_signature", str(hv["errors"]))
    cp=cpv["inner_contract"]; head=hv["inner_contract"]
    if head["authority_id"] != expected_authority_id: raise PolicyHeadAuthorityError("gossip_head_authority_mismatch", head["authority_id"])
    if head["store_id"] != store_id or cp["store_id"] != store_id: raise PolicyHeadAuthorityError("gossip_store_binding_mismatch", store_id)
    if head["verifier_id"] != challenge_ledger.session.verifier_id or head["verifier_epoch_sha256"] != challenge_ledger.session.epoch_sha256:
        raise PolicyHeadAuthorityError("gossip_head_verifier_binding_mismatch", head["verifier_id"])
    if head["challenge_sha256"] != challenge["challenge_sha256"] or head["requested_at"] != challenge["issued_at"]:
        raise PolicyHeadAuthorityError("gossip_head_challenge_mismatch", head["challenge_sha256"])
    if evaluation_tick - head["issued_at"] > max_response_age: raise PolicyHeadAuthorityError("gossip_head_response_too_old", str(head["issued_at"]))
    local=export_gossip_state(gossip_store, store_id=store_id)
    bindings=("checkpoint_sequence","checkpoint_sha256","gossip_sequence","gossip_state_sha256","pins_root_sha256")
    for field in bindings:
        expected = cp[field]
        if head[field] != expected: raise PolicyHeadAuthorityError("gossip_head_checkpoint_mismatch", field)
    if local["gossip_sequence"] != cp["gossip_sequence"] or local["state_sha256"] != cp["gossip_state_sha256"] or local["pins_root_sha256"] != cp["pins_root_sha256"]:
        raise PolicyHeadAuthorityError("local_gossip_state_rollback_detected", f"local={local['gossip_sequence']} checkpoint={cp['gossip_sequence']}")
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {"status":"PASS", "gossip_state":local, "checkpoint":cp, "external_head":head}


__all__=["GOSSIP_STATE_CONTRACT_ID","GOSSIP_CHECKPOINT_CONTRACT_ID","GOSSIP_HEAD_RESPONSE_CONTRACT_ID",
"SQLiteGossipCheckpointIssuer","SQLiteGossipHeadAuthority","export_gossip_state","make_gossip_checkpoint","enforce_external_gossip_head"]
