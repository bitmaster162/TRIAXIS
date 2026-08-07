"""TRIAXIS v3.32 completion transparency quorum local reference.

Each authority remembers the highest immutable-completion-anchor head it has
accepted.  A verifier requires a threshold that exactly matches the current
anchor head, while any valid newer or same-sequence conflicting minority vetoes
an older majority.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import sqlite3
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .completion_immutable_anchor import verify_completion_immutable_anchor_head
from .crypto_trust import (
    PURPOSE_COMPLETION_TRANSPARENCY,
    TrustKeyRegistry,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_TRANSPARENCY_CONFIG_CONTRACT_ID = "TRIAXIS_COMPLETION_TRANSPARENCY_QUORUM_CONFIG_v1"
COMPLETION_TRANSPARENCY_RESPONSE_CONTRACT_ID = "TRIAXIS_COMPLETION_TRANSPARENCY_RESPONSE_v1"
COMPLETION_TRANSPARENCY_WITNESS_CONTRACT_ID = "TRIAXIS_COMPLETION_TRANSPARENCY_QUORUM_WITNESS_v1"


class CompletionTransparencyError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise CompletionTransparencyError("invalid_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def make_completion_transparency_config(*, config_id: str, authority_set_id: str, anchor_id: str, threshold: int, authorities: Sequence[Mapping[str, str]], valid_from: int, valid_until: int) -> dict[str, Any]:
    rows = [{field: str(item[field]) for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")} for item in authorities]
    rows.sort(key=lambda row: (row["signer_id"], row["key_id"]))
    return seal_mapping({
        "contract_id": COMPLETION_TRANSPARENCY_CONFIG_CONTRACT_ID,
        "config_id": config_id,
        "authority_set_id": authority_set_id,
        "anchor_id": anchor_id,
        "threshold": threshold,
        "authorities": rows,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "config_sha256": "",
    }, "config_sha256")


def validate_completion_transparency_config(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "config", "message": "mapping required"}]}
    try:
        config = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [{"code": "materialization_failed", "path": "config", "message": type(exc).__name__}]}
    if not isinstance(config, dict):
        return {"status": "BLOCK", "errors": [{"code": "invalid_type", "path": "config", "message": "object required"}]}
    if config.get("contract_id") != COMPLETION_TRANSPARENCY_CONFIG_CONTRACT_ID:
        errors.append({"code": "invalid_contract_id", "path": "config.contract_id", "message": COMPLETION_TRANSPARENCY_CONFIG_CONTRACT_ID})
    if not verify_sealed_mapping(config, "config_sha256"):
        errors.append({"code": "digest_mismatch", "path": "config.config_sha256", "message": "canonical digest mismatch"})
    for field in ("config_id", "authority_set_id", "anchor_id"):
        if not isinstance(config.get(field), str) or not config[field]:
            errors.append({"code": f"invalid_{field}", "path": f"config.{field}", "message": "non-empty string required"})
    threshold = config.get("threshold")
    rows = config.get("authorities")
    if type(threshold) is not int or threshold < 2:
        errors.append({"code": "invalid_threshold", "path": "config.threshold", "message": "integer >= 2 required"})
    if not isinstance(rows, list) or not rows:
        rows = []
        errors.append({"code": "invalid_authorities", "path": "config.authorities", "message": "non-empty list required"})
    seen = {f: set() for f in ("authority_id", "service_id", "signer_id", "key_id")}
    domains: set[str] = set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append({"code": "invalid_authority", "path": f"config.authorities[{i}]", "message": "object required"})
            continue
        for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain"):
            val = row.get(field)
            if not isinstance(val, str) or not val:
                errors.append({"code": f"invalid_{field}", "path": f"config.authorities[{i}].{field}", "message": "non-empty string required"})
        for field in seen:
            val = row.get(field)
            if val in seen[field]:
                errors.append({"code": f"duplicate_{field}", "path": f"config.authorities[{i}].{field}", "message": str(val)})
            seen[field].add(val)
        if isinstance(row.get("trust_domain"), str):
            domains.add(row["trust_domain"])
    if type(threshold) is int and len(rows) < threshold:
        errors.append({"code": "threshold_exceeds_members", "path": "config.threshold", "message": str(threshold)})
    if type(threshold) is int and len(domains) < threshold:
        errors.append({"code": "insufficient_domain_diversity", "path": "config.authorities", "message": str(len(domains))})
    vf, vu = config.get("valid_from"), config.get("valid_until")
    if type(vf) is not int or type(vu) is not int or vf < 0 or vu <= vf:
        errors.append({"code": "invalid_validity_window", "path": "config", "message": "valid_from < valid_until required"})
    if evaluation_tick is not None and type(vf) is int and type(vu) is int and not (vf <= evaluation_tick < vu):
        errors.append({"code": "config_not_current", "path": "config", "message": str(evaluation_tick)})
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "config": config}


class SQLiteCompletionTransparencyAuthority:
    def __init__(self, path: str | Path, *, authority_id: str, service_id: str, anchor_id: str, key_id: str, signer_id: str, trust_domain: str, private_key_b64: str, response_ttl: int = 30) -> None:
        for name, value in (("authority_id", authority_id), ("service_id", service_id), ("anchor_id", anchor_id), ("key_id", key_id), ("signer_id", signer_id), ("trust_domain", trust_domain), ("private_key_b64", private_key_b64)):
            if not isinstance(value, str) or not value:
                raise CompletionTransparencyError("invalid_configuration", name)
        self.path = str(path)
        self.authority_id = authority_id
        self.service_id = service_id
        self.anchor_id = anchor_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self.private_key_b64 = private_key_b64
        self.response_ttl = response_ttl
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("CREATE TABLE IF NOT EXISTS transparency_checkpoint(anchor_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, head_event_sha256 TEXT NOT NULL, state_root_sha256 TEXT NOT NULL, head_sha256 TEXT NOT NULL, observed_at INTEGER NOT NULL)")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteCompletionTransparencyAuthority":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def public_key_record(self) -> dict[str, Any]:
        raw = base64.b64decode(self.private_key_b64.encode("ascii"), validate=True)
        private = Ed25519PrivateKey.from_private_bytes(raw)
        public_b64 = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
        return make_trust_key_record(key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, public_key_b64=public_b64, purposes=[PURPOSE_COMPLETION_TRANSPARENCY], valid_from=0, valid_until=2**62)

    def checkpoint(self) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT sequence,head_event_sha256,state_root_sha256,head_sha256,observed_at FROM transparency_checkpoint WHERE anchor_id=?", (self.anchor_id,)).fetchone()
        if row is None:
            return None
        return {"anchor_id": self.anchor_id, "sequence": row[0], "head_event_sha256": row[1], "state_root_sha256": row[2], "head_sha256": row[3], "observed_at": row[4]}

    def observe_verified_head(self, head: Mapping[str, Any], *, observed_at: int) -> dict[str, Any]:
        if head.get("anchor_id") != self.anchor_id:
            raise CompletionTransparencyError("transparency_anchor_identity_mismatch", str(head.get("anchor_id")))
        sequence = head.get("sequence")
        if type(sequence) is not int or sequence < 0:
            raise CompletionTransparencyError("invalid_transparency_sequence", str(sequence))
        for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
            if not _is_sha256(head.get(field)):
                raise CompletionTransparencyError("invalid_transparency_digest", field)
        current = self.checkpoint()
        if current is None:
            self._conn.execute("INSERT INTO transparency_checkpoint(anchor_id,sequence,head_event_sha256,state_root_sha256,head_sha256,observed_at) VALUES(?,?,?,?,?,?)", (self.anchor_id, sequence, head["head_event_sha256"], head["state_root_sha256"], head["head_sha256"], observed_at))
        elif sequence < current["sequence"]:
            raise CompletionTransparencyError("transparency_checkpoint_rollback", str(sequence))
        elif sequence == current["sequence"]:
            if (head["head_event_sha256"], head["state_root_sha256"], head["head_sha256"]) != (current["head_event_sha256"], current["state_root_sha256"], current["head_sha256"]):
                raise CompletionTransparencyError("transparency_checkpoint_fork", str(sequence))
        else:
            self._conn.execute("UPDATE transparency_checkpoint SET sequence=?,head_event_sha256=?,state_root_sha256=?,head_sha256=?,observed_at=? WHERE anchor_id=?", (sequence, head["head_event_sha256"], head["state_root_sha256"], head["head_sha256"], observed_at, self.anchor_id))
        return {"status": "PASS", "checkpoint": self.checkpoint(), "authority_granted": False}

    def signed_response(self, *, challenge: str, verifier_id: str, verifier_epoch_sha256: str, requested_at: int, now_tick: int) -> dict[str, Any]:
        cp = self.checkpoint()
        if cp is None:
            raise CompletionTransparencyError("transparency_checkpoint_missing", self.anchor_id)
        response = seal_mapping({
            "contract_id": COMPLETION_TRANSPARENCY_RESPONSE_CONTRACT_ID,
            "authority_id": self.authority_id,
            "service_id": self.service_id,
            "anchor_id": self.anchor_id,
            "sequence": cp["sequence"],
            "head_event_sha256": cp["head_event_sha256"],
            "state_root_sha256": cp["state_root_sha256"],
            "head_sha256": cp["head_sha256"],
            "verifier_id": verifier_id,
            "verifier_epoch_sha256": verifier_epoch_sha256,
            "challenge_sha256": _challenge_sha256(challenge),
            "requested_at": requested_at,
            "issued_at": now_tick,
            "valid_until": now_tick + self.response_ttl,
            "authority_granted": False,
            "response_sha256": "",
        }, "response_sha256")
        return sign_contract_envelope(response, digest_field="response_sha256", purpose=PURPOSE_COMPLETION_TRANSPARENCY, key_id=self.key_id, signer_id=self.signer_id, trust_domain=self.trust_domain, private_key_b64=self.private_key_b64, issued_at=now_tick, valid_until=now_tick+self.response_ttl)


def verify_completion_transparency_quorum(signed_local_anchor_head: Mapping[str, Any], signed_responses: Sequence[Mapping[str, Any]], *, anchor_registry: TrustKeyRegistry, transparency_registry: TrustKeyRegistry, expected_anchor_id: str, expected_anchor_authority_id: str, expected_anchor_service_id: str, expected_anchor_signer_id: str, expected_anchor_trust_domain: str, expected_provider_id: str, expected_provider_service_id: str, expected_retention_policy_id: str, config: Mapping[str, Any], expected_config_sha256: str, challenge_ledger: SQLiteEpochChallengeLedger, expected_challenge: str, evaluation_tick: int, max_response_age: int = 5) -> dict[str, Any]:
    cfg_result = validate_completion_transparency_config(config, evaluation_tick)
    if cfg_result["status"] != "PASS":
        raise CompletionTransparencyError("invalid_completion_transparency_config", str(cfg_result["errors"]))
    cfg = cfg_result["config"]
    if cfg["config_sha256"] != expected_config_sha256:
        raise CompletionTransparencyError("completion_transparency_config_substitution", cfg["config_sha256"])
    if cfg["anchor_id"] != expected_anchor_id:
        raise CompletionTransparencyError("completion_transparency_anchor_mismatch", cfg["anchor_id"])
    local_result = verify_completion_immutable_anchor_head(signed_local_anchor_head, registry=anchor_registry, expected_anchor_id=expected_anchor_id, expected_authority_id=expected_anchor_authority_id, expected_service_id=expected_anchor_service_id, expected_signer_id=expected_anchor_signer_id, expected_trust_domain=expected_anchor_trust_domain, expected_provider_id=expected_provider_id, expected_provider_service_id=expected_provider_service_id, expected_retention_policy_id=expected_retention_policy_id, evaluation_tick=evaluation_tick, checkpoint_ledger=None, max_head_age=max_response_age)
    local = local_result["head"]
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    member_by_key = {row["key_id"]: row for row in cfg["authorities"]}
    exact: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    valid_rows: list[dict[str, Any]] = []
    for signed in signed_responses:
        key_id = signed.get("key_id") if isinstance(signed, Mapping) else None
        member = member_by_key.get(key_id)
        if member is None:
            raise CompletionTransparencyError("completion_transparency_unconfigured_member", str(key_id))
        if key_id in seen_keys:
            raise CompletionTransparencyError("completion_transparency_duplicate_member", str(key_id))
        seen_keys.add(key_id)
        verified = verify_contract_envelope(signed, registry=transparency_registry, evaluation_tick=evaluation_tick, expected_purpose=PURPOSE_COMPLETION_TRANSPARENCY, expected_digest_field="response_sha256", expected_inner_contract_id=COMPLETION_TRANSPARENCY_RESPONSE_CONTRACT_ID, expected_signer_id=member["signer_id"], expected_trust_domain=member["trust_domain"])
        if verified["status"] != "PASS":
            raise CompletionTransparencyError("invalid_completion_transparency_response_signature", str(verified["errors"]))
        response = verified["inner_contract"]
        # Critical v3.32 binding: the signed envelope window and the inner freshness window are identical.
        if response.get("issued_at") != signed.get("issued_at") or response.get("valid_until") != signed.get("valid_until"):
            raise CompletionTransparencyError("completion_transparency_envelope_window_mismatch", member["authority_id"])
        for field in ("authority_id", "service_id"):
            if response.get(field) != member[field]:
                raise CompletionTransparencyError(f"completion_transparency_{field}_mismatch", str(response.get(field)))
        for field, expected in (("anchor_id", expected_anchor_id), ("verifier_id", challenge["verifier_id"]), ("verifier_epoch_sha256", challenge["verifier_epoch_sha256"]), ("challenge_sha256", challenge["challenge_sha256"])):
            if response.get(field) != expected:
                raise CompletionTransparencyError(f"completion_transparency_{field}_mismatch", str(response.get(field)))
        issued_at = response.get("issued_at")
        if type(issued_at) is not int or issued_at > evaluation_tick or evaluation_tick - issued_at > max_response_age:
            raise CompletionTransparencyError("completion_transparency_response_not_fresh", str(issued_at))
        if response.get("authority_granted") is not False:
            raise CompletionTransparencyError("completion_transparency_authority_expansion", str(response.get("authority_granted")))
        seq = response.get("sequence")
        if type(seq) is not int or seq < 0:
            raise CompletionTransparencyError("invalid_completion_transparency_sequence", str(seq))
        row = {k: response.get(k) for k in ("authority_id", "service_id", "sequence", "head_event_sha256", "state_root_sha256", "head_sha256")}
        valid_rows.append(row)
        if seq > local["sequence"]:
            raise CompletionTransparencyError("completion_transparency_newer_minority_veto", member["authority_id"])
        if seq == local["sequence"] and (response.get("head_event_sha256"), response.get("state_root_sha256"), response.get("head_sha256")) != (local["head_event_sha256"], local["state_root_sha256"], local["head_sha256"]):
            raise CompletionTransparencyError("completion_transparency_fork_veto", member["authority_id"])
        if seq == local["sequence"]:
            exact.append(row)
    if len(exact) < cfg["threshold"]:
        raise CompletionTransparencyError("completion_transparency_threshold_not_reached", f"{len(exact)}/{cfg['threshold']}")
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    witness = seal_mapping({
        "contract_id": COMPLETION_TRANSPARENCY_WITNESS_CONTRACT_ID,
        "config_sha256": cfg["config_sha256"],
        "authority_set_id": cfg["authority_set_id"],
        "anchor_id": expected_anchor_id,
        "sequence": local["sequence"],
        "head_event_sha256": local["head_event_sha256"],
        "state_root_sha256": local["state_root_sha256"],
        "head_sha256": local["head_sha256"],
        "threshold": cfg["threshold"],
        "matching_authority_ids": sorted(row["authority_id"] for row in exact),
        "verifier_id": challenge["verifier_id"],
        "verifier_epoch_sha256": challenge["verifier_epoch_sha256"],
        "challenge_sha256": challenge["challenge_sha256"],
        "issued_at": evaluation_tick,
        "authority_granted": False,
        "witness_sha256": "",
    }, "witness_sha256")
    return {"status": "PASS", "quorum_witness": witness, "valid_responses": valid_rows, "authority_granted": False, "required_separate_authorization": True}


__all__ = [
    "COMPLETION_TRANSPARENCY_CONFIG_CONTRACT_ID", "COMPLETION_TRANSPARENCY_RESPONSE_CONTRACT_ID", "COMPLETION_TRANSPARENCY_WITNESS_CONTRACT_ID",
    "CompletionTransparencyError", "SQLiteCompletionTransparencyAuthority", "make_completion_transparency_config", "validate_completion_transparency_config", "verify_completion_transparency_quorum",
]
