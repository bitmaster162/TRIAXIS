"""TRIAXIS v3.14 independent policy-transparency floor quorum.

A policy-head quorum proves what a configured set of authorities currently
claims.  It does not by itself stop a threshold of rolled-back authorities and a
stale client from agreeing on an older, still correctly signed policy.

This module adds a second, separation-of-duties plane: transparency witnesses.
Each witness maintains an independently persisted, append-only signed policy
history and returns the highest policy it has observed under a verifier-issued,
single-use challenge.  A client accepts a policy only when:

* a pinned quorum of distinct transparency witnesses agrees on a minimum floor;
* the local signed policy history contains that exact floor; and
* the current policy is at or above the floor.

This is a reference protocol.  Declared trust-domain labels do not prove
physical or administrative independence.  A threshold compromise of both the
policy-head authorities and transparency witnesses remains outside its claim.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .anchor_quorum_policy import SQLiteAnchorQuorumPolicyStore
from .crypto_trust import (
    PURPOSE_POLICY_TRANSPARENCY_WITNESS,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .policy_head_authority import PolicyHeadAuthorityError
from .trust_registry_quorum import SQLiteEpochChallengeLedger

POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID = "TRIAXIS_POLICY_TRANSPARENCY_FLOOR_RESPONSE_v1"
POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID = "TRIAXIS_POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_v1"


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 16:
        raise PolicyHeadAuthorityError("invalid_transparency_challenge", "minimum 16 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def make_policy_transparency_floor_response(
    *,
    witness_id: str,
    log_id: str,
    policy_head_quorum_config_sha256: str,
    policy_id: str,
    minimum_policy_version: int,
    minimum_policy_sha256: str,
    verifier_id: str,
    verifier_epoch_sha256: str,
    challenge_sha256: str,
    requested_at: int,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return seal_mapping(
        {
            "contract_id": POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID,
            "witness_id": witness_id,
            "log_id": log_id,
            "policy_head_quorum_config_sha256": policy_head_quorum_config_sha256,
            "policy_id": policy_id,
            "minimum_policy_version": minimum_policy_version,
            "minimum_policy_sha256": minimum_policy_sha256,
            "verifier_id": verifier_id,
            "verifier_epoch_sha256": verifier_epoch_sha256,
            "challenge_sha256": challenge_sha256,
            "requested_at": requested_at,
            "issued_at": issued_at,
            "valid_until": valid_until,
            "response_sha256": "",
        },
        "response_sha256",
    )


def validate_policy_transparency_floor_response(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "response", "mapping required")]}
    try:
        response = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "response", type(exc).__name__)]}
    if not isinstance(response, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "response", "object required")]}
    if response.get("contract_id") != POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "response.contract_id", "unexpected transparency response"))
    if not verify_sealed_mapping(response, "response_sha256"):
        errors.append(_error("digest_mismatch", "response.response_sha256", "canonical digest mismatch"))
    for field in ("witness_id", "log_id", "policy_id", "verifier_id"):
        if not isinstance(response.get(field), str) or not response.get(field):
            errors.append(_error("missing_required", f"response.{field}", f"{field} required"))
    for field in (
        "policy_head_quorum_config_sha256",
        "minimum_policy_sha256",
        "verifier_epoch_sha256",
        "challenge_sha256",
    ):
        if not _is_sha256(response.get(field)):
            errors.append(_error("invalid_sha256", f"response.{field}", "lowercase SHA-256 required"))
    version = response.get("minimum_policy_version")
    if type(version) is not int or version < 1:
        errors.append(_error("invalid_minimum_policy_version", "response.minimum_policy_version", "integer >= 1 required"))
    requested_at, issued_at, valid_until = (
        response.get("requested_at"),
        response.get("issued_at"),
        response.get("valid_until"),
    )
    for field, item in (("requested_at", requested_at), ("issued_at", issued_at), ("valid_until", valid_until)):
        if type(item) is not int or item < 0:
            errors.append(_error(f"invalid_{field}", f"response.{field}", "integer >= 0 required"))
    if type(requested_at) is int and type(issued_at) is int and issued_at < requested_at:
        errors.append(_error("invalid_response_window", "response.issued_at", "must be >= requested_at"))
    if type(issued_at) is int and type(valid_until) is int and valid_until <= issued_at:
        errors.append(_error("invalid_response_window", "response.valid_until", "must be > issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_response", "response.issued_at", str(issued_at)))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("expired_response", "response.valid_until", str(valid_until)))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "response": response}


def make_policy_transparency_floor_quorum_config(
    *,
    config_id: str,
    witness_set_id: str,
    policy_id: str,
    policy_head_quorum_config_sha256: str,
    threshold: int,
    witnesses: Sequence[Mapping[str, str]],
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    normalized = [
        {
            "witness_id": str(item["witness_id"]),
            "log_id": str(item["log_id"]),
            "signer_id": str(item["signer_id"]),
            "key_id": str(item["key_id"]),
            "trust_domain": str(item["trust_domain"]),
        }
        for item in witnesses
    ]
    normalized.sort(key=lambda item: (item["signer_id"], item["key_id"]))
    return seal_mapping(
        {
            "contract_id": POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID,
            "config_id": config_id,
            "witness_set_id": witness_set_id,
            "policy_id": policy_id,
            "policy_head_quorum_config_sha256": policy_head_quorum_config_sha256,
            "threshold": threshold,
            "witnesses": normalized,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "config_sha256": "",
        },
        "config_sha256",
    )


def validate_policy_transparency_floor_quorum_config(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "config", "mapping required")]}
    try:
        config = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "config", type(exc).__name__)]}
    if not isinstance(config, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "config", "object required")]}
    if config.get("contract_id") != POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "config.contract_id", "unexpected floor quorum config"))
    if not verify_sealed_mapping(config, "config_sha256"):
        errors.append(_error("digest_mismatch", "config.config_sha256", "canonical digest mismatch"))
    for field in ("config_id", "witness_set_id", "policy_id"):
        if not isinstance(config.get(field), str) or not config.get(field):
            errors.append(_error("missing_required", f"config.{field}", f"{field} required"))
    if not _is_sha256(config.get("policy_head_quorum_config_sha256")):
        errors.append(_error("invalid_head_config_digest", "config.policy_head_quorum_config_sha256", "SHA-256 required"))
    threshold = config.get("threshold")
    if type(threshold) is not int or threshold < 2:
        errors.append(_error("invalid_threshold", "config.threshold", "integer >= 2 required"))
    witnesses = config.get("witnesses")
    if not isinstance(witnesses, list) or not witnesses:
        errors.append(_error("invalid_witnesses", "config.witnesses", "non-empty array required"))
        witnesses = []
    seen: dict[str, set[str]] = {
        "witness_id": set(),
        "log_id": set(),
        "signer_id": set(),
        "key_id": set(),
    }
    domains: set[str] = set()
    for index, item in enumerate(witnesses):
        if not isinstance(item, dict):
            errors.append(_error("invalid_witness", f"config.witnesses[{index}]", "object required"))
            continue
        for field in ("witness_id", "log_id", "signer_id", "key_id", "trust_domain"):
            if not isinstance(item.get(field), str) or not item.get(field):
                errors.append(_error("missing_required", f"config.witnesses[{index}].{field}", f"{field} required"))
        for field, values in seen.items():
            item_value = item.get(field)
            if isinstance(item_value, str):
                if item_value in values:
                    errors.append(_error(f"duplicate_{field}", f"config.witnesses[{index}].{field}", item_value))
                values.add(item_value)
        if isinstance(item.get("trust_domain"), str):
            domains.add(item["trust_domain"])
    if type(threshold) is int:
        if threshold > len(witnesses):
            errors.append(_error("impossible_threshold", "config.threshold", "exceeds witness count"))
        if threshold > len(domains):
            errors.append(_error("insufficient_domain_diversity", "config.threshold", "not enough distinct trust domains"))
    valid_from, valid_until = config.get("valid_from"), config.get("valid_until")
    if type(valid_from) is not int or valid_from < 0:
        errors.append(_error("invalid_valid_from", "config.valid_from", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "config.valid_until", "integer >= 0 required"))
    elif type(valid_from) is int and valid_until <= valid_from:
        errors.append(_error("invalid_config_window", "config.valid_until", "must be > valid_from"))
    if evaluation_tick is not None:
        if type(valid_from) is int and evaluation_tick < valid_from:
            errors.append(_error("config_not_yet_valid", "config.valid_from", str(valid_from)))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("config_expired", "config.valid_until", str(valid_until)))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "config": config}


class SQLitePolicyTransparencyWitnessService:
    """Challenge-bound signer over an independently maintained policy history."""

    def __init__(
        self,
        path: str | Path,
        *,
        policy_store: SQLiteAnchorQuorumPolicyStore,
        witness_id: str,
        log_id: str,
        policy_head_quorum_config_sha256: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
    ) -> None:
        if not _is_sha256(policy_head_quorum_config_sha256):
            raise PolicyHeadAuthorityError("invalid_head_quorum_config_digest", str(policy_head_quorum_config_sha256))
        for field, value in (
            ("witness_id", witness_id),
            ("log_id", log_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
        ):
            if not isinstance(value, str) or not value:
                raise PolicyHeadAuthorityError(f"invalid_{field}", str(value))
        self.policy_store = policy_store
        self.witness_id = witness_id
        self.log_id = log_id
        self.policy_head_quorum_config_sha256 = policy_head_quorum_config_sha256
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self._conn = sqlite3.connect(str(path), isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transparency_floor_responses (
                challenge_sha256 TEXT PRIMARY KEY,
                verifier_id TEXT NOT NULL,
                verifier_epoch_sha256 TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                policy_version INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL,
                signed_response_json TEXT NOT NULL,
                issued_at INTEGER NOT NULL
            )
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLitePolicyTransparencyWitnessService":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def issue_floor_response(
        self,
        *,
        challenge: str,
        verifier_id: str,
        verifier_epoch_sha256: str,
        requested_at: int,
        issued_at: int,
        valid_until: int,
    ) -> dict[str, Any]:
        challenge_digest = _challenge_sha256(challenge)
        if not isinstance(verifier_id, str) or not verifier_id:
            raise PolicyHeadAuthorityError("invalid_verifier_id", "non-empty string required")
        if not _is_sha256(verifier_epoch_sha256):
            raise PolicyHeadAuthorityError("invalid_verifier_epoch", str(verifier_epoch_sha256))
        if type(requested_at) is not int or type(issued_at) is not int or type(valid_until) is not int:
            raise PolicyHeadAuthorityError("invalid_response_window", "integer times required")
        if issued_at < requested_at or valid_until <= issued_at:
            raise PolicyHeadAuthorityError("invalid_response_window", "requested_at <= issued_at < valid_until required")
        history = self.policy_store.verify_history()
        existing = self._conn.execute(
            "SELECT verifier_id,verifier_epoch_sha256,requested_at,policy_version,policy_sha256,signed_response_json "
            "FROM transparency_floor_responses WHERE challenge_sha256=?",
            (challenge_digest,),
        ).fetchone()
        expected = (
            verifier_id,
            verifier_epoch_sha256,
            requested_at,
            history["policy_version"],
            history["policy_sha256"],
        )
        if existing is not None:
            if tuple(existing[:5]) != expected:
                raise PolicyHeadAuthorityError("transparency_challenge_reuse_conflict", challenge_digest)
            return json.loads(existing[5])
        response = make_policy_transparency_floor_response(
            witness_id=self.witness_id,
            log_id=self.log_id,
            policy_head_quorum_config_sha256=self.policy_head_quorum_config_sha256,
            policy_id=history["policy_id"],
            minimum_policy_version=history["policy_version"],
            minimum_policy_sha256=history["policy_sha256"],
            verifier_id=verifier_id,
            verifier_epoch_sha256=verifier_epoch_sha256,
            challenge_sha256=challenge_digest,
            requested_at=requested_at,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        signed = sign_contract_envelope(
            response,
            digest_field="response_sha256",
            purpose=PURPOSE_POLICY_TRANSPARENCY_WITNESS,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        self._conn.execute(
            "INSERT INTO transparency_floor_responses("
            "challenge_sha256,verifier_id,verifier_epoch_sha256,requested_at,policy_version,policy_sha256,signed_response_json,issued_at"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                challenge_digest,
                verifier_id,
                verifier_epoch_sha256,
                requested_at,
                history["policy_version"],
                history["policy_sha256"],
                json.dumps(signed, sort_keys=True, separators=(",", ":")),
                issued_at,
            ),
        )
        return signed


def enforce_policy_transparency_floor_quorum(
    policy_store: SQLiteAnchorQuorumPolicyStore,
    signed_responses: Sequence[Mapping[str, Any]],
    *,
    witness_registry: TrustKeyRegistry,
    floor_quorum_config: Mapping[str, Any],
    expected_floor_config_sha256: str,
    expected_policy_head_quorum_config_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    max_response_age: int = 5,
) -> dict[str, Any]:
    if not _is_sha256(expected_floor_config_sha256):
        raise PolicyHeadAuthorityError("invalid_expected_floor_config_digest", str(expected_floor_config_sha256))
    if not _is_sha256(expected_policy_head_quorum_config_sha256):
        raise PolicyHeadAuthorityError("invalid_expected_head_config_digest", str(expected_policy_head_quorum_config_sha256))
    validated_config = validate_policy_transparency_floor_quorum_config(floor_quorum_config, evaluation_tick)
    if validated_config["status"] != "PASS":
        raise PolicyHeadAuthorityError("invalid_transparency_floor_config", str(validated_config["errors"]))
    config = validated_config["config"]
    if config["config_sha256"] != expected_floor_config_sha256:
        raise PolicyHeadAuthorityError("transparency_floor_config_substitution", config["config_sha256"])
    if config["policy_head_quorum_config_sha256"] != expected_policy_head_quorum_config_sha256:
        raise PolicyHeadAuthorityError("transparency_head_config_binding_mismatch", config["policy_head_quorum_config_sha256"])
    if type(max_response_age) is not int or max_response_age < 0:
        raise PolicyHeadAuthorityError("invalid_max_response_age", str(max_response_age))

    challenge_record = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    witnesses = {item["signer_id"]: item for item in config["witnesses"]}
    valid_by_statement: dict[tuple[Any, ...], list[dict[str, str]]] = defaultdict(list)
    seen_signers: dict[str, tuple[Any, ...]] = {}
    seen_keys: set[str] = set()
    invalid_rows: list[dict[str, Any]] = []

    for index, signed in enumerate(signed_responses):
        verified = verify_contract_envelope(
            signed,
            registry=witness_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_POLICY_TRANSPARENCY_WITNESS,
            expected_digest_field="response_sha256",
            expected_inner_contract_id=POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID,
        )
        if verified["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "signature", "errors": verified["errors"]})
            continue
        signer = verified["verified_signer"]
        assert signer is not None
        witness = witnesses.get(signer.signer_id)
        if witness is None:
            invalid_rows.append({"index": index, "reason": "signer_not_in_config", "signer_id": signer.signer_id})
            continue
        if signer.key_id != witness["key_id"]:
            invalid_rows.append({"index": index, "reason": "key_mismatch", "signer_id": signer.signer_id})
            continue
        if signer.trust_domain != witness["trust_domain"]:
            invalid_rows.append({"index": index, "reason": "trust_domain_mismatch", "signer_id": signer.signer_id})
            continue
        validated = validate_policy_transparency_floor_response(verified["inner_contract"], evaluation_tick)
        if validated["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "response", "errors": validated["errors"]})
            continue
        response = validated["response"]
        if response["witness_id"] != witness["witness_id"] or response["log_id"] != witness["log_id"]:
            invalid_rows.append({"index": index, "reason": "witness_identity_mismatch", "signer_id": signer.signer_id})
            continue
        if response["policy_id"] != config["policy_id"]:
            invalid_rows.append({"index": index, "reason": "policy_id_mismatch", "signer_id": signer.signer_id})
            continue
        if response["policy_head_quorum_config_sha256"] != expected_policy_head_quorum_config_sha256:
            invalid_rows.append({"index": index, "reason": "head_config_binding_mismatch", "signer_id": signer.signer_id})
            continue
        if response["verifier_id"] != challenge_ledger.session.verifier_id:
            invalid_rows.append({"index": index, "reason": "verifier_id_mismatch", "signer_id": signer.signer_id})
            continue
        if response["verifier_epoch_sha256"] != challenge_ledger.session.epoch_sha256:
            invalid_rows.append({"index": index, "reason": "verifier_epoch_mismatch", "signer_id": signer.signer_id})
            continue
        if response["challenge_sha256"] != challenge_record["challenge_sha256"]:
            invalid_rows.append({"index": index, "reason": "challenge_mismatch", "signer_id": signer.signer_id})
            continue
        if response["requested_at"] != challenge_record["issued_at"]:
            invalid_rows.append({"index": index, "reason": "request_time_mismatch", "signer_id": signer.signer_id})
            continue
        if evaluation_tick - response["issued_at"] > max_response_age:
            invalid_rows.append({"index": index, "reason": "response_too_old", "signer_id": signer.signer_id})
            continue
        statement = (
            response["policy_id"],
            response["minimum_policy_version"],
            response["minimum_policy_sha256"],
            response["policy_head_quorum_config_sha256"],
            response["verifier_id"],
            response["verifier_epoch_sha256"],
            response["challenge_sha256"],
            response["requested_at"],
        )
        previous = seen_signers.get(signer.signer_id)
        if previous is not None:
            if previous != statement:
                raise PolicyHeadAuthorityError("transparency_witness_equivocation", signer.signer_id)
            continue
        if signer.key_id in seen_keys:
            raise PolicyHeadAuthorityError("duplicate_transparency_witness_key", signer.key_id)
        seen_signers[signer.signer_id] = statement
        seen_keys.add(signer.key_id)
        valid_by_statement[statement].append(
            {
                "witness_id": witness["witness_id"],
                "log_id": witness["log_id"],
                "signer_id": signer.signer_id,
                "key_id": signer.key_id,
                "trust_domain": signer.trust_domain,
            }
        )

    threshold = config["threshold"]
    quorum_groups: list[tuple[tuple[Any, ...], list[dict[str, str]]]] = []
    for statement, members in valid_by_statement.items():
        if (
            len(members) >= threshold
            and len({item["witness_id"] for item in members}) >= threshold
            and len({item["log_id"] for item in members}) >= threshold
            and len({item["signer_id"] for item in members}) >= threshold
            and len({item["key_id"] for item in members}) >= threshold
            and len({item["trust_domain"] for item in members}) >= threshold
        ):
            quorum_groups.append((statement, members))
    if not quorum_groups:
        raise PolicyHeadAuthorityError(
            "transparency_floor_quorum_not_met",
            f"threshold={threshold} valid_signers={len(seen_signers)} invalid={len(invalid_rows)}",
        )
    if len(quorum_groups) > 1:
        raise PolicyHeadAuthorityError("multiple_transparency_floor_quorums", str(len(quorum_groups)))

    statement, members = quorum_groups[0]
    _, floor_version, floor_digest, *_ = statement
    local = policy_store.load_current(evaluation_tick)
    policy_store.verify_history()
    if local["policy_id"] != config["policy_id"]:
        raise PolicyHeadAuthorityError("local_policy_id_mismatch", local["policy_id"])
    if local["policy_version"] < floor_version:
        raise PolicyHeadAuthorityError(
            "policy_below_transparency_floor",
            f"local={local['policy_version']} floor={floor_version}",
        )
    if not policy_store.contains_policy(floor_version, floor_digest):
        raise PolicyHeadAuthorityError(
            "transparency_floor_not_in_local_history",
            f"version={floor_version} digest={floor_digest}",
        )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "policy": local,
        "transparency_floor": {
            "config_id": config["config_id"],
            "config_sha256": config["config_sha256"],
            "witness_set_id": config["witness_set_id"],
            "threshold": threshold,
            "minimum_policy_version": floor_version,
            "minimum_policy_sha256": floor_digest,
            "members": sorted(members, key=lambda item: item["signer_id"]),
        },
    }


__all__ = [
    "POLICY_TRANSPARENCY_FLOOR_QUORUM_CONFIG_CONTRACT_ID",
    "POLICY_TRANSPARENCY_FLOOR_RESPONSE_CONTRACT_ID",
    "SQLitePolicyTransparencyWitnessService",
    "enforce_policy_transparency_floor_quorum",
    "make_policy_transparency_floor_quorum_config",
    "make_policy_transparency_floor_response",
    "validate_policy_transparency_floor_quorum_config",
    "validate_policy_transparency_floor_response",
]
