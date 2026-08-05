"""TRIAXIS v3.12 external Policy Head Authority reference boundary.

v3.11 authenticates a local monotonic quorum policy store, but restoring the
entire local policy database can resurrect an older, lower-threshold policy.
This module moves freshness outside that local failure domain:

* an independently operated authority holds the accepted current policy head;
* every response is Ed25519 signed and bound to a fresh verifier challenge;
* the client requires the local policy version and digest to match the external
  head exactly before the policy can authorize any registry quorum;
* optional minimum version/digest pins provide an additional operator floor.

This is a reference implementation. It does not claim resistance to compromise
or rollback of the external authority itself. Production use requires separate
administration, protected key custody, durable replicated storage, trusted time,
and complete mediation at the consuming execution boundary.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from .anchor_quorum_policy import SQLiteAnchorQuorumPolicyStore
from .crypto_trust import (
    PURPOSE_POLICY_HEAD_AUTHORITY,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

POLICY_HEAD_RESPONSE_CONTRACT_ID = "TRIAXIS_POLICY_HEAD_AUTHORITY_RESPONSE_v1"


class PolicyHeadAuthorityError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _challenge_sha256(challenge: str) -> str:
    if not isinstance(challenge, str) or len(challenge) < 32:
        raise PolicyHeadAuthorityError("invalid_challenge", "unpredictable string of at least 32 characters required")
    return hashlib.sha256(challenge.encode("utf-8")).hexdigest()


def make_policy_head_response(
    *,
    authority_id: str,
    policy_id: str,
    policy_version: int,
    policy_sha256: str,
    verifier_id: str,
    verifier_epoch_sha256: str,
    challenge_sha256: str,
    requested_at: int,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return seal_mapping(
        {
            "contract_id": POLICY_HEAD_RESPONSE_CONTRACT_ID,
            "authority_id": authority_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_sha256": policy_sha256,
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


def validate_policy_head_response(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "response", "mapping required")]}
    try:
        response = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "response", type(exc).__name__)]}
    if not isinstance(response, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "response", "object required")]}
    if response.get("contract_id") != POLICY_HEAD_RESPONSE_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "response.contract_id", "unexpected response contract"))
    if not verify_sealed_mapping(response, "response_sha256"):
        errors.append(_error("digest_mismatch", "response.response_sha256", "canonical digest mismatch"))
    for name in ("authority_id", "policy_id", "verifier_id"):
        if not isinstance(response.get(name), str) or not response.get(name):
            errors.append(_error("missing_required", f"response.{name}", f"{name} required"))
    if type(response.get("policy_version")) is not int or response.get("policy_version", 0) < 1:
        errors.append(_error("invalid_policy_version", "response.policy_version", "integer >= 1 required"))
    for name in ("policy_sha256", "verifier_epoch_sha256", "challenge_sha256"):
        if not _is_sha256(response.get(name)):
            errors.append(_error("invalid_digest", f"response.{name}", "lowercase SHA-256 required"))
    requested_at = response.get("requested_at")
    issued_at = response.get("issued_at")
    valid_until = response.get("valid_until")
    for name, item in (("requested_at", requested_at), ("issued_at", issued_at), ("valid_until", valid_until)):
        if type(item) is not int or item < 0:
            errors.append(_error("invalid_time", f"response.{name}", "integer >= 0 required"))
    if type(requested_at) is int and type(issued_at) is int and issued_at < requested_at:
        errors.append(_error("issued_before_request", "response.issued_at", "must not predate request"))
    if type(issued_at) is int and type(valid_until) is int and valid_until <= issued_at:
        errors.append(_error("invalid_response_window", "response.valid_until", "must be after issued_at"))
    if evaluation_tick is not None:
        if type(issued_at) is int and issued_at > evaluation_tick:
            errors.append(_error("future_response", "response.issued_at", "response from future"))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("stale_response", "response.valid_until", "response expired"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "response": response}


class SQLitePolicyHeadAuthorityService:
    """Independent policy-head responder with an auditable challenge ledger.

    The service stores no private key on disk. The signing key is supplied by a
    provisioning layer and remains process-local in this reference design.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        policy_store: SQLiteAnchorQuorumPolicyStore,
        authority_id: str,
        key_id: str,
        signer_id: str,
        trust_domain: str,
        private_key_b64: str,
    ) -> None:
        for name, value in (
            ("authority_id", authority_id),
            ("key_id", key_id),
            ("signer_id", signer_id),
            ("trust_domain", trust_domain),
            ("private_key_b64", private_key_b64),
        ):
            if not isinstance(value, str) or not value:
                raise PolicyHeadAuthorityError("invalid_configuration", name)
        self.path = str(path)
        self.policy_store = policy_store
        self.authority_id = authority_id
        self.key_id = key_id
        self.signer_id = signer_id
        self.trust_domain = trust_domain
        self._private_key_b64 = private_key_b64
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS policy_head_responses (
                challenge_sha256 TEXT PRIMARY KEY,
                verifier_id TEXT NOT NULL,
                verifier_epoch_sha256 TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                policy_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL,
                signed_response_json TEXT NOT NULL,
                issued_at INTEGER NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLitePolicyHeadAuthorityService":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def install_policy(self, signed_policy: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        return self.policy_store.install(signed_policy, evaluation_tick)

    def issue_head_response(
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
            raise PolicyHeadAuthorityError("invalid_verifier_epoch", verifier_epoch_sha256)
        if type(requested_at) is not int or type(issued_at) is not int or type(valid_until) is not int:
            raise PolicyHeadAuthorityError("invalid_response_window", "integer times required")
        if issued_at < requested_at or valid_until <= issued_at:
            raise PolicyHeadAuthorityError("invalid_response_window", "requested_at <= issued_at < valid_until required")
        policy = self.policy_store.load_current(issued_at)
        existing = self._conn.execute(
            "SELECT verifier_id,verifier_epoch_sha256,requested_at,policy_id,policy_version,policy_sha256,signed_response_json "
            "FROM policy_head_responses WHERE challenge_sha256=?",
            (challenge_digest,),
        ).fetchone()
        if existing is not None:
            expected = (
                verifier_id,
                verifier_epoch_sha256,
                requested_at,
                policy["policy_id"],
                policy["policy_version"],
                policy["policy_sha256"],
            )
            if tuple(existing[:6]) != expected:
                raise PolicyHeadAuthorityError("challenge_reuse_conflict", challenge_digest)
            return json.loads(existing[6])
        response = make_policy_head_response(
            authority_id=self.authority_id,
            policy_id=policy["policy_id"],
            policy_version=policy["policy_version"],
            policy_sha256=policy["policy_sha256"],
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
            purpose=PURPOSE_POLICY_HEAD_AUTHORITY,
            key_id=self.key_id,
            signer_id=self.signer_id,
            trust_domain=self.trust_domain,
            private_key_b64=self._private_key_b64,
            issued_at=issued_at,
            valid_until=valid_until,
        )
        self._conn.execute(
            "INSERT INTO policy_head_responses("
            "challenge_sha256,verifier_id,verifier_epoch_sha256,requested_at,policy_id,policy_version,policy_sha256,signed_response_json,issued_at"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                challenge_digest,
                verifier_id,
                verifier_epoch_sha256,
                requested_at,
                policy["policy_id"],
                policy["policy_version"],
                policy["policy_sha256"],
                json.dumps(signed, sort_keys=True, separators=(",", ":")),
                issued_at,
            ),
        )
        return signed


def load_policy_with_external_head(
    policy_store: SQLiteAnchorQuorumPolicyStore,
    signed_response: Mapping[str, Any],
    *,
    authority_registry: TrustKeyRegistry,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    expected_authority_id: str,
    expected_policy_id: str,
    expected_authority_signer_id: str,
    expected_authority_trust_domain: str,
    max_response_age: int = 5,
    minimum_policy_version: int | None = None,
    minimum_policy_sha256: str | None = None,
) -> dict[str, Any]:
    challenge_record = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    verified = verify_contract_envelope(
        signed_response,
        registry=authority_registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_POLICY_HEAD_AUTHORITY,
        expected_digest_field="response_sha256",
        expected_inner_contract_id=POLICY_HEAD_RESPONSE_CONTRACT_ID,
        expected_signer_id=expected_authority_signer_id,
        expected_trust_domain=expected_authority_trust_domain,
    )
    if verified["status"] != "PASS":
        raise PolicyHeadAuthorityError("invalid_policy_head_signature", str(verified["errors"]))
    validated = validate_policy_head_response(verified["inner_contract"], evaluation_tick)
    if validated["status"] != "PASS":
        raise PolicyHeadAuthorityError("invalid_policy_head_response", str(validated["errors"]))
    response = validated["response"]
    if response["authority_id"] != expected_authority_id:
        raise PolicyHeadAuthorityError("policy_head_authority_mismatch", response["authority_id"])
    if response["policy_id"] != expected_policy_id:
        raise PolicyHeadAuthorityError("policy_head_policy_id_mismatch", response["policy_id"])
    if response["verifier_id"] != challenge_ledger.session.verifier_id:
        raise PolicyHeadAuthorityError("policy_head_verifier_mismatch", response["verifier_id"])
    if response["verifier_epoch_sha256"] != challenge_ledger.session.epoch_sha256:
        raise PolicyHeadAuthorityError("policy_head_epoch_mismatch", response["verifier_epoch_sha256"])
    if response["challenge_sha256"] != challenge_record["challenge_sha256"]:
        raise PolicyHeadAuthorityError("policy_head_challenge_mismatch", response["challenge_sha256"])
    if response["requested_at"] != challenge_record["issued_at"]:
        raise PolicyHeadAuthorityError("policy_head_request_time_mismatch", str(response["requested_at"]))
    if type(max_response_age) is not int or max_response_age < 0:
        raise PolicyHeadAuthorityError("invalid_max_response_age", str(max_response_age))
    if evaluation_tick - response["issued_at"] > max_response_age:
        raise PolicyHeadAuthorityError("policy_head_response_too_old", str(response["issued_at"]))
    local = policy_store.load_current(evaluation_tick)
    if local["policy_id"] != expected_policy_id:
        raise PolicyHeadAuthorityError("local_policy_id_mismatch", local["policy_id"])
    local_version = local["policy_version"]
    remote_version = response["policy_version"]
    if local_version < remote_version:
        raise PolicyHeadAuthorityError("local_policy_rollback", f"local={local_version} authority={remote_version}")
    if local_version > remote_version:
        raise PolicyHeadAuthorityError("stale_policy_head_authority", f"local={local_version} authority={remote_version}")
    if local["policy_sha256"] != response["policy_sha256"]:
        raise PolicyHeadAuthorityError("local_policy_fork", "version matches but digest differs")
    if minimum_policy_version is not None:
        if type(minimum_policy_version) is not int or minimum_policy_version < 1:
            raise PolicyHeadAuthorityError("invalid_minimum_policy_version", str(minimum_policy_version))
        if remote_version < minimum_policy_version:
            raise PolicyHeadAuthorityError("minimum_policy_version_not_met", f"head={remote_version} minimum={minimum_policy_version}")
    if minimum_policy_sha256 is not None:
        if not _is_sha256(minimum_policy_sha256):
            raise PolicyHeadAuthorityError("invalid_minimum_policy_digest", str(minimum_policy_sha256))
        if response["policy_sha256"] != minimum_policy_sha256:
            raise PolicyHeadAuthorityError("minimum_policy_digest_not_met", response["policy_sha256"])
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return local


__all__ = [
    "POLICY_HEAD_RESPONSE_CONTRACT_ID",
    "PolicyHeadAuthorityError",
    "SQLitePolicyHeadAuthorityService",
    "load_policy_with_external_head",
    "make_policy_head_response",
    "validate_policy_head_response",
]
