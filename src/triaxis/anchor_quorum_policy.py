"""TRIAXIS v3.11 authenticated and monotonic anchor-quorum policy."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import sqlite3
from typing import Any

from .crypto_trust import (
    PURPOSE_ANCHOR_QUORUM_POLICY,
    TrustKeyRegistry,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_anchor import TrustRegistryAnchorError

ANCHOR_QUORUM_POLICY_CONTRACT_ID = "TRIAXIS_ANCHOR_QUORUM_POLICY_v1"


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def make_anchor_quorum_policy(
    *,
    policy_id: str,
    policy_version: int,
    previous_policy_sha256: str | None,
    registry_id: str,
    anchor_set_id: str,
    threshold: int,
    authorities: Sequence[Mapping[str, str]],
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    normalized = [
        {
            "anchor_id": str(item["anchor_id"]),
            "signer_id": str(item["signer_id"]),
            "key_id": str(item["key_id"]),
            "trust_domain": str(item["trust_domain"]),
        }
        for item in authorities
    ]
    normalized.sort(key=lambda item: (item["signer_id"], item["key_id"]))
    return seal_mapping(
        {
            "contract_id": ANCHOR_QUORUM_POLICY_CONTRACT_ID,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "previous_policy_sha256": previous_policy_sha256,
            "registry_id": registry_id,
            "anchor_set_id": anchor_set_id,
            "threshold": threshold,
            "authorities": normalized,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "policy_sha256": "",
        },
        "policy_sha256",
    )


def validate_anchor_quorum_policy(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "policy", "mapping required")]}
    try:
        policy = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "policy", type(exc).__name__)]}
    if not isinstance(policy, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "policy", "object required")]}
    if policy.get("contract_id") != ANCHOR_QUORUM_POLICY_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "policy.contract_id", "unexpected policy contract"))
    if not verify_sealed_mapping(policy, "policy_sha256"):
        errors.append(_error("digest_mismatch", "policy.policy_sha256", "canonical digest mismatch"))
    for field in ("policy_id", "registry_id", "anchor_set_id"):
        if not isinstance(policy.get(field), str) or not policy.get(field):
            errors.append(_error("missing_required", f"policy.{field}", f"{field} required"))
    version = policy.get("policy_version")
    if type(version) is not int or version < 1:
        errors.append(_error("invalid_policy_version", "policy.policy_version", "integer >= 1 required"))
    previous = policy.get("previous_policy_sha256")
    if previous is not None and not _is_sha256(previous):
        errors.append(_error("invalid_previous_digest", "policy.previous_policy_sha256", "null or SHA-256 required"))
    threshold = policy.get("threshold")
    if type(threshold) is not int or threshold < 2:
        errors.append(_error("invalid_threshold", "policy.threshold", "integer >= 2 required"))
    authorities = policy.get("authorities")
    signer_ids: set[str] = set()
    key_ids: set[str] = set()
    anchor_ids: set[str] = set()
    domains: set[str] = set()
    if not isinstance(authorities, list) or not authorities:
        errors.append(_error("invalid_authorities", "policy.authorities", "non-empty array required"))
        authorities = []
    for index, item in enumerate(authorities):
        if not isinstance(item, dict):
            errors.append(_error("invalid_authority", f"policy.authorities[{index}]", "object required"))
            continue
        for name in ("anchor_id", "signer_id", "key_id", "trust_domain"):
            if not isinstance(item.get(name), str) or not item.get(name):
                errors.append(_error("missing_required", f"policy.authorities[{index}].{name}", f"{name} required"))
        if isinstance(item.get("signer_id"), str):
            if item["signer_id"] in signer_ids:
                errors.append(_error("duplicate_signer", f"policy.authorities[{index}].signer_id", item["signer_id"]))
            signer_ids.add(item["signer_id"])
        if isinstance(item.get("key_id"), str):
            if item["key_id"] in key_ids:
                errors.append(_error("duplicate_key", f"policy.authorities[{index}].key_id", item["key_id"]))
            key_ids.add(item["key_id"])
        if isinstance(item.get("anchor_id"), str):
            if item["anchor_id"] in anchor_ids:
                errors.append(_error("duplicate_anchor", f"policy.authorities[{index}].anchor_id", item["anchor_id"]))
            anchor_ids.add(item["anchor_id"])
        if isinstance(item.get("trust_domain"), str):
            domains.add(item["trust_domain"])
    if type(threshold) is int:
        if threshold > len(authorities):
            errors.append(_error("impossible_threshold", "policy.threshold", "exceeds authority count"))
        if threshold > len(domains):
            errors.append(_error("insufficient_domain_diversity", "policy.threshold", "not enough distinct trust domains"))
    valid_from, valid_until = policy.get("valid_from"), policy.get("valid_until")
    if type(valid_from) is not int or valid_from < 0:
        errors.append(_error("invalid_valid_from", "policy.valid_from", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "policy.valid_until", "integer >= 0 required"))
    elif type(valid_from) is int and valid_until <= valid_from:
        errors.append(_error("invalid_policy_window", "policy.valid_until", "must be after valid_from"))
    if evaluation_tick is not None:
        if type(valid_from) is int and evaluation_tick < valid_from:
            errors.append(_error("policy_not_yet_valid", "policy.valid_from", str(valid_from)))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("policy_expired", "policy.valid_until", str(valid_until)))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "policy": policy}


class SQLiteAnchorQuorumPolicyStore:
    """Root-signed monotonic local policy store.

    This rejects local reinstall/fork/gap attacks. Whole-database rollback remains
    an external freshness boundary and is stated explicitly in v3.11.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        policy_root_registry: TrustKeyRegistry,
        policy_id: str,
        policy_root_signer_id: str,
        policy_root_trust_domain: str,
    ) -> None:
        self.path = str(path)
        self.policy_root_registry = policy_root_registry
        self.policy_id = policy_id
        self.policy_root_signer_id = policy_root_signer_id
        self.policy_root_trust_domain = policy_root_trust_domain
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS anchor_quorum_policy_history (
                policy_version INTEGER PRIMARY KEY,
                policy_sha256 TEXT UNIQUE NOT NULL,
                signed_policy_json TEXT NOT NULL,
                installed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anchor_quorum_policy_head (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                policy_version INTEGER NOT NULL,
                policy_sha256 TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteAnchorQuorumPolicyStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _verify_signed(self, signed_policy: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        result = verify_contract_envelope(
            signed_policy,
            registry=self.policy_root_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_ANCHOR_QUORUM_POLICY,
            expected_digest_field="policy_sha256",
            expected_inner_contract_id=ANCHOR_QUORUM_POLICY_CONTRACT_ID,
            expected_signer_id=self.policy_root_signer_id,
            expected_trust_domain=self.policy_root_trust_domain,
        )
        if result["status"] != "PASS":
            raise TrustRegistryAnchorError("invalid_quorum_policy_signature", str(result["errors"]))
        validated = validate_anchor_quorum_policy(result["inner_contract"], evaluation_tick)
        if validated["status"] != "PASS":
            raise TrustRegistryAnchorError("invalid_quorum_policy", str(validated["errors"]))
        policy = validated["policy"]
        if policy["policy_id"] != self.policy_id:
            raise TrustRegistryAnchorError("quorum_policy_id_mismatch", str(policy["policy_id"]))
        return {"policy": policy, "signed": materialize_json(signed_policy)}

    def head(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT policy_version,policy_sha256 FROM anchor_quorum_policy_head WHERE singleton=1"
        ).fetchone()
        if row is None:
            return None
        return {"policy_version": row[0], "policy_sha256": row[1]}

    def install(self, signed_policy: Mapping[str, Any], evaluation_tick: int) -> dict[str, Any]:
        verified = self._verify_signed(signed_policy, evaluation_tick)
        policy = verified["policy"]
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            current = self.head()
            if current is None:
                if policy["policy_version"] != 1 or policy["previous_policy_sha256"] is not None:
                    raise TrustRegistryAnchorError("invalid_policy_genesis", str(policy["policy_version"]))
            else:
                if policy["policy_version"] == current["policy_version"] and policy["policy_sha256"] == current["policy_sha256"]:
                    self._conn.execute("COMMIT")
                    return current
                if policy["policy_version"] <= current["policy_version"]:
                    raise TrustRegistryAnchorError("quorum_policy_rollback", str(policy["policy_version"]))
                if policy["policy_version"] != current["policy_version"] + 1:
                    raise TrustRegistryAnchorError("quorum_policy_version_gap", str(policy["policy_version"]))
                if policy["previous_policy_sha256"] != current["policy_sha256"]:
                    raise TrustRegistryAnchorError("quorum_policy_parent_mismatch", str(policy["previous_policy_sha256"]))
            self._conn.execute(
                "INSERT INTO anchor_quorum_policy_history(policy_version,policy_sha256,signed_policy_json,installed_at) "
                "VALUES(?,?,?,?)",
                (
                    policy["policy_version"],
                    policy["policy_sha256"],
                    json.dumps(verified["signed"], sort_keys=True, separators=(",", ":")),
                    evaluation_tick,
                ),
            )
            self._conn.execute(
                "INSERT INTO anchor_quorum_policy_head(singleton,policy_version,policy_sha256) VALUES(1,?,?) "
                "ON CONFLICT(singleton) DO UPDATE SET policy_version=excluded.policy_version,policy_sha256=excluded.policy_sha256",
                (policy["policy_version"], policy["policy_sha256"]),
            )
            self._conn.execute("COMMIT")
            return {"policy_version": policy["policy_version"], "policy_sha256": policy["policy_sha256"]}
        except Exception:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
            raise

    def load_current(self, evaluation_tick: int) -> dict[str, Any]:
        head = self.head()
        if head is None:
            raise TrustRegistryAnchorError("quorum_policy_missing", self.policy_id)
        row = self._conn.execute(
            "SELECT signed_policy_json FROM anchor_quorum_policy_history WHERE policy_version=? AND policy_sha256=?",
            (head["policy_version"], head["policy_sha256"]),
        ).fetchone()
        if row is None:
            raise TrustRegistryAnchorError("quorum_policy_history_missing", str(head))
        signed = json.loads(row[0])
        verified = self._verify_signed(signed, evaluation_tick)
        policy = verified["policy"]
        if policy["policy_sha256"] != head["policy_sha256"]:
            raise TrustRegistryAnchorError("quorum_policy_head_mismatch", policy["policy_sha256"])
        return policy


__all__ = [
    "ANCHOR_QUORUM_POLICY_CONTRACT_ID",
    "SQLiteAnchorQuorumPolicyStore",
    "make_anchor_quorum_policy",
    "validate_anchor_quorum_policy",
]
