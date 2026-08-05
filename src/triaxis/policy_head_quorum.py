"""TRIAXIS v3.13 distinct Policy Head Authority quorum.

v3.12 depends on one external policy-head signer. A compromised or rolled-back
single authority can still sign an old or equivocated head. v3.13 requires an
operator-pinned quorum configuration and agreement by distinct authority IDs,
signer IDs, key IDs, and trust domains.

The quorum configuration is sealed and its exact digest must be pinned by the
consumer. It is intentionally not self-authorizing. A hostile administrator who
can replace both the configuration and the independently provisioned digest pin
remains outside this reference implementation's guarantees.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .anchor_quorum_policy import SQLiteAnchorQuorumPolicyStore
from .crypto_trust import (
    PURPOSE_POLICY_HEAD_AUTHORITY,
    TrustKeyRegistry,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .policy_head_authority import (
    POLICY_HEAD_RESPONSE_CONTRACT_ID,
    PolicyHeadAuthorityError,
    validate_policy_head_response,
)
from .trust_registry_quorum import SQLiteEpochChallengeLedger

POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID = "TRIAXIS_POLICY_HEAD_QUORUM_CONFIG_v1"


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def make_policy_head_quorum_config(
    *,
    config_id: str,
    authority_set_id: str,
    policy_id: str,
    threshold: int,
    authorities: Sequence[Mapping[str, str]],
    minimum_policy_version: int,
    minimum_policy_sha256: str | None,
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    normalized = [
        {
            "authority_id": str(item["authority_id"]),
            "signer_id": str(item["signer_id"]),
            "key_id": str(item["key_id"]),
            "trust_domain": str(item["trust_domain"]),
        }
        for item in authorities
    ]
    normalized.sort(key=lambda item: (item["signer_id"], item["key_id"]))
    return seal_mapping(
        {
            "contract_id": POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID,
            "config_id": config_id,
            "authority_set_id": authority_set_id,
            "policy_id": policy_id,
            "threshold": threshold,
            "authorities": normalized,
            "minimum_policy_version": minimum_policy_version,
            "minimum_policy_sha256": minimum_policy_sha256,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "config_sha256": "",
        },
        "config_sha256",
    )


def validate_policy_head_quorum_config(value: Any, evaluation_tick: int | None = None) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "config", "mapping required")]}
    try:
        config = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "config", type(exc).__name__)]}
    if not isinstance(config, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "config", "object required")]}
    if config.get("contract_id") != POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "config.contract_id", "unexpected quorum config"))
    if not verify_sealed_mapping(config, "config_sha256"):
        errors.append(_error("digest_mismatch", "config.config_sha256", "canonical digest mismatch"))
    for name in ("config_id", "authority_set_id", "policy_id"):
        if not isinstance(config.get(name), str) or not config.get(name):
            errors.append(_error("missing_required", f"config.{name}", f"{name} required"))
    threshold = config.get("threshold")
    if type(threshold) is not int or threshold < 2:
        errors.append(_error("invalid_threshold", "config.threshold", "integer >= 2 required"))
    authorities = config.get("authorities")
    if not isinstance(authorities, list) or not authorities:
        errors.append(_error("invalid_authorities", "config.authorities", "non-empty array required"))
        authorities = []
    seen_authorities: set[str] = set()
    seen_signers: set[str] = set()
    seen_keys: set[str] = set()
    domains: set[str] = set()
    for index, item in enumerate(authorities):
        if not isinstance(item, dict):
            errors.append(_error("invalid_authority", f"config.authorities[{index}]", "object required"))
            continue
        for name in ("authority_id", "signer_id", "key_id", "trust_domain"):
            if not isinstance(item.get(name), str) or not item.get(name):
                errors.append(_error("missing_required", f"config.authorities[{index}].{name}", f"{name} required"))
        for name, seen, code in (
            ("authority_id", seen_authorities, "duplicate_authority"),
            ("signer_id", seen_signers, "duplicate_signer"),
            ("key_id", seen_keys, "duplicate_key"),
        ):
            item_value = item.get(name)
            if isinstance(item_value, str):
                if item_value in seen:
                    errors.append(_error(code, f"config.authorities[{index}].{name}", item_value))
                seen.add(item_value)
        domain = item.get("trust_domain")
        if isinstance(domain, str):
            domains.add(domain)
    if type(threshold) is int:
        if threshold > len(authorities):
            errors.append(_error("impossible_threshold", "config.threshold", "exceeds authority count"))
        if threshold > len(domains):
            errors.append(_error("insufficient_domain_diversity", "config.threshold", "not enough distinct trust domains"))
    minimum_version = config.get("minimum_policy_version")
    if type(minimum_version) is not int or minimum_version < 1:
        errors.append(_error("invalid_minimum_policy_version", "config.minimum_policy_version", "integer >= 1 required"))
    minimum_digest = config.get("minimum_policy_sha256")
    if minimum_digest is not None and not _is_sha256(minimum_digest):
        errors.append(_error("invalid_minimum_policy_digest", "config.minimum_policy_sha256", "null or SHA-256 required"))
    valid_from = config.get("valid_from")
    valid_until = config.get("valid_until")
    if type(valid_from) is not int or valid_from < 0:
        errors.append(_error("invalid_valid_from", "config.valid_from", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "config.valid_until", "integer >= 0 required"))
    elif type(valid_from) is int and valid_until <= valid_from:
        errors.append(_error("invalid_config_window", "config.valid_until", "must be after valid_from"))
    if evaluation_tick is not None:
        if type(valid_from) is int and evaluation_tick < valid_from:
            errors.append(_error("config_not_yet_valid", "config.valid_from", str(valid_from)))
        if type(valid_until) is int and evaluation_tick >= valid_until:
            errors.append(_error("config_expired", "config.valid_until", str(valid_until)))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "config": config}


def load_policy_with_external_head_quorum(
    policy_store: SQLiteAnchorQuorumPolicyStore,
    signed_responses: Sequence[Mapping[str, Any]],
    *,
    authority_registry: TrustKeyRegistry,
    quorum_config: Mapping[str, Any],
    expected_config_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    max_response_age: int = 5,
) -> dict[str, Any]:
    if not _is_sha256(expected_config_sha256):
        raise PolicyHeadAuthorityError("invalid_expected_quorum_config_digest", str(expected_config_sha256))
    validated_config = validate_policy_head_quorum_config(quorum_config, evaluation_tick)
    if validated_config["status"] != "PASS":
        raise PolicyHeadAuthorityError("invalid_policy_head_quorum_config", str(validated_config["errors"]))
    config = validated_config["config"]
    if config["config_sha256"] != expected_config_sha256:
        raise PolicyHeadAuthorityError("policy_head_quorum_config_substitution", config["config_sha256"])
    if type(max_response_age) is not int or max_response_age < 0:
        raise PolicyHeadAuthorityError("invalid_max_response_age", str(max_response_age))

    challenge_record = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    authorities = {item["signer_id"]: item for item in config["authorities"]}
    valid_by_statement: dict[tuple[Any, ...], list[dict[str, str]]] = defaultdict(list)
    seen_signers: dict[str, tuple[Any, ...]] = {}
    seen_keys: set[str] = set()
    invalid_rows: list[dict[str, Any]] = []

    for index, signed in enumerate(signed_responses):
        verified = verify_contract_envelope(
            signed,
            registry=authority_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_POLICY_HEAD_AUTHORITY,
            expected_digest_field="response_sha256",
            expected_inner_contract_id=POLICY_HEAD_RESPONSE_CONTRACT_ID,
        )
        if verified["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "signature", "errors": verified["errors"]})
            continue
        signer = verified["verified_signer"]
        assert signer is not None
        authority = authorities.get(signer.signer_id)
        if authority is None:
            invalid_rows.append({"index": index, "reason": "signer_not_in_config", "signer_id": signer.signer_id})
            continue
        if signer.key_id != authority["key_id"]:
            invalid_rows.append({"index": index, "reason": "key_mismatch", "signer_id": signer.signer_id})
            continue
        if signer.trust_domain != authority["trust_domain"]:
            invalid_rows.append({"index": index, "reason": "trust_domain_mismatch", "signer_id": signer.signer_id})
            continue
        validated = validate_policy_head_response(verified["inner_contract"], evaluation_tick)
        if validated["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "response", "errors": validated["errors"]})
            continue
        response = validated["response"]
        if response["authority_id"] != authority["authority_id"]:
            invalid_rows.append({"index": index, "reason": "authority_id_mismatch", "signer_id": signer.signer_id})
            continue
        if response["policy_id"] != config["policy_id"]:
            invalid_rows.append({"index": index, "reason": "policy_id_mismatch", "signer_id": signer.signer_id})
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
            response["policy_version"],
            response["policy_sha256"],
            response["verifier_id"],
            response["verifier_epoch_sha256"],
            response["challenge_sha256"],
            response["requested_at"],
        )
        previous = seen_signers.get(signer.signer_id)
        if previous is not None:
            if previous != statement:
                raise PolicyHeadAuthorityError("policy_head_signer_equivocation", signer.signer_id)
            continue
        if signer.key_id in seen_keys:
            raise PolicyHeadAuthorityError("duplicate_policy_head_key", signer.key_id)
        seen_signers[signer.signer_id] = statement
        seen_keys.add(signer.key_id)
        valid_by_statement[statement].append(
            {
                "authority_id": authority["authority_id"],
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
            and len({item["authority_id"] for item in members}) >= threshold
            and len({item["signer_id"] for item in members}) >= threshold
            and len({item["key_id"] for item in members}) >= threshold
            and len({item["trust_domain"] for item in members}) >= threshold
        ):
            quorum_groups.append((statement, members))
    if not quorum_groups:
        raise PolicyHeadAuthorityError(
            "policy_head_quorum_not_met",
            f"threshold={threshold} valid_signers={len(seen_signers)} invalid={len(invalid_rows)}",
        )
    if len(quorum_groups) > 1:
        raise PolicyHeadAuthorityError("multiple_policy_head_quorums", str(len(quorum_groups)))

    statement, members = quorum_groups[0]
    _, remote_version, remote_digest, *_ = statement
    local = policy_store.load_current(evaluation_tick)
    if local["policy_id"] != config["policy_id"]:
        raise PolicyHeadAuthorityError("local_policy_id_mismatch", local["policy_id"])
    if local["policy_version"] < remote_version:
        raise PolicyHeadAuthorityError("local_policy_rollback", f"local={local['policy_version']} quorum={remote_version}")
    if local["policy_version"] > remote_version:
        raise PolicyHeadAuthorityError("stale_policy_head_quorum", f"local={local['policy_version']} quorum={remote_version}")
    if local["policy_sha256"] != remote_digest:
        raise PolicyHeadAuthorityError("local_policy_fork", "version matches but digest differs")
    if remote_version < config["minimum_policy_version"]:
        raise PolicyHeadAuthorityError(
            "minimum_policy_version_not_met",
            f"head={remote_version} minimum={config['minimum_policy_version']}",
        )
    minimum_digest = config["minimum_policy_sha256"]
    if minimum_digest is not None and remote_digest != minimum_digest:
        raise PolicyHeadAuthorityError("minimum_policy_digest_not_met", str(remote_digest))
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "policy": local,
        "quorum": {
            "config_id": config["config_id"],
            "config_sha256": config["config_sha256"],
            "authority_set_id": config["authority_set_id"],
            "threshold": threshold,
            "members": sorted(members, key=lambda item: item["signer_id"]),
        },
    }


__all__ = [
    "POLICY_HEAD_QUORUM_CONFIG_CONTRACT_ID",
    "load_policy_with_external_head_quorum",
    "make_policy_head_quorum_config",
    "validate_policy_head_quorum_config",
]
