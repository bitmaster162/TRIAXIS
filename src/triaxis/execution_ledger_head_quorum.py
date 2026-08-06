"""TRIAXIS v3.29 independent execution-ledger head quorum.

v3.28 relies on one external monotonic head authority.  This module requires an
operator-pinned threshold of distinct authority identities, signing keys and
trust domains to make the same fresh challenge-bound statement about the exact
execution-ledger head.  It also composes that quorum with provider and external
completion-witness preflight evidence.

A quorum witness is evidence only.  It does not grant or widen action authority.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .crypto_trust import (
    PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
    PURPOSE_EXECUTION_LEDGER_HEAD_QUORUM,
    PURPOSE_EXECUTION_RECEIPT,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .execution_ledger_head_authority import EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID
from .external_completion_witness import (
    CompletionWitnessError,
    verify_external_completion_witness_status,
)
from .external_execution_ledger import (
    EXECUTION_LEDGER_HEAD_CONTRACT_ID,
    SQLiteExternalExecutionLedger,
    verify_external_effect_guard,
)
from .idempotent_effect_provider import ProviderEffectError, verify_provider_effect_status
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_CONTRACT_ID = "TRIAXIS_EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_v1"
EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID = "TRIAXIS_EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_v1"


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


class ExecutionLedgerHeadQuorumError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def make_execution_ledger_head_quorum_config(
    *,
    config_id: str,
    authority_set_id: str,
    ledger_id: str,
    threshold: int,
    authorities: Sequence[Mapping[str, str]],
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    rows: list[dict[str, str]] = []
    for authority in authorities:
        rows.append(
            {
                field: str(authority[field])
                for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")
            }
        )
    rows.sort(key=lambda row: (row["signer_id"], row["key_id"]))
    return seal_mapping(
        {
            "contract_id": EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_CONTRACT_ID,
            "config_id": config_id,
            "authority_set_id": authority_set_id,
            "ledger_id": ledger_id,
            "threshold": threshold,
            "authorities": rows,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "config_sha256": "",
        },
        "config_sha256",
    )


def validate_execution_ledger_head_quorum_config(
    value: Any,
    evaluation_tick: int | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {
            "status": "BLOCK",
            "errors": [{"code": "invalid_type", "path": "config", "message": "mapping required"}],
        }
    try:
        config = materialize_json(value)
    except Exception as exc:
        return {
            "status": "BLOCK",
            "errors": [
                {"code": "materialization_failed", "path": "config", "message": type(exc).__name__}
            ],
        }
    if not isinstance(config, dict):
        return {
            "status": "BLOCK",
            "errors": [{"code": "invalid_type", "path": "config", "message": "object required"}],
        }
    if config.get("contract_id") != EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_CONTRACT_ID:
        errors.append(
            {
                "code": "invalid_contract_id",
                "path": "config.contract_id",
                "message": EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_CONTRACT_ID,
            }
        )
    if not verify_sealed_mapping(config, "config_sha256"):
        errors.append(
            {
                "code": "digest_mismatch",
                "path": "config.config_sha256",
                "message": "canonical digest mismatch",
            }
        )
    for field in ("config_id", "authority_set_id", "ledger_id"):
        if not isinstance(config.get(field), str) or not config[field]:
            errors.append(
                {
                    "code": f"invalid_{field}",
                    "path": f"config.{field}",
                    "message": "non-empty string required",
                }
            )
    threshold = config.get("threshold")
    if type(threshold) is not int or threshold < 2:
        errors.append(
            {
                "code": "invalid_threshold",
                "path": "config.threshold",
                "message": "integer >= 2 required",
            }
        )
    rows = config.get("authorities")
    if not isinstance(rows, list) or not rows:
        rows = []
        errors.append(
            {
                "code": "invalid_authorities",
                "path": "config.authorities",
                "message": "non-empty array required",
            }
        )
    seen = {field: set() for field in ("authority_id", "service_id", "signer_id", "key_id")}
    domains: set[Any] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(
                {
                    "code": "invalid_authority",
                    "path": f"config.authorities[{index}]",
                    "message": "object required",
                }
            )
            continue
        for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain"):
            item = row.get(field)
            if not isinstance(item, str) or not item:
                errors.append(
                    {
                        "code": f"invalid_{field}",
                        "path": f"config.authorities[{index}].{field}",
                        "message": "non-empty string required",
                    }
                )
        for field, values in seen.items():
            item = row.get(field)
            if item in values:
                errors.append(
                    {
                        "code": f"duplicate_{field}",
                        "path": f"config.authorities[{index}].{field}",
                        "message": str(item),
                    }
                )
            values.add(item)
        domains.add(row.get("trust_domain"))
    if type(threshold) is int and len(rows) < threshold:
        errors.append(
            {
                "code": "threshold_exceeds_members",
                "path": "config.threshold",
                "message": str(threshold),
            }
        )
    if type(threshold) is int and len(domains) < threshold:
        errors.append(
            {
                "code": "insufficient_domain_diversity",
                "path": "config.authorities",
                "message": str(len(domains)),
            }
        )
    valid_from, valid_until = config.get("valid_from"), config.get("valid_until")
    if (
        type(valid_from) is not int
        or type(valid_until) is not int
        or valid_from < 0
        or valid_until <= valid_from
    ):
        errors.append(
            {
                "code": "invalid_validity_window",
                "path": "config",
                "message": "valid_from < valid_until required",
            }
        )
    if (
        evaluation_tick is not None
        and type(valid_from) is int
        and type(valid_until) is int
        and not (valid_from <= evaluation_tick < valid_until)
    ):
        errors.append(
            {
                "code": "config_not_current",
                "path": "config",
                "message": str(evaluation_tick),
            }
        )
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "config": config}


def _verify_local_head(
    signed_local_head: Mapping[str, Any],
    *,
    ledger_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    evaluation_tick: int,
) -> dict[str, Any]:
    result = verify_contract_envelope(
        signed_local_head,
        registry=ledger_registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_RECEIPT,
        expected_digest_field="head_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_HEAD_CONTRACT_ID,
        expected_signer_id=expected_ledger_signer_id,
        expected_trust_domain=expected_ledger_trust_domain,
    )
    if result["status"] != "PASS":
        raise ExecutionLedgerHeadQuorumError("invalid_local_ledger_head_signature", str(result["errors"]))
    head = result["inner_contract"]
    if not isinstance(head, dict):
        raise ExecutionLedgerHeadQuorumError("invalid_local_ledger_head", "object required")
    if head.get("ledger_id") != expected_ledger_id:
        raise ExecutionLedgerHeadQuorumError("execution_ledger_id_mismatch", str(head.get("ledger_id")))
    if head.get("authority_id") != expected_ledger_authority_id:
        raise ExecutionLedgerHeadQuorumError(
            "execution_ledger_authority_mismatch", str(head.get("authority_id"))
        )
    if type(head.get("sequence")) is not int or head["sequence"] < 0:
        raise ExecutionLedgerHeadQuorumError("invalid_local_ledger_sequence", str(head.get("sequence")))
    for field in ("head_event_sha256", "state_root_sha256", "head_sha256"):
        if not _is_sha256(head.get(field)):
            raise ExecutionLedgerHeadQuorumError("invalid_local_ledger_digest", field)
    return head


def verify_execution_ledger_head_quorum(
    signed_local_head: Mapping[str, Any],
    signed_head_responses: Sequence[Mapping[str, Any]],
    *,
    ledger_registry: TrustKeyRegistry,
    authority_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    max_response_age: int = 5,
) -> dict[str, Any]:
    """Require one exact statement from a distinct 2-of-N or higher quorum."""
    if type(evaluation_tick) is not int or evaluation_tick < 0:
        raise ExecutionLedgerHeadQuorumError("invalid_evaluation_tick", str(evaluation_tick))
    if type(max_response_age) is not int or max_response_age < 0:
        raise ExecutionLedgerHeadQuorumError("invalid_max_response_age", str(max_response_age))
    config_result = validate_execution_ledger_head_quorum_config(quorum_config, evaluation_tick)
    if config_result["status"] != "PASS":
        raise ExecutionLedgerHeadQuorumError(
            "invalid_execution_head_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if config["config_sha256"] != expected_quorum_config_sha256:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_config_substitution", config["config_sha256"]
        )
    if config["ledger_id"] != expected_ledger_id:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_ledger_mismatch", config["ledger_id"]
        )
    if not isinstance(signed_head_responses, Sequence) or isinstance(
        signed_head_responses, (str, bytes)
    ):
        raise ExecutionLedgerHeadQuorumError("invalid_head_responses", "sequence required")
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    local_head = _verify_local_head(
        signed_local_head,
        ledger_registry=ledger_registry,
        expected_ledger_id=expected_ledger_id,
        expected_ledger_authority_id=expected_ledger_authority_id,
        expected_ledger_signer_id=expected_ledger_signer_id,
        expected_ledger_trust_domain=expected_ledger_trust_domain,
        evaluation_tick=evaluation_tick,
    )
    members = {row["signer_id"]: row for row in config["authorities"]}
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    seen_signers: dict[str, tuple[Any, ...]] = {}
    seen_keys: set[str] = set()
    invalid_rows: list[dict[str, Any]] = []

    for index, signed in enumerate(signed_head_responses):
        verified = verify_contract_envelope(
            signed,
            registry=authority_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_EXECUTION_LEDGER_HEAD_AUTHORITY,
            expected_digest_field="response_sha256",
            expected_inner_contract_id=EXECUTION_LEDGER_HEAD_RESPONSE_CONTRACT_ID,
        )
        if verified["status"] != "PASS":
            invalid_rows.append({"index": index, "reason": "signature", "errors": verified["errors"]})
            continue
        signer = verified["verified_signer"]
        if signer is None:
            invalid_rows.append({"index": index, "reason": "missing_signer"})
            continue
        member = members.get(signer.signer_id)
        if (
            member is None
            or signer.key_id != member["key_id"]
            or signer.trust_domain != member["trust_domain"]
        ):
            invalid_rows.append(
                {"index": index, "reason": "identity", "signer_id": signer.signer_id}
            )
            continue
        response = verified["inner_contract"]
        if not isinstance(response, dict):
            invalid_rows.append({"index": index, "reason": "response_type"})
            continue
        if (
            response.get("authority_id") != member["authority_id"]
            or response.get("service_id") != member["service_id"]
            or response.get("ledger_id") != expected_ledger_id
            or response.get("ledger_authority_id") != expected_ledger_authority_id
        ):
            invalid_rows.append(
                {"index": index, "reason": "binding", "signer_id": signer.signer_id}
            )
            continue
        if (
            response.get("verifier_id") != challenge_ledger.session.verifier_id
            or response.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
            or response.get("challenge_sha256") != challenge["challenge_sha256"]
            or response.get("requested_at") != challenge["issued_at"]
        ):
            invalid_rows.append(
                {"index": index, "reason": "challenge", "signer_id": signer.signer_id}
            )
            continue
        issued_at = response.get("issued_at")
        if (
            type(issued_at) is not int
            or issued_at > evaluation_tick
            or evaluation_tick - issued_at > max_response_age
        ):
            invalid_rows.append(
                {"index": index, "reason": "age", "signer_id": signer.signer_id}
            )
            continue
        statement = (
            response.get("ledger_sequence"),
            response.get("ledger_head_event_sha256"),
            response.get("ledger_state_root_sha256"),
            response.get("ledger_head_sha256"),
            response.get("verifier_id"),
            response.get("verifier_epoch_sha256"),
            response.get("challenge_sha256"),
            response.get("requested_at"),
        )
        if type(statement[0]) is not int or statement[0] < 0 or not all(
            _is_sha256(statement[pos]) for pos in (1, 2, 3, 5, 6)
        ):
            invalid_rows.append(
                {"index": index, "reason": "statement", "signer_id": signer.signer_id}
            )
            continue
        previous = seen_signers.get(signer.signer_id)
        if previous is not None:
            if previous != statement:
                raise ExecutionLedgerHeadQuorumError(
                    "execution_head_authority_equivocation", signer.signer_id
                )
            continue
        if signer.key_id in seen_keys:
            raise ExecutionLedgerHeadQuorumError(
                "duplicate_execution_head_authority_key", signer.key_id
            )
        seen_signers[signer.signer_id] = statement
        seen_keys.add(signer.key_id)
        vote = materialize_json(member)
        vote.update(
            {
                "response_sha256": response["response_sha256"],
                "response_issued_at": response["issued_at"],
                "response_valid_until": response["valid_until"],
                "authority_accepted_at_tick": response["accepted_at_tick"],
            }
        )
        groups[statement].append(vote)

    threshold = config["threshold"]
    quorums: list[tuple[tuple[Any, ...], list[dict[str, Any]]]] = []
    for statement, rows in groups.items():
        if len(rows) < threshold:
            continue
        if all(
            len({row[field] for row in rows}) >= threshold
            for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")
        ):
            quorums.append((statement, rows))
    if not quorums:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_authority_quorum_not_met",
            f"threshold={threshold} valid={len(seen_signers)} invalid={len(invalid_rows)}",
        )
    if len(quorums) > 1:
        raise ExecutionLedgerHeadQuorumError(
            "multiple_execution_head_authority_quorums", str(len(quorums))
        )
    statement, rows = quorums[0]
    for local_field, observed in (
        ("sequence", statement[0]),
        ("head_event_sha256", statement[1]),
        ("state_root_sha256", statement[2]),
    ):
        if local_head[local_field] != observed:
            raise ExecutionLedgerHeadQuorumError(
                "execution_ledger_rollback_or_fork_detected", local_field
            )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    member_rows = sorted(
        [materialize_json(row) for row in rows], key=lambda row: (row["signer_id"], row["key_id"])
    )
    witness = seal_mapping(
        {
            "contract_id": EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID,
            "config_id": config["config_id"],
            "config_sha256": config["config_sha256"],
            "authority_set_id": config["authority_set_id"],
            "ledger_id": expected_ledger_id,
            "ledger_authority_id": expected_ledger_authority_id,
            "ledger_sequence": statement[0],
            "ledger_head_event_sha256": statement[1],
            "ledger_state_root_sha256": statement[2],
            "authority_ledger_head_sha256": statement[3],
            "threshold": threshold,
            "member_count": len(member_rows),
            "members": member_rows,
            "verifier_id": challenge_ledger.session.verifier_id,
            "verifier_epoch_sha256": challenge_ledger.session.epoch_sha256,
            "challenge_sha256": challenge["challenge_sha256"],
            "requested_at": challenge["issued_at"],
            "evaluated_at": evaluation_tick,
            "authority_granted": False,
            "witness_sha256": "",
        },
        "witness_sha256",
    )
    return {
        "status": "PASS",
        "local_head": local_head,
        "quorum_witness": witness,
        "invalid_rows": invalid_rows,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def sign_execution_ledger_head_quorum_witness(
    witness: Mapping[str, Any],
    *,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    private_key_b64: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    if not isinstance(witness, Mapping) or witness.get("contract_id") != EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID:
        raise ExecutionLedgerHeadQuorumError("invalid_quorum_witness", "unexpected contract")
    if not verify_sealed_mapping(witness, "witness_sha256"):
        raise ExecutionLedgerHeadQuorumError("invalid_quorum_witness", "digest mismatch")
    return sign_contract_envelope(
        witness,
        digest_field="witness_sha256",
        purpose=PURPOSE_EXECUTION_LEDGER_HEAD_QUORUM,
        key_id=key_id,
        signer_id=signer_id,
        trust_domain=trust_domain,
        private_key_b64=private_key_b64,
        issued_at=issued_at,
        valid_until=valid_until,
    )


def verify_execution_ledger_head_quorum_witness(
    signed_witness: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_signer_id: str,
    expected_trust_domain: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    evaluation_tick: int,
    expected_verifier_id: str | None = None,
    expected_verifier_epoch_sha256: str | None = None,
    max_witness_age: int = 30,
) -> dict[str, Any]:
    if type(max_witness_age) is not int or max_witness_age < 0:
        raise ExecutionLedgerHeadQuorumError("invalid_max_witness_age", str(max_witness_age))
    verified = verify_contract_envelope(
        signed_witness,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_EXECUTION_LEDGER_HEAD_QUORUM,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise ExecutionLedgerHeadQuorumError(
            "invalid_execution_head_quorum_witness_signature", str(verified["errors"])
        )
    witness = verified["inner_contract"]
    envelope = verified["envelope"]
    if not isinstance(witness, dict) or not isinstance(envelope, dict):
        raise ExecutionLedgerHeadQuorumError("invalid_quorum_witness", "object required")
    evaluated_at = witness.get("evaluated_at")
    if type(evaluated_at) is not int or evaluated_at < 0:
        raise ExecutionLedgerHeadQuorumError("invalid_quorum_witness_time", str(evaluated_at))
    if (
        evaluated_at > envelope.get("issued_at", -1)
        or evaluated_at > evaluation_tick
        or evaluation_tick - evaluated_at > max_witness_age
    ):
        raise ExecutionLedgerHeadQuorumError("execution_head_quorum_witness_not_fresh", str(evaluated_at))
    config_result = validate_execution_ledger_head_quorum_config(quorum_config, evaluated_at)
    if config_result["status"] != "PASS":
        raise ExecutionLedgerHeadQuorumError(
            "invalid_execution_head_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if (
        config["config_sha256"] != expected_quorum_config_sha256
        or witness.get("config_sha256") != expected_quorum_config_sha256
    ):
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_config_substitution", str(witness.get("config_sha256"))
        )
    for field in ("config_id", "authority_set_id"):
        if witness.get(field) != config[field]:
            raise ExecutionLedgerHeadQuorumError(
                "execution_head_quorum_config_binding_mismatch", field
            )
    if witness.get("ledger_id") != expected_ledger_id or config["ledger_id"] != expected_ledger_id:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_ledger_mismatch", str(witness.get("ledger_id"))
        )
    if witness.get("ledger_authority_id") != expected_ledger_authority_id:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_ledger_authority_mismatch",
            str(witness.get("ledger_authority_id")),
        )
    if type(witness.get("ledger_sequence")) is not int or witness["ledger_sequence"] < 0:
        raise ExecutionLedgerHeadQuorumError(
            "invalid_execution_head_quorum_sequence", str(witness.get("ledger_sequence"))
        )
    for field in (
        "ledger_head_event_sha256",
        "ledger_state_root_sha256",
        "authority_ledger_head_sha256",
        "verifier_epoch_sha256",
        "challenge_sha256",
        "witness_sha256",
    ):
        if not _is_sha256(witness.get(field)):
            raise ExecutionLedgerHeadQuorumError(
                "invalid_execution_head_quorum_digest", f"{field}={witness.get(field)}"
            )
    for field in ("verifier_id",):
        if not isinstance(witness.get(field), str) or not witness[field]:
            raise ExecutionLedgerHeadQuorumError(
                "invalid_execution_head_quorum_field", field
            )
    if expected_verifier_id is not None and witness["verifier_id"] != expected_verifier_id:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_verifier_mismatch", witness["verifier_id"]
        )
    if (
        expected_verifier_epoch_sha256 is not None
        and witness["verifier_epoch_sha256"] != expected_verifier_epoch_sha256
    ):
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_verifier_epoch_mismatch", witness["verifier_epoch_sha256"]
        )
    requested_at = witness.get("requested_at")
    if type(requested_at) is not int or requested_at < 0 or requested_at > evaluated_at:
        raise ExecutionLedgerHeadQuorumError(
            "invalid_execution_head_quorum_request_time", str(requested_at)
        )
    if witness.get("authority_granted") is not False:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_authority_escalation", str(witness.get("authority_granted"))
        )
    threshold = witness.get("threshold")
    members = witness.get("members")
    if threshold != config["threshold"] or type(threshold) is not int or threshold < 2:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_threshold_mismatch", str(threshold)
        )
    if not isinstance(members, list) or witness.get("member_count") != len(members) or len(members) < threshold:
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_member_count_mismatch", str(witness.get("member_count"))
        )
    configured = {row["signer_id"]: row for row in config["authorities"]}
    seen = {field: set() for field in ("authority_id", "service_id", "signer_id", "key_id", "trust_domain")}
    for index, member in enumerate(members):
        if not isinstance(member, dict):
            raise ExecutionLedgerHeadQuorumError(
                "invalid_execution_head_quorum_member", str(index)
            )
        pinned = configured.get(member.get("signer_id"))
        if pinned is None or any(member.get(field) != pinned[field] for field in seen):
            raise ExecutionLedgerHeadQuorumError(
                "execution_head_quorum_member_not_pinned", str(member.get("signer_id"))
            )
        for field, values in seen.items():
            if member[field] in values:
                raise ExecutionLedgerHeadQuorumError(
                    f"duplicate_execution_head_quorum_{field}", str(member[field])
                )
            values.add(member[field])
        if not _is_sha256(member.get("response_sha256")):
            raise ExecutionLedgerHeadQuorumError(
                "invalid_execution_head_quorum_response_digest", str(member.get("response_sha256"))
            )
        response_issued = member.get("response_issued_at")
        response_until = member.get("response_valid_until")
        accepted_at = member.get("authority_accepted_at_tick")
        if (
            type(response_issued) is not int
            or type(response_until) is not int
            or type(accepted_at) is not int
            or accepted_at < 0
            or accepted_at > response_issued
            or response_issued > evaluated_at
            or evaluated_at >= response_until
        ):
            raise ExecutionLedgerHeadQuorumError(
                "invalid_execution_head_quorum_response_time", str(member.get("signer_id"))
            )
    if any(len(values) < threshold for values in seen.values()):
        raise ExecutionLedgerHeadQuorumError(
            "execution_head_quorum_independence_not_met", str(threshold)
        )
    return {
        "status": "PASS",
        "quorum_witness": witness,
        "verified_member_count": len(members),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def reserve_with_external_head_quorum(
    ledger: SQLiteExternalExecutionLedger,
    intent: Mapping[str, Any],
    *,
    attempt_id: str,
    dispatch_id: str,
    now_tick: int,
    signed_local_head: Mapping[str, Any],
    signed_head_responses: Sequence[Mapping[str, Any]],
    ledger_registry: TrustKeyRegistry,
    authority_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
) -> dict[str, Any]:
    freshness = verify_execution_ledger_head_quorum(
        signed_local_head,
        signed_head_responses,
        ledger_registry=ledger_registry,
        authority_registry=authority_registry,
        expected_ledger_id=expected_ledger_id,
        expected_ledger_authority_id=expected_ledger_authority_id,
        expected_ledger_signer_id=expected_ledger_signer_id,
        expected_ledger_trust_domain=expected_ledger_trust_domain,
        quorum_config=quorum_config,
        expected_quorum_config_sha256=expected_quorum_config_sha256,
        challenge_ledger=challenge_ledger,
        expected_challenge=expected_challenge,
        evaluation_tick=now_tick,
    )
    reservation = ledger.reserve(
        intent,
        attempt_id=attempt_id,
        dispatch_id=dispatch_id,
        now_tick=now_tick,
    )
    return {"status": reservation["status"], "quorum_guard": freshness, "reservation": reservation}


def verify_external_effect_guard_with_head_quorum_and_completion_witness(
    intent: Mapping[str, Any],
    signed_in_flight_receipt: Mapping[str, Any],
    *,
    expected_attempt_id: str,
    expected_dispatch_id: str,
    evaluation_tick: int,
    signed_local_head: Mapping[str, Any],
    signed_head_responses: Sequence[Mapping[str, Any]],
    ledger_registry: TrustKeyRegistry,
    head_authority_registry: TrustKeyRegistry,
    expected_ledger_id: str,
    expected_ledger_authority_id: str,
    expected_ledger_signer_id: str,
    expected_ledger_trust_domain: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    head_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_head_challenge: str,
    signed_provider_status: Mapping[str, Any],
    provider_registry: TrustKeyRegistry,
    expected_provider_id: str,
    expected_provider_service_id: str,
    expected_provider_signer_id: str,
    expected_provider_trust_domain: str,
    expected_provider_payload_sha256: str,
    provider_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_provider_challenge: str,
    signed_completion_witness_status: Mapping[str, Any],
    completion_witness_registry: TrustKeyRegistry,
    expected_completion_witness_id: str,
    expected_completion_witness_authority_id: str,
    expected_completion_witness_service_id: str,
    expected_completion_witness_signer_id: str,
    expected_completion_witness_trust_domain: str,
    completion_witness_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_completion_witness_challenge: str,
) -> dict[str, Any]:
    receipt_guard = verify_external_effect_guard(
        intent,
        signed_in_flight_receipt,
        registry=ledger_registry,
        evaluation_tick=evaluation_tick,
        expected_ledger_id=expected_ledger_id,
        expected_authority_id=expected_ledger_authority_id,
        expected_signer_id=expected_ledger_signer_id,
        expected_trust_domain=expected_ledger_trust_domain,
        expected_attempt_id=expected_attempt_id,
        expected_dispatch_id=expected_dispatch_id,
    )
    if receipt_guard["status"] != "PASS":
        return {
            "status": "BLOCK",
            "errors": receipt_guard["errors"],
            "authority_granted": False,
            "required_separate_authorization": True,
        }
    effect_id = receipt_guard["event"]["effect_id"]
    try:
        quorum_guard = verify_execution_ledger_head_quorum(
            signed_local_head,
            signed_head_responses,
            ledger_registry=ledger_registry,
            authority_registry=head_authority_registry,
            expected_ledger_id=expected_ledger_id,
            expected_ledger_authority_id=expected_ledger_authority_id,
            expected_ledger_signer_id=expected_ledger_signer_id,
            expected_ledger_trust_domain=expected_ledger_trust_domain,
            quorum_config=quorum_config,
            expected_quorum_config_sha256=expected_quorum_config_sha256,
            challenge_ledger=head_challenge_ledger,
            expected_challenge=expected_head_challenge,
            evaluation_tick=evaluation_tick,
        )
        provider_guard = verify_provider_effect_status(
            signed_provider_status,
            registry=provider_registry,
            expected_provider_id=expected_provider_id,
            expected_service_id=expected_provider_service_id,
            expected_signer_id=expected_provider_signer_id,
            expected_trust_domain=expected_provider_trust_domain,
            expected_effect_id=effect_id,
            expected_payload_sha256=expected_provider_payload_sha256,
            challenge_ledger=provider_challenge_ledger,
            expected_challenge=expected_provider_challenge,
            evaluation_tick=evaluation_tick,
        )
        completion_guard = verify_external_completion_witness_status(
            signed_completion_witness_status,
            registry=completion_witness_registry,
            expected_witness_id=expected_completion_witness_id,
            expected_authority_id=expected_completion_witness_authority_id,
            expected_service_id=expected_completion_witness_service_id,
            expected_signer_id=expected_completion_witness_signer_id,
            expected_trust_domain=expected_completion_witness_trust_domain,
            expected_effect_id=effect_id,
            expected_payload_sha256=expected_provider_payload_sha256,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            challenge_ledger=completion_witness_challenge_ledger,
            expected_challenge=expected_completion_witness_challenge,
            evaluation_tick=evaluation_tick,
        )
    except (ExecutionLedgerHeadQuorumError, ProviderEffectError, CompletionWitnessError) as exc:
        return {
            "status": "BLOCK",
            "errors": [{"code": exc.code, "path": "external_effect_preflight", "message": exc.detail}],
            "authority_granted": False,
            "required_separate_authorization": True,
        }
    return {
        "status": "PASS",
        "errors": [],
        "receipt_guard": receipt_guard,
        "quorum_guard": quorum_guard,
        "provider_guard": provider_guard,
        "completion_witness_guard": completion_guard,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "EXECUTION_LEDGER_HEAD_QUORUM_CONFIG_CONTRACT_ID",
    "EXECUTION_LEDGER_HEAD_QUORUM_WITNESS_CONTRACT_ID",
    "ExecutionLedgerHeadQuorumError",
    "make_execution_ledger_head_quorum_config",
    "reserve_with_external_head_quorum",
    "sign_execution_ledger_head_quorum_witness",
    "validate_execution_ledger_head_quorum_config",
    "verify_execution_ledger_head_quorum",
    "verify_execution_ledger_head_quorum_witness",
    "verify_external_effect_guard_with_head_quorum_and_completion_witness",
]
