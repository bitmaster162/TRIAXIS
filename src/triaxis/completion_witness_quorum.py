"""TRIAXIS v3.30 independent completion-witness quorum.

A single external completion witness can be rolled back together with the
provider and a threshold of execution-head authorities.  This module requires
an operator-pinned threshold of distinct completion-witness authorities to make
one fresh, challenge-bound statement about a stable effect.

The verifier deliberately applies a blocking-minority veto: any valid configured
witness that reports ``RESERVED``, ``UNKNOWN`` or ``COMPLETED`` blocks retry even
when a permissive threshold could otherwise be assembled.  Omission of an
unavailable witness remains outside the claim.

Quorum evidence never grants or widens action authority.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .crypto_trust import (
    PURPOSE_COMPLETION_WITNESS_QUORUM,
    PURPOSE_EXTERNAL_COMPLETION_WITNESS,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_PROVIDER_EFFECT_RECEIPT,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .execution_ledger_head_quorum import (
    ExecutionLedgerHeadQuorumError,
    verify_execution_ledger_head_quorum,
)
from .external_completion_witness import (
    COMPLETION_WITNESS_BLOCKING_STATES,
    COMPLETION_WITNESS_STATUS_CONTRACT_ID,
    COMPLETION_WITNESS_STATES,
    CompletionWitnessError,
)
from .external_execution_ledger import verify_external_effect_guard
from .idempotent_effect_provider import ProviderEffectError, verify_provider_effect_status
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_WITNESS_QUORUM_CONFIG_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_WITNESS_QUORUM_CONFIG_v1"
)
COMPLETION_WITNESS_QUORUM_WITNESS_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_WITNESS_QUORUM_WITNESS_v1"
)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


class CompletionWitnessQuorumError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def make_completion_witness_quorum_config(
    *,
    config_id: str,
    witness_set_id: str,
    provider_id: str,
    provider_service_id: str,
    threshold: int,
    witnesses: Sequence[Mapping[str, str]],
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    rows = [
        {
            field: str(item[field])
            for field in (
                "witness_id",
                "authority_id",
                "service_id",
                "signer_id",
                "key_id",
                "trust_domain",
            )
        }
        for item in witnesses
    ]
    rows.sort(key=lambda item: (item["signer_id"], item["key_id"]))
    return seal_mapping(
        {
            "contract_id": COMPLETION_WITNESS_QUORUM_CONFIG_CONTRACT_ID,
            "config_id": config_id,
            "witness_set_id": witness_set_id,
            "provider_id": provider_id,
            "provider_service_id": provider_service_id,
            "threshold": threshold,
            "witnesses": rows,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "config_sha256": "",
        },
        "config_sha256",
    )


def validate_completion_witness_quorum_config(
    value: Any,
    evaluation_tick: int | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {
            "status": "BLOCK",
            "errors": [
                {"code": "invalid_type", "path": "config", "message": "mapping required"}
            ],
        }
    try:
        config = materialize_json(value)
    except Exception as exc:
        return {
            "status": "BLOCK",
            "errors": [
                {
                    "code": "materialization_failed",
                    "path": "config",
                    "message": type(exc).__name__,
                }
            ],
        }
    if not isinstance(config, dict):
        return {
            "status": "BLOCK",
            "errors": [
                {"code": "invalid_type", "path": "config", "message": "object required"}
            ],
        }
    if config.get("contract_id") != COMPLETION_WITNESS_QUORUM_CONFIG_CONTRACT_ID:
        errors.append(
            {
                "code": "invalid_contract_id",
                "path": "config.contract_id",
                "message": COMPLETION_WITNESS_QUORUM_CONFIG_CONTRACT_ID,
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
    for field in ("config_id", "witness_set_id", "provider_id", "provider_service_id"):
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
    rows = config.get("witnesses")
    if not isinstance(rows, list) or not rows:
        rows = []
        errors.append(
            {
                "code": "invalid_witnesses",
                "path": "config.witnesses",
                "message": "non-empty array required",
            }
        )
    seen = {
        field: set()
        for field in ("witness_id", "authority_id", "service_id", "signer_id", "key_id")
    }
    domains: set[Any] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(
                {
                    "code": "invalid_witness",
                    "path": f"config.witnesses[{index}]",
                    "message": "object required",
                }
            )
            continue
        for field in (
            "witness_id",
            "authority_id",
            "service_id",
            "signer_id",
            "key_id",
            "trust_domain",
        ):
            item = row.get(field)
            if not isinstance(item, str) or not item:
                errors.append(
                    {
                        "code": f"invalid_{field}",
                        "path": f"config.witnesses[{index}].{field}",
                        "message": "non-empty string required",
                    }
                )
        for field, values in seen.items():
            item = row.get(field)
            if item in values:
                errors.append(
                    {
                        "code": f"duplicate_{field}",
                        "path": f"config.witnesses[{index}].{field}",
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
                "path": "config.witnesses",
                "message": str(len(domains)),
            }
        )
    valid_from = config.get("valid_from")
    valid_until = config.get("valid_until")
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


def _validate_status_contract(
    status: Mapping[str, Any],
    *,
    pinned: Mapping[str, str],
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    challenge: Mapping[str, Any],
    challenge_ledger: SQLiteEpochChallengeLedger,
    evaluation_tick: int,
    max_response_age: int,
) -> tuple[Any, ...]:
    for field in ("witness_id", "authority_id", "service_id"):
        if status.get(field) != pinned[field]:
            raise CompletionWitnessQuorumError(
                "completion_witness_identity_mismatch",
                f"{field}={status.get(field)}",
            )
    for field, expected in (
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
    ):
        if status.get(field) != expected:
            raise CompletionWitnessQuorumError(
                f"completion_witness_{field}_mismatch", str(status.get(field))
            )
    state = status.get("state")
    if state not in COMPLETION_WITNESS_STATES:
        raise CompletionWitnessQuorumError("invalid_completion_witness_state", str(state))
    generation = status.get("generation")
    if type(generation) is not int or generation < 0:
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_generation", str(generation)
        )
    provider_request_id = status.get("provider_request_id")
    provider_receipt_sha256 = status.get("provider_receipt_sha256")
    evidence_sha256 = status.get("evidence_sha256")
    updated_at_tick = status.get("updated_at_tick")
    if state == "ABSENT":
        if generation != 0 or any(
            item is not None
            for item in (
                provider_request_id,
                provider_receipt_sha256,
                evidence_sha256,
                updated_at_tick,
            )
        ):
            raise CompletionWitnessQuorumError(
                "invalid_absent_completion_witness_statement", str(pinned["witness_id"])
            )
    else:
        if generation < 1:
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_generation", str(generation)
            )
        if not isinstance(provider_request_id, str) or not provider_request_id:
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_provider_request_id", str(provider_request_id)
            )
        if type(updated_at_tick) is not int or updated_at_tick < 0:
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_updated_at", str(updated_at_tick)
            )
        if state in {"UNKNOWN", "COMPLETED", "NO_EFFECT"}:
            if not _is_sha256(provider_receipt_sha256):
                raise CompletionWitnessQuorumError(
                    "completion_witness_provider_receipt_required", str(provider_receipt_sha256)
                )
            if not _is_sha256(evidence_sha256):
                raise CompletionWitnessQuorumError(
                    "completion_witness_evidence_required", str(evidence_sha256)
                )
        elif provider_receipt_sha256 is not None or evidence_sha256 is not None:
            raise CompletionWitnessQuorumError(
                "completion_witness_reserved_evidence_conflict", str(pinned["witness_id"])
            )
    witness_sequence = status.get("witness_sequence")
    if type(witness_sequence) is not int or witness_sequence < 0:
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_sequence", str(witness_sequence)
        )
    for field in ("witness_head_event_sha256", "witness_state_root_sha256", "status_sha256"):
        if not _is_sha256(status.get(field)):
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_digest", f"{field}={status.get(field)}"
            )
    if (
        status.get("verifier_id") != challenge_ledger.session.verifier_id
        or status.get("verifier_epoch_sha256") != challenge_ledger.session.epoch_sha256
        or status.get("challenge_sha256") != challenge["challenge_sha256"]
        or status.get("requested_at") != challenge["issued_at"]
    ):
        raise CompletionWitnessQuorumError(
            "completion_witness_challenge_binding_mismatch", str(pinned["witness_id"])
        )
    issued_at = status.get("issued_at")
    valid_until = status.get("valid_until")
    if (
        type(issued_at) is not int
        or type(valid_until) is not int
        or issued_at < status["requested_at"]
        or issued_at > evaluation_tick
        or evaluation_tick >= valid_until
        or evaluation_tick - issued_at > max_response_age
    ):
        raise CompletionWitnessQuorumError(
            "completion_witness_response_not_fresh", str(pinned["witness_id"])
        )
    return (
        state,
        generation,
        provider_request_id,
        provider_receipt_sha256,
        evidence_sha256,
        updated_at_tick,
    )


def verify_completion_witness_quorum(
    signed_statuses: Sequence[Mapping[str, Any]],
    *,
    registry: TrustKeyRegistry,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
    max_response_age: int = 5,
    blocking_minority_veto: bool = True,
) -> dict[str, Any]:
    if not _is_sha256(expected_effect_id):
        raise CompletionWitnessQuorumError("invalid_effect_id", str(expected_effect_id))
    if not _is_sha256(expected_payload_sha256):
        raise CompletionWitnessQuorumError(
            "invalid_payload_sha256", str(expected_payload_sha256)
        )
    allowed = set(allowed_states)
    if not allowed or not allowed.issubset(COMPLETION_WITNESS_STATES):
        raise CompletionWitnessQuorumError(
            "invalid_allowed_completion_witness_states", str(tuple(allowed_states))
        )
    if type(max_response_age) is not int or max_response_age < 0:
        raise CompletionWitnessQuorumError(
            "invalid_max_response_age", str(max_response_age)
        )
    config_result = validate_completion_witness_quorum_config(
        quorum_config, evaluation_tick
    )
    if config_result["status"] != "PASS":
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if config["config_sha256"] != expected_quorum_config_sha256:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_config_substitution", config["config_sha256"]
        )
    if (
        config["provider_id"] != expected_provider_id
        or config["provider_service_id"] != expected_provider_service_id
    ):
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_provider_mismatch",
            f"{config['provider_id']}:{config['provider_service_id']}",
        )
    challenge = challenge_ledger.inspect_issued(expected_challenge, evaluation_tick)
    configured = {row["signer_id"]: row for row in config["witnesses"]}
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    seen_statements: dict[str, tuple[Any, ...]] = {}
    seen_keys: set[str] = set()
    valid_blocking: list[dict[str, Any]] = []
    invalid_count = 0

    for index, signed_status in enumerate(signed_statuses):
        verified = verify_contract_envelope(
            signed_status,
            registry=registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_EXTERNAL_COMPLETION_WITNESS,
            expected_digest_field="status_sha256",
            expected_inner_contract_id=COMPLETION_WITNESS_STATUS_CONTRACT_ID,
        )
        if verified["status"] != "PASS":
            invalid_count += 1
            continue
        signer = verified["verified_signer"]
        status = verified["inner_contract"]
        envelope = verified["envelope"]
        if signer is None or not isinstance(status, dict) or not isinstance(envelope, dict):
            invalid_count += 1
            continue
        pinned = configured.get(signer.signer_id)
        if (
            pinned is None
            or signer.key_id != pinned["key_id"]
            or signer.trust_domain != pinned["trust_domain"]
        ):
            invalid_count += 1
            continue
        try:
            statement = _validate_status_contract(
                status,
                pinned=pinned,
                expected_effect_id=expected_effect_id,
                expected_payload_sha256=expected_payload_sha256,
                expected_provider_id=expected_provider_id,
                expected_provider_service_id=expected_provider_service_id,
                challenge=challenge,
                challenge_ledger=challenge_ledger,
                evaluation_tick=evaluation_tick,
                max_response_age=max_response_age,
            )
        except CompletionWitnessQuorumError:
            invalid_count += 1
            continue
        if envelope.get("issued_at") != status["issued_at"] or envelope.get("valid_until") != status["valid_until"]:
            raise CompletionWitnessQuorumError(
                "completion_witness_envelope_time_binding_mismatch", signer.signer_id
            )
        previous = seen_statements.get(signer.signer_id)
        if previous is not None:
            if previous != statement:
                raise CompletionWitnessQuorumError(
                    "completion_witness_equivocation", signer.signer_id
                )
            continue
        if signer.key_id in seen_keys:
            raise CompletionWitnessQuorumError(
                "duplicate_completion_witness_key", signer.key_id
            )
        seen_statements[signer.signer_id] = statement
        seen_keys.add(signer.key_id)
        member = {
            "witness_id": pinned["witness_id"],
            "authority_id": pinned["authority_id"],
            "service_id": pinned["service_id"],
            "signer_id": pinned["signer_id"],
            "key_id": pinned["key_id"],
            "trust_domain": pinned["trust_domain"],
            "response_sha256": status["status_sha256"],
            "witness_sequence": status["witness_sequence"],
            "witness_head_event_sha256": status["witness_head_event_sha256"],
            "witness_state_root_sha256": status["witness_state_root_sha256"],
            "response_issued_at": status["issued_at"],
            "response_valid_until": status["valid_until"],
        }
        groups[statement].append(member)
        if status["state"] in COMPLETION_WITNESS_BLOCKING_STATES:
            valid_blocking.append(member | {"state": status["state"]})

    if blocking_minority_veto and valid_blocking:
        raise CompletionWitnessQuorumError(
            "blocking_completion_witness_minority",
            ",".join(
                f"{item['witness_id']}:{item['state']}" for item in sorted(
                    valid_blocking, key=lambda item: item["witness_id"]
                )
            ),
        )

    threshold = config["threshold"]
    quorums: list[tuple[tuple[Any, ...], list[dict[str, Any]]]] = []
    for statement, members in groups.items():
        if len(members) < threshold:
            continue
        if all(
            len({member[field] for member in members}) >= threshold
            for field in (
                "witness_id",
                "authority_id",
                "service_id",
                "signer_id",
                "key_id",
                "trust_domain",
            )
        ):
            quorums.append((statement, members))
    if not quorums:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_not_met",
            f"threshold={threshold} valid={len(seen_statements)} invalid={invalid_count}",
        )
    if len(quorums) > 1:
        raise CompletionWitnessQuorumError(
            "multiple_completion_witness_quorums", str(len(quorums))
        )
    statement, members = quorums[0]
    state, generation, provider_request_id, provider_receipt_sha256, evidence_sha256, updated_at_tick = statement
    if state not in allowed:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_state_blocks_retry", str(state)
        )
    members = sorted(members, key=lambda member: member["signer_id"])
    quorum_witness = seal_mapping(
        {
            "contract_id": COMPLETION_WITNESS_QUORUM_WITNESS_CONTRACT_ID,
            "config_id": config["config_id"],
            "config_sha256": config["config_sha256"],
            "witness_set_id": config["witness_set_id"],
            "effect_id": expected_effect_id,
            "payload_sha256": expected_payload_sha256,
            "provider_id": expected_provider_id,
            "provider_service_id": expected_provider_service_id,
            "state": state,
            "generation": generation,
            "provider_request_id": provider_request_id,
            "provider_receipt_sha256": provider_receipt_sha256,
            "evidence_sha256": evidence_sha256,
            "updated_at_tick": updated_at_tick,
            "threshold": threshold,
            "member_count": len(members),
            "members": members,
            "verifier_id": challenge_ledger.session.verifier_id,
            "verifier_epoch_sha256": challenge_ledger.session.epoch_sha256,
            "challenge_sha256": challenge["challenge_sha256"],
            "requested_at": challenge["issued_at"],
            "evaluated_at": evaluation_tick,
            "blocking_minority_veto": bool(blocking_minority_veto),
            "authority_granted": False,
            "witness_sha256": "",
        },
        "witness_sha256",
    )
    challenge_ledger.consume(expected_challenge, evaluation_tick)
    return {
        "status": "PASS",
        "quorum_witness": quorum_witness,
        "state": state,
        "generation": generation,
        "member_count": len(members),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def sign_completion_witness_quorum_witness(
    quorum_witness: Mapping[str, Any],
    *,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    private_key_b64: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    if not verify_sealed_mapping(quorum_witness, "witness_sha256"):
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_quorum_witness", "canonical digest mismatch"
        )
    return sign_contract_envelope(
        quorum_witness,
        digest_field="witness_sha256",
        purpose=PURPOSE_COMPLETION_WITNESS_QUORUM,
        key_id=key_id,
        signer_id=signer_id,
        trust_domain=trust_domain,
        private_key_b64=private_key_b64,
        issued_at=issued_at,
        valid_until=valid_until,
    )


def verify_completion_witness_quorum_witness(
    signed_witness: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_signer_id: str,
    expected_trust_domain: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
) -> dict[str, Any]:
    verified = verify_contract_envelope(
        signed_witness,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_WITNESS_QUORUM,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=COMPLETION_WITNESS_QUORUM_WITNESS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_quorum_signature", str(verified["errors"])
        )
    config_result = validate_completion_witness_quorum_config(
        quorum_config, evaluation_tick
    )
    if config_result["status"] != "PASS":
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if config["config_sha256"] != expected_quorum_config_sha256:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_config_substitution", config["config_sha256"]
        )
    witness = verified["inner_contract"]
    if not isinstance(witness, dict):
        raise CompletionWitnessQuorumError(
            "invalid_completion_witness_quorum_witness", "object required"
        )
    for field, expected in (
        ("config_id", config["config_id"]),
        ("config_sha256", config["config_sha256"]),
        ("witness_set_id", config["witness_set_id"]),
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("threshold", config["threshold"]),
    ):
        if witness.get(field) != expected:
            raise CompletionWitnessQuorumError(
                f"completion_witness_quorum_{field}_mismatch", str(witness.get(field))
            )
    allowed = set(allowed_states)
    if witness.get("state") not in allowed:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_state_blocks_retry", str(witness.get("state"))
        )
    members = witness.get("members")
    if not isinstance(members, list) or len(members) != witness.get("member_count"):
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_member_count_mismatch", str(witness.get("member_count"))
        )
    if len(members) < config["threshold"]:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_threshold_not_met", str(len(members))
        )
    pinned_by_signer = {row["signer_id"]: row for row in config["witnesses"]}
    seen = {
        field: set()
        for field in (
            "witness_id",
            "authority_id",
            "service_id",
            "signer_id",
            "key_id",
            "trust_domain",
        )
    }
    for member in members:
        if not isinstance(member, dict):
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_quorum_member", "object required"
            )
        pinned = pinned_by_signer.get(member.get("signer_id"))
        if pinned is None or any(
            member.get(field) != pinned[field]
            for field in (
                "witness_id",
                "authority_id",
                "service_id",
                "signer_id",
                "key_id",
                "trust_domain",
            )
        ):
            raise CompletionWitnessQuorumError(
                "completion_witness_quorum_member_not_pinned", str(member.get("signer_id"))
            )
        for field, values in seen.items():
            if member[field] in values:
                raise CompletionWitnessQuorumError(
                    f"duplicate_completion_witness_quorum_{field}", str(member[field])
                )
            values.add(member[field])
        for field in (
            "response_sha256",
            "witness_head_event_sha256",
            "witness_state_root_sha256",
        ):
            if not _is_sha256(member.get(field)):
                raise CompletionWitnessQuorumError(
                    "invalid_completion_witness_quorum_member_digest", field
                )
        if (
            type(member.get("witness_sequence")) is not int
            or member["witness_sequence"] < 0
            or type(member.get("response_issued_at")) is not int
            or type(member.get("response_valid_until")) is not int
            or member["response_issued_at"] > witness.get("evaluated_at", -1)
            or witness.get("evaluated_at", -1) >= member["response_valid_until"]
        ):
            raise CompletionWitnessQuorumError(
                "invalid_completion_witness_quorum_member_time", str(member.get("signer_id"))
            )
    if any(len(values) < config["threshold"] for values in seen.values()):
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_independence_not_met", str(config["threshold"])
        )
    if witness.get("authority_granted") is not False:
        raise CompletionWitnessQuorumError(
            "completion_witness_quorum_authority_expansion", str(witness.get("authority_granted"))
        )
    return {
        "status": "PASS",
        "quorum_witness": witness,
        "verified_member_count": len(members),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_external_effect_guard_with_completion_quorum_and_worm_anchor(
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
    head_quorum_config: Mapping[str, Any],
    expected_head_quorum_config_sha256: str,
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
    signed_completion_witness_statuses: Sequence[Mapping[str, Any]],
    completion_witness_registry: TrustKeyRegistry,
    completion_quorum_config: Mapping[str, Any],
    expected_completion_quorum_config_sha256: str,
    completion_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_completion_challenge: str,
    signed_worm_anchor_status: Mapping[str, Any],
    worm_anchor_registry: TrustKeyRegistry,
    expected_worm_anchor_id: str,
    expected_worm_anchor_authority_id: str,
    expected_worm_anchor_service_id: str,
    expected_worm_anchor_signer_id: str,
    expected_worm_anchor_trust_domain: str,
    worm_anchor_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_worm_anchor_challenge: str,
) -> dict[str, Any]:
    # Imported lazily to keep the quorum module independent from the anchor's
    # storage implementation during import-time schema tooling.
    from .completion_worm_anchor import (
        CompletionWORMAnchorError,
        verify_completion_worm_anchor_status,
    )

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
        head_guard = verify_execution_ledger_head_quorum(
            signed_local_head,
            signed_head_responses,
            ledger_registry=ledger_registry,
            authority_registry=head_authority_registry,
            expected_ledger_id=expected_ledger_id,
            expected_ledger_authority_id=expected_ledger_authority_id,
            expected_ledger_signer_id=expected_ledger_signer_id,
            expected_ledger_trust_domain=expected_ledger_trust_domain,
            quorum_config=head_quorum_config,
            expected_quorum_config_sha256=expected_head_quorum_config_sha256,
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
        completion_guard = verify_completion_witness_quorum(
            signed_completion_witness_statuses,
            registry=completion_witness_registry,
            quorum_config=completion_quorum_config,
            expected_quorum_config_sha256=expected_completion_quorum_config_sha256,
            expected_effect_id=effect_id,
            expected_payload_sha256=expected_provider_payload_sha256,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            challenge_ledger=completion_challenge_ledger,
            expected_challenge=expected_completion_challenge,
            evaluation_tick=evaluation_tick,
        )
        worm_guard = verify_completion_worm_anchor_status(
            signed_worm_anchor_status,
            registry=worm_anchor_registry,
            expected_anchor_id=expected_worm_anchor_id,
            expected_authority_id=expected_worm_anchor_authority_id,
            expected_service_id=expected_worm_anchor_service_id,
            expected_signer_id=expected_worm_anchor_signer_id,
            expected_trust_domain=expected_worm_anchor_trust_domain,
            expected_effect_id=effect_id,
            expected_payload_sha256=expected_provider_payload_sha256,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            challenge_ledger=worm_anchor_challenge_ledger,
            expected_challenge=expected_worm_anchor_challenge,
            evaluation_tick=evaluation_tick,
        )
    except (
        ExecutionLedgerHeadQuorumError,
        ProviderEffectError,
        CompletionWitnessError,
        CompletionWitnessQuorumError,
        CompletionWORMAnchorError,
    ) as exc:
        return {
            "status": "BLOCK",
            "errors": [
                {"code": exc.code, "path": "external_effect_preflight", "message": exc.detail}
            ],
            "authority_granted": False,
            "required_separate_authorization": True,
        }
    return {
        "status": "PASS",
        "errors": [],
        "receipt_guard": receipt_guard,
        "head_quorum_guard": head_guard,
        "provider_guard": provider_guard,
        "completion_witness_quorum_guard": completion_guard,
        "worm_anchor_guard": worm_guard,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "COMPLETION_WITNESS_QUORUM_CONFIG_CONTRACT_ID",
    "COMPLETION_WITNESS_QUORUM_WITNESS_CONTRACT_ID",
    "CompletionWitnessQuorumError",
    "make_completion_witness_quorum_config",
    "sign_completion_witness_quorum_witness",
    "validate_completion_witness_quorum_config",
    "verify_completion_witness_quorum",
    "verify_completion_witness_quorum_witness",
    "verify_external_effect_guard_with_completion_quorum_and_worm_anchor",
]
