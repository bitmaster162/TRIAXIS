"""TRIAXIS v3.31 availability-closed completion control.

v3.30 allowed a threshold quorum to remain usable when a configured completion
witness was unavailable.  That is an availability choice, not a safe default
for irreversible/high-risk effects: an omitted current minority can hide a
``COMPLETED`` or ``UNKNOWN`` state while two rolled-back members report
``ABSENT``.

This module adds an operator-pinned policy that requires every configured
completion witness to contribute one fresh, identity-pinned statement.  Missing,
invalid, stale, equivocal or disagreeing members fail closed.  The result is an
evidence witness only; it never grants action authority.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .completion_witness_quorum import (
    CompletionWitnessQuorumError,
    validate_completion_witness_quorum_config,
    verify_completion_witness_quorum,
)
from .execution_ledger_head_quorum import (
    ExecutionLedgerHeadQuorumError,
    verify_execution_ledger_head_quorum,
)
from .external_completion_witness import CompletionWitnessError
from .external_execution_ledger import verify_external_effect_guard
from .idempotent_effect_provider import (
    ProviderEffectError,
    verify_provider_effect_status,
)
from .crypto_trust import (
    PURPOSE_COMPLETION_AVAILABILITY_CONTROL,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping
from .trust_registry_quorum import SQLiteEpochChallengeLedger

COMPLETION_AVAILABILITY_POLICY_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_AVAILABILITY_POLICY_v1"
)
COMPLETION_AVAILABILITY_WITNESS_CONTRACT_ID = (
    "TRIAXIS_COMPLETION_AVAILABILITY_WITNESS_v1"
)
AVAILABILITY_MODE_ALL_CONFIGURED = "ALL_CONFIGURED_REQUIRED"
AVAILABILITY_RISK_CLASSES = frozenset({"HIGH", "CRITICAL"})


class CompletionAvailabilityError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _normalize_permissive_allowed_states(value: Sequence[str]) -> tuple[str, ...]:
    """Accept only the two non-blocking completion states.

    ``allowed_states`` is a verifier convenience, not an authority surface.  A
    caller must not be able to relabel ``UNKNOWN`` or ``COMPLETED`` as
    permissive by widening the sequence supplied to the public API.
    """
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CompletionAvailabilityError(
            "invalid_completion_availability_allowed_states",
            "sequence of ABSENT/NO_EFFECT required",
        )
    states = tuple(value)
    if (
        not states
        or any(not isinstance(state, str) for state in states)
        or len(set(states)) != len(states)
        or any(state not in {"ABSENT", "NO_EFFECT"} for state in states)
    ):
        raise CompletionAvailabilityError(
            "invalid_completion_availability_allowed_states", repr(states)
        )
    return states


def make_completion_availability_policy(
    *,
    policy_id: str,
    completion_quorum_config_sha256: str,
    risk_class: str,
    required_witness_count: int,
    valid_from: int,
    valid_until: int,
) -> dict[str, Any]:
    """Create the v3.31 fail-closed availability policy.

    The only supported mode intentionally has ``max_missing=0``.  A looser
    policy belongs to the v3.30 threshold surface and must not be relabelled as
    availability-closed.
    """
    return seal_mapping(
        {
            "contract_id": COMPLETION_AVAILABILITY_POLICY_CONTRACT_ID,
            "policy_id": policy_id,
            "completion_quorum_config_sha256": completion_quorum_config_sha256,
            "risk_class": risk_class,
            "availability_mode": AVAILABILITY_MODE_ALL_CONFIGURED,
            "required_witness_count": required_witness_count,
            "max_missing": 0,
            "require_blocking_minority_veto": True,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "policy_sha256": "",
        },
        "policy_sha256",
    )


def validate_completion_availability_policy(
    value: Any,
    *,
    evaluation_tick: int | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {
            "status": "BLOCK",
            "errors": [
                {"code": "invalid_type", "path": "policy", "message": "mapping required"}
            ],
        }
    try:
        policy = materialize_json(value)
    except Exception as exc:
        return {
            "status": "BLOCK",
            "errors": [
                {
                    "code": "materialization_failed",
                    "path": "policy",
                    "message": type(exc).__name__,
                }
            ],
        }
    if not isinstance(policy, dict):
        return {
            "status": "BLOCK",
            "errors": [
                {"code": "invalid_type", "path": "policy", "message": "object required"}
            ],
        }
    if policy.get("contract_id") != COMPLETION_AVAILABILITY_POLICY_CONTRACT_ID:
        errors.append(
            {
                "code": "invalid_contract_id",
                "path": "policy.contract_id",
                "message": COMPLETION_AVAILABILITY_POLICY_CONTRACT_ID,
            }
        )
    if not verify_sealed_mapping(policy, "policy_sha256"):
        errors.append(
            {
                "code": "digest_mismatch",
                "path": "policy.policy_sha256",
                "message": "canonical digest mismatch",
            }
        )
    if not isinstance(policy.get("policy_id"), str) or not policy["policy_id"]:
        errors.append(
            {
                "code": "invalid_policy_id",
                "path": "policy.policy_id",
                "message": "non-empty string required",
            }
        )
    if not _is_sha256(policy.get("completion_quorum_config_sha256")):
        errors.append(
            {
                "code": "invalid_quorum_config_digest",
                "path": "policy.completion_quorum_config_sha256",
                "message": "lowercase SHA-256 required",
            }
        )
    if policy.get("risk_class") not in AVAILABILITY_RISK_CLASSES:
        errors.append(
            {
                "code": "invalid_risk_class",
                "path": "policy.risk_class",
                "message": "HIGH or CRITICAL required",
            }
        )
    if policy.get("availability_mode") != AVAILABILITY_MODE_ALL_CONFIGURED:
        errors.append(
            {
                "code": "availability_mode_not_closed",
                "path": "policy.availability_mode",
                "message": AVAILABILITY_MODE_ALL_CONFIGURED,
            }
        )
    if type(policy.get("required_witness_count")) is not int or policy[
        "required_witness_count"
    ] < 2:
        errors.append(
            {
                "code": "invalid_required_witness_count",
                "path": "policy.required_witness_count",
                "message": "integer >= 2 required",
            }
        )
    if policy.get("max_missing") != 0:
        errors.append(
            {
                "code": "availability_gap_not_closed",
                "path": "policy.max_missing",
                "message": "must equal 0",
            }
        )
    if policy.get("require_blocking_minority_veto") is not True:
        errors.append(
            {
                "code": "blocking_minority_veto_required",
                "path": "policy.require_blocking_minority_veto",
                "message": "must equal true",
            }
        )
    valid_from = policy.get("valid_from")
    valid_until = policy.get("valid_until")
    if (
        type(valid_from) is not int
        or type(valid_until) is not int
        or valid_from < 0
        or valid_until <= valid_from
    ):
        errors.append(
            {
                "code": "invalid_validity_window",
                "path": "policy",
                "message": "valid_from < valid_until required",
            }
        )
    if evaluation_tick is not None:
        if type(evaluation_tick) is not int or evaluation_tick < 0:
            errors.append(
                {
                    "code": "invalid_evaluation_tick",
                    "path": "evaluation_tick",
                    "message": "integer >= 0 required",
                }
            )
        elif (
            type(valid_from) is int
            and type(valid_until) is int
            and not (valid_from <= evaluation_tick < valid_until)
        ):
            errors.append(
                {
                    "code": "policy_not_current",
                    "path": "policy",
                    "message": str(evaluation_tick),
                }
            )
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "policy": policy,
    }


def verify_availability_closed_completion_quorum(
    signed_statuses: Sequence[Mapping[str, Any]],
    *,
    registry: TrustKeyRegistry,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    availability_policy: Mapping[str, Any],
    expected_availability_policy_sha256: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    challenge_ledger: SQLiteEpochChallengeLedger,
    expected_challenge: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
    max_response_age: int = 5,
) -> dict[str, Any]:
    """Require one valid, agreeing response from every configured witness."""
    allowed_states = _normalize_permissive_allowed_states(allowed_states)
    policy_result = validate_completion_availability_policy(
        availability_policy, evaluation_tick=evaluation_tick
    )
    if policy_result["status"] != "PASS":
        raise CompletionAvailabilityError(
            "invalid_completion_availability_policy", str(policy_result["errors"])
        )
    policy = policy_result["policy"]
    if policy["policy_sha256"] != expected_availability_policy_sha256:
        raise CompletionAvailabilityError(
            "completion_availability_policy_substitution", policy["policy_sha256"]
        )
    config_result = validate_completion_witness_quorum_config(
        quorum_config, evaluation_tick
    )
    if config_result["status"] != "PASS":
        raise CompletionAvailabilityError(
            "invalid_completion_witness_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if config["config_sha256"] != expected_quorum_config_sha256:
        raise CompletionAvailabilityError(
            "completion_witness_quorum_config_substitution", config["config_sha256"]
        )
    if policy["completion_quorum_config_sha256"] != config["config_sha256"]:
        raise CompletionAvailabilityError(
            "completion_availability_quorum_binding_mismatch",
            policy["completion_quorum_config_sha256"],
        )
    configured_count = len(config["witnesses"])
    if policy["required_witness_count"] != configured_count:
        raise CompletionAvailabilityError(
            "completion_availability_required_count_mismatch",
            f"policy={policy['required_witness_count']} configured={configured_count}",
        )
    if len(signed_statuses) < configured_count:
        raise CompletionAvailabilityError(
            "completion_availability_witness_set_incomplete",
            f"received={len(signed_statuses)} configured={configured_count}",
        )
    try:
        quorum_result = verify_completion_witness_quorum(
            signed_statuses,
            registry=registry,
            quorum_config=config,
            expected_quorum_config_sha256=config["config_sha256"],
            expected_effect_id=expected_effect_id,
            expected_payload_sha256=expected_payload_sha256,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            challenge_ledger=challenge_ledger,
            expected_challenge=expected_challenge,
            evaluation_tick=evaluation_tick,
            allowed_states=allowed_states,
            max_response_age=max_response_age,
            blocking_minority_veto=True,
        )
    except CompletionWitnessQuorumError as exc:
        raise CompletionAvailabilityError(exc.code, exc.detail) from exc

    quorum_witness = quorum_result["quorum_witness"]
    members = quorum_witness.get("members")
    if not isinstance(members, list):
        raise CompletionAvailabilityError(
            "completion_availability_invalid_quorum_witness", "members required"
        )
    configured_by_signer = {row["signer_id"]: row for row in config["witnesses"]}
    observed_signers = {
        str(member.get("signer_id"))
        for member in members
        if isinstance(member, Mapping)
    }
    configured_signers = set(configured_by_signer)
    missing = sorted(configured_signers - observed_signers)
    unexpected = sorted(observed_signers - configured_signers)
    if (
        len(members) != configured_count
        or missing
        or unexpected
        or quorum_witness.get("member_count") != configured_count
    ):
        raise CompletionAvailabilityError(
            "completion_availability_witness_set_incomplete",
            f"missing={missing} unexpected={unexpected} observed={len(members)} configured={configured_count}",
        )
    for member in members:
        signer_id = member["signer_id"]
        pinned = configured_by_signer[signer_id]
        if any(
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
            raise CompletionAvailabilityError(
                "completion_availability_member_not_pinned", signer_id
            )

    availability_witness = seal_mapping(
        {
            "contract_id": COMPLETION_AVAILABILITY_WITNESS_CONTRACT_ID,
            "policy_id": policy["policy_id"],
            "policy_sha256": policy["policy_sha256"],
            "risk_class": policy["risk_class"],
            "availability_mode": policy["availability_mode"],
            "completion_quorum_config_sha256": config["config_sha256"],
            "completion_quorum_witness_sha256": quorum_witness["witness_sha256"],
            "effect_id": expected_effect_id,
            "payload_sha256": expected_payload_sha256,
            "provider_id": expected_provider_id,
            "provider_service_id": expected_provider_service_id,
            "state": quorum_witness["state"],
            "generation": quorum_witness["generation"],
            "configured_witness_count": configured_count,
            "responding_witness_count": len(members),
            "missing_witness_ids": [],
            "members": materialize_json(members),
            "verifier_id": quorum_witness["verifier_id"],
            "verifier_epoch_sha256": quorum_witness["verifier_epoch_sha256"],
            "challenge_sha256": quorum_witness["challenge_sha256"],
            "requested_at": quorum_witness["requested_at"],
            "evaluated_at": evaluation_tick,
            "authority_granted": False,
            "witness_sha256": "",
        },
        "witness_sha256",
    )
    return {
        "status": "PASS",
        "availability_witness": availability_witness,
        "completion_quorum_result": quorum_result,
        "configured_witness_count": configured_count,
        "responding_witness_count": len(members),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def sign_completion_availability_witness(
    availability_witness: Mapping[str, Any],
    *,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    private_key_b64: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    if not verify_sealed_mapping(availability_witness, "witness_sha256"):
        raise CompletionAvailabilityError(
            "invalid_completion_availability_witness", "canonical digest mismatch"
        )
    return sign_contract_envelope(
        availability_witness,
        digest_field="witness_sha256",
        purpose=PURPOSE_COMPLETION_AVAILABILITY_CONTROL,
        key_id=key_id,
        signer_id=signer_id,
        trust_domain=trust_domain,
        private_key_b64=private_key_b64,
        issued_at=issued_at,
        valid_until=valid_until,
    )


def verify_completion_availability_witness(
    signed_witness: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    expected_signer_id: str,
    expected_trust_domain: str,
    availability_policy: Mapping[str, Any],
    expected_availability_policy_sha256: str,
    quorum_config: Mapping[str, Any],
    expected_quorum_config_sha256: str,
    expected_effect_id: str,
    expected_payload_sha256: str,
    expected_provider_id: str,
    expected_provider_service_id: str,
    evaluation_tick: int,
    allowed_states: Sequence[str] = ("ABSENT", "NO_EFFECT"),
) -> dict[str, Any]:
    allowed_states = _normalize_permissive_allowed_states(allowed_states)
    verified = verify_contract_envelope(
        signed_witness,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_COMPLETION_AVAILABILITY_CONTROL,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=COMPLETION_AVAILABILITY_WITNESS_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    if verified["status"] != "PASS":
        raise CompletionAvailabilityError(
            "invalid_completion_availability_signature", str(verified["errors"])
        )
    policy_result = validate_completion_availability_policy(
        availability_policy, evaluation_tick=evaluation_tick
    )
    if policy_result["status"] != "PASS":
        raise CompletionAvailabilityError(
            "invalid_completion_availability_policy", str(policy_result["errors"])
        )
    policy = policy_result["policy"]
    if policy["policy_sha256"] != expected_availability_policy_sha256:
        raise CompletionAvailabilityError(
            "completion_availability_policy_substitution", policy["policy_sha256"]
        )
    config_result = validate_completion_witness_quorum_config(
        quorum_config, evaluation_tick
    )
    if config_result["status"] != "PASS":
        raise CompletionAvailabilityError(
            "invalid_completion_witness_quorum_config", str(config_result["errors"])
        )
    config = config_result["config"]
    if config["config_sha256"] != expected_quorum_config_sha256:
        raise CompletionAvailabilityError(
            "completion_witness_quorum_config_substitution", config["config_sha256"]
        )
    witness = verified["inner_contract"]
    if not isinstance(witness, dict):
        raise CompletionAvailabilityError(
            "invalid_completion_availability_witness", "object required"
        )
    expected_fields = (
        ("policy_id", policy["policy_id"]),
        ("policy_sha256", policy["policy_sha256"]),
        ("risk_class", policy["risk_class"]),
        ("availability_mode", AVAILABILITY_MODE_ALL_CONFIGURED),
        ("completion_quorum_config_sha256", config["config_sha256"]),
        ("effect_id", expected_effect_id),
        ("payload_sha256", expected_payload_sha256),
        ("provider_id", expected_provider_id),
        ("provider_service_id", expected_provider_service_id),
        ("configured_witness_count", len(config["witnesses"])),
        ("responding_witness_count", len(config["witnesses"])),
        ("missing_witness_ids", []),
    )
    for field, expected in expected_fields:
        if witness.get(field) != expected:
            raise CompletionAvailabilityError(
                f"completion_availability_{field}_mismatch", str(witness.get(field))
            )
    if witness.get("state") not in set(allowed_states):
        raise CompletionAvailabilityError(
            "completion_availability_state_blocks_retry", str(witness.get("state"))
        )
    if not _is_sha256(witness.get("completion_quorum_witness_sha256")):
        raise CompletionAvailabilityError(
            "invalid_completion_quorum_witness_digest",
            str(witness.get("completion_quorum_witness_sha256")),
        )
    members = witness.get("members")
    if not isinstance(members, list) or len(members) != len(config["witnesses"]):
        raise CompletionAvailabilityError(
            "completion_availability_witness_set_incomplete", str(len(members or []))
        )
    pinned = {row["signer_id"]: row for row in config["witnesses"]}
    observed: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            raise CompletionAvailabilityError(
                "invalid_completion_availability_member", "object required"
            )
        signer = member.get("signer_id")
        row = pinned.get(signer)
        if row is None or any(
            member.get(field) != row[field]
            for field in (
                "witness_id",
                "authority_id",
                "service_id",
                "signer_id",
                "key_id",
                "trust_domain",
            )
        ):
            raise CompletionAvailabilityError(
                "completion_availability_member_not_pinned", str(signer)
            )
        if signer in observed:
            raise CompletionAvailabilityError(
                "duplicate_completion_availability_member", str(signer)
            )
        observed.add(str(signer))
    if observed != set(pinned):
        raise CompletionAvailabilityError(
            "completion_availability_witness_set_incomplete",
            str(sorted(set(pinned) - observed)),
        )
    if witness.get("authority_granted") is not False:
        raise CompletionAvailabilityError(
            "completion_availability_authority_expansion",
            str(witness.get("authority_granted")),
        )
    return {
        "status": "PASS",
        "availability_witness": witness,
        "verified_member_count": len(members),
        "authority_granted": False,
        "required_separate_authorization": True,
    }


def verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor(
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
    availability_policy: Mapping[str, Any],
    expected_availability_policy_sha256: str,
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
    signed_immutable_anchor_status: Mapping[str, Any],
    immutable_anchor_registry: TrustKeyRegistry,
    expected_immutable_anchor_id: str,
    expected_immutable_anchor_authority_id: str,
    expected_immutable_anchor_service_id: str,
    expected_immutable_anchor_signer_id: str,
    expected_immutable_anchor_trust_domain: str,
    expected_immutable_anchor_retention_policy_id: str,
    immutable_anchor_challenge_ledger: SQLiteEpochChallengeLedger,
    expected_immutable_anchor_challenge: str,
    immutable_anchor_checkpoint_ledger: Any | None = None,
) -> dict[str, Any]:
    """Evaluate the cumulative v3.31 external-effect preflight.

    The function deliberately keeps reasoning/evidence separate from action
    authority.  Every cumulative evidence plane must report a current,
    permissive state.  Missing completion-witness availability, an anchor
    rollback, or any blocking state returns ``BLOCK`` without broadening the
    authorization envelope carried by the original execution intent.
    """
    # Imported lazily so schema and documentation tooling can import this
    # module without forcing filesystem-anchor initialization.
    from .completion_immutable_anchor import (
        CompletionImmutableAnchorError,
        verify_completion_immutable_anchor_status,
    )
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
        completion_guard = verify_availability_closed_completion_quorum(
            signed_completion_witness_statuses,
            registry=completion_witness_registry,
            quorum_config=completion_quorum_config,
            expected_quorum_config_sha256=expected_completion_quorum_config_sha256,
            availability_policy=availability_policy,
            expected_availability_policy_sha256=expected_availability_policy_sha256,
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
        immutable_guard = verify_completion_immutable_anchor_status(
            signed_immutable_anchor_status,
            registry=immutable_anchor_registry,
            expected_anchor_id=expected_immutable_anchor_id,
            expected_authority_id=expected_immutable_anchor_authority_id,
            expected_service_id=expected_immutable_anchor_service_id,
            expected_signer_id=expected_immutable_anchor_signer_id,
            expected_trust_domain=expected_immutable_anchor_trust_domain,
            expected_provider_id=expected_provider_id,
            expected_provider_service_id=expected_provider_service_id,
            expected_retention_policy_id=expected_immutable_anchor_retention_policy_id,
            expected_effect_id=effect_id,
            expected_payload_sha256=expected_provider_payload_sha256,
            challenge_ledger=immutable_anchor_challenge_ledger,
            expected_challenge=expected_immutable_anchor_challenge,
            evaluation_tick=evaluation_tick,
            checkpoint_ledger=immutable_anchor_checkpoint_ledger,
        )
    except (
        ExecutionLedgerHeadQuorumError,
        ProviderEffectError,
        CompletionWitnessError,
        CompletionWitnessQuorumError,
        CompletionAvailabilityError,
        CompletionWORMAnchorError,
        CompletionImmutableAnchorError,
    ) as exc:
        return {
            "status": "BLOCK",
            "errors": [
                {
                    "code": exc.code,
                    "path": "external_effect_preflight",
                    "message": exc.detail,
                }
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
        "completion_availability_guard": completion_guard,
        "worm_anchor_guard": worm_guard,
        "immutable_anchor_guard": immutable_guard,
        "authority_granted": False,
        "required_separate_authorization": True,
    }


__all__ = [
    "AVAILABILITY_MODE_ALL_CONFIGURED",
    "AVAILABILITY_RISK_CLASSES",
    "COMPLETION_AVAILABILITY_POLICY_CONTRACT_ID",
    "COMPLETION_AVAILABILITY_WITNESS_CONTRACT_ID",
    "CompletionAvailabilityError",
    "make_completion_availability_policy",
    "sign_completion_availability_witness",
    "validate_completion_availability_policy",
    "verify_availability_closed_completion_quorum",
    "verify_completion_availability_witness",
    "verify_external_effect_guard_with_availability_closed_completion_and_immutable_anchor",
]
