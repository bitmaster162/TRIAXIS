"""Host-configured authority-analysis ingress for TRIAXIS.

The low-level Bundle v5 validator intentionally remains reproducible with raw
Trust Snapshot v2. Authority-grade application traffic must not call that API
directly: it enters through a session that owns a host-configured snapshot
state guard and accepts a signed envelope before analytical validation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .integrity import canonical_sha256, materialize_json

from .analysis_v5 import (
    ANALYSIS_BUNDLE_CONTRACT_ID,
    validate_analysis_bundle as validate_analysis_bundle_v5,
)
from .provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)

AUTHORITY_ANALYSIS_SESSION_V1_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v1"
AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v2"
AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v3"
AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v4"
AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v5"
AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID = "TRIAXIS_AUTHORITY_ANALYSIS_SESSION_v6"


def authority_analysis_required(value: Mapping[str, Any]) -> bool:
    """Return whether a structured bundle activates external authority semantics."""

    frame = value.get("frame")
    profile = frame.get("control_profile") if isinstance(frame, Mapping) else None
    evaluation_context = frame.get("evaluation_context_ref") if isinstance(frame, Mapping) else None

    passes = value.get("passes")
    pass_items = passes if isinstance(passes, list) else []
    independent = any(
        isinstance(item, Mapping)
        and item.get("independence_class") == "INDEPENDENT_VERIFICATION"
        for item in pass_items
    )

    register = value.get("conflict_register")
    conflicts = register.get("conflicts") if isinstance(register, Mapping) else None
    conflict_items = conflicts if isinstance(conflicts, list) else []
    human_decision = any(
        isinstance(item, Mapping) and item.get("resolution_mode") == "HUMAN_DECISION"
        for item in conflict_items
    )
    return (
        profile == "A3"
        or independent
        or human_decision
        or isinstance(evaluation_context, str)
    )


def authority_session_required_result() -> dict[str, Any]:
    return {
        "status": "BLOCK",
        "primary_reason": "BLOCKED_BY_AUTHENTICATED_TRUST_STATE",
        "errors": [{
            "code": "authority_analysis_session_required",
            "path": "provenance_trust",
            "message": (
                "authority-grade Bundle v5 must be evaluated through a host-configured "
                "AuthorityAnalysisSession using a signed trust snapshot envelope"
            ),
        }],
        "error_count": 1,
    }


def _state_block(exc: TrustSnapshotStateError) -> dict[str, Any]:
    return {
        "status": "BLOCK",
        "primary_reason": "BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        "errors": [{
            "code": exc.code,
            "path": "provenance_trust_envelope",
            "message": str(exc),
        }],
        "error_count": 1,
    }


def _authority_time_block(
    code: str,
    message: str,
    *,
    path: str = "authority_session.trusted_evaluation_tick",
) -> dict[str, Any]:
    return {
        "status": "BLOCK",
        "primary_reason": "BLOCKED_BY_AUTHORITY_TIME",
        "errors": [{
            "code": code,
            "path": path,
            "message": message,
        }],
        "error_count": 1,
    }


def validate_authority_analysis_bundle(
    value: Any,
    *,
    trust_guard: ProvenanceTrustStateGuard,
    trust_envelope: Mapping[str, Any],
    trusted_evaluation_tick: int | None = None,
) -> dict[str, Any]:
    """Validate one authority-grade bundle through an authenticated trust session.

    ``trust_guard`` and ``trusted_evaluation_tick`` are host configuration, not
    request payload. A request frame may declare the time it was built for, but
    it cannot create or advance authority time by itself.
    """

    if not isinstance(value, Mapping):
        return validate_analysis_bundle_v5(value)

    # Freeze the complete request bundle once. All authority classification,
    # time binding, analytical validation and the final decision refer to these
    # exact bytes. A hostile or concurrently mutated Mapping must not create a
    # time-of-check/time-of-use split around checkpoint commitment.
    try:
        bundle_value = materialize_json(value)
        if not isinstance(bundle_value, dict):
            raise TypeError("analysis bundle must materialize to an object")
    except Exception as exc:
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_ANALYSIS_CONTRACT",
            "errors": [{
                "code": "invalid_analysis_bundle_materialization",
                "path": "bundle",
                "message": (
                    "analysis bundle could not be materialized: "
                    f"{type(exc).__name__}"
                ),
            }],
            "error_count": 1,
        }

    if bundle_value.get("contract_id") != ANALYSIS_BUNDLE_CONTRACT_ID:
        return validate_analysis_bundle_v5(bundle_value)
    if not authority_analysis_required(bundle_value):
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_AUTHENTICATED_TRUST_STATE",
            "errors": [{
                "code": "authority_session_not_required",
                "path": "bundle.frame.control_profile",
                "message": "non-authority analysis must use the generic validator",
            }],
            "error_count": 1,
        }
    if not isinstance(trust_guard, ProvenanceTrustStateGuard):
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_AUTHENTICATED_TRUST_STATE",
            "errors": [{
                "code": "invalid_authority_analysis_session",
                "path": "provenance_trust",
                "message": "trust_guard must be a host-configured ProvenanceTrustStateGuard",
            }],
            "error_count": 1,
        }
    if not isinstance(trust_envelope, Mapping):
        return {
            "status": "BLOCK",
            "primary_reason": "BLOCKED_BY_AUTHENTICATED_TRUST_STATE",
            "errors": [{
                "code": "missing_trust_snapshot_envelope",
                "path": "provenance_trust_envelope",
                "message": "authority analysis requires a signed trust snapshot envelope",
            }],
            "error_count": 1,
        }

    # Freeze the request mapping once. Authenticity is checked before the time
    # gate so malformed/tampered envelopes retain their exact state error, but
    # this preflight cannot advance the guard.
    try:
        envelope_value = materialize_json(trust_envelope)
        if not isinstance(envelope_value, dict):
            raise TypeError("trust snapshot envelope must materialize to an object")
    except Exception as exc:
        return _state_block(TrustSnapshotStateError(
            "invalid_trust_snapshot_envelope",
            f"trust snapshot envelope could not be materialized: {type(exc).__name__}",
        ))
    try:
        parsed_envelope = trust_guard.authenticate_envelope(envelope_value)
    except TrustSnapshotStateError as exc:
        return _state_block(exc)

    frame = bundle_value.get("frame")
    bundle_tick = frame.get("evaluation_tick") if isinstance(frame, Mapping) else None
    if type(bundle_tick) is not int or bundle_tick < 0:  # noqa: E721
        # Let the low-level contract return its exact frame errors without first
        # accepting external trust state at an unbound caller-selected time.
        return validate_analysis_bundle_v5(bundle_value)

    checkpoint = trust_guard.checkpoint
    if trusted_evaluation_tick is None:
        if checkpoint is None:
            return _authority_time_block(
                "trusted_evaluation_time_required",
                "a fresh authority session requires a host-controlled evaluation tick",
            )
        effective_tick = checkpoint.evaluation_tick
    elif type(trusted_evaluation_tick) is not int or trusted_evaluation_tick < 0:  # noqa: E721
        return _authority_time_block(
            "invalid_trusted_evaluation_time",
            "trusted_evaluation_tick must be an integer >= 0",
        )
    else:
        effective_tick = trusted_evaluation_tick

    if checkpoint is not None and effective_tick < checkpoint.evaluation_tick:
        return _authority_time_block(
            "authority_evaluation_time_mismatch",
            "host evaluation time cannot precede the accepted authority checkpoint",
        )
    if bundle_tick != effective_tick:
        return _authority_time_block(
            "authority_evaluation_time_mismatch",
            "bundle evaluation_tick must equal the host-controlled evaluation tick",
            path="bundle.frame.evaluation_tick",
        )

    # A signed snapshot is an observation of trust state at one exact logical
    # time. Re-signing old bytes or keeping an old envelope valid cannot make
    # omitted revocations or root changes observable at a later host tick.
    snapshot_tick = parsed_envelope.snapshot.get("evaluation_tick")
    if snapshot_tick < effective_tick:
        return _state_block(TrustSnapshotStateError(
            "stale_trust_snapshot_state",
            "trust snapshot evaluation_tick precedes the host-controlled evaluation tick",
        ))
    if snapshot_tick > effective_tick:
        return _state_block(TrustSnapshotStateError(
            "future_trust_snapshot_state",
            "trust snapshot evaluation_tick exceeds the host-controlled evaluation tick",
        ))

    # Authenticity and freshness do not establish analytical subject identity.
    # Bind the signed snapshot to the exact frozen bundle and its exact
    # provenance registry before any analytical preparation or state mutation.
    bundle_sha256 = bundle_value.get("bundle_sha256")
    trust_records_sha256 = canonical_sha256(bundle_value.get("provenance_registry", {}))
    if parsed_envelope.snapshot.get("source_bundle_sha256") != bundle_sha256:
        return _state_block(TrustSnapshotStateError(
            "trust_snapshot_bundle_binding_mismatch",
            "trust snapshot source bundle digest does not match the frozen Analysis Bundle",
        ))
    if parsed_envelope.snapshot.get("trust_records_sha256") != trust_records_sha256:
        return _state_block(TrustSnapshotStateError(
            "trust_snapshot_provenance_binding_mismatch",
            "trust snapshot provenance digest does not match the frozen Analysis Bundle registry",
        ))

    # Prepare is deliberately state-neutral. The raw snapshot was authenticated
    # by the host-configured envelope key, but the monotonic head is not advanced
    # until the exact frozen Analysis Bundle has passed all structural,
    # semantic, subject/context and provenance-trust checks.
    prepared = validate_analysis_bundle_v5(
        bundle_value,
        trust_snapshot=parsed_envelope.snapshot,
    )
    if prepared.get("status") != "PASS":
        return prepared

    # Commit only after analytical acceptance. ``accept`` re-authenticates and
    # atomically rechecks temporal validity, parentage, sequence, root continuity
    # and configured transitions under its lock. A race or intervening state
    # change therefore blocks instead of committing a stale preparation.
    try:
        trust_guard.accept(
            envelope_value,
            evaluation_tick=effective_tick,
            expected_bundle_sha256=str(bundle_sha256),
            expected_trust_records_sha256=trust_records_sha256,
        )
    except TrustSnapshotStateError as exc:
        return _state_block(exc)
    return prepared


@dataclass(frozen=True, slots=True)
class AuthorityAnalysisSession:
    """Host-owned authority-analysis session bound to one state guard."""

    _trust_guard: ProvenanceTrustStateGuard
    contract_id = AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID

    def __init__(self, *, trust_guard: ProvenanceTrustStateGuard) -> None:
        if not isinstance(trust_guard, ProvenanceTrustStateGuard):
            raise TypeError("trust_guard must be a ProvenanceTrustStateGuard")
        object.__setattr__(self, "_trust_guard", trust_guard)

    @property
    def checkpoint(self):
        return self._trust_guard.checkpoint

    @property
    def authority_roots(self):
        return self._trust_guard.authority_roots

    def validate(
        self,
        value: Any,
        *,
        trust_envelope: Mapping[str, Any],
        trusted_evaluation_tick: int | None = None,
    ) -> dict[str, Any]:
        return validate_authority_analysis_bundle(
            value,
            trust_guard=self._trust_guard,
            trust_envelope=trust_envelope,
            trusted_evaluation_tick=trusted_evaluation_tick,
        )


__all__ = [
    "AUTHORITY_ANALYSIS_SESSION_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V1_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V2_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V3_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V4_CONTRACT_ID",
    "AUTHORITY_ANALYSIS_SESSION_V5_CONTRACT_ID",
    "AuthorityAnalysisSession",
    "authority_analysis_required",
    "authority_session_required_result",
    "validate_authority_analysis_bundle",
]
