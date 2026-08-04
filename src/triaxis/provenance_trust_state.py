"""Authenticated, monotonic trust-snapshot state for the recovery lineage."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .integrity import canonical_json_bytes, canonical_sha256, materialize_json

TRUST_SNAPSHOT_CONTRACT_ID = "TRIAXIS_PROVENANCE_TRUST_SNAPSHOT_v2"
TRUST_SNAPSHOT_ENVELOPE_CONTRACT_ID = "TRIAXIS_PROVENANCE_TRUST_SNAPSHOT_ENVELOPE_v1"
TRUST_CHECKPOINT_V2_CONTRACT_ID = "TRIAXIS_PROVENANCE_TRUST_CHECKPOINT_v2"
TRUST_CHECKPOINT_CONTRACT_ID = "TRIAXIS_PROVENANCE_TRUST_CHECKPOINT_v3"
SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID = "TRIAXIS_SNAPSHOT_AUTHORITY_ROOT_v1"


class TrustSnapshotStateError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuthenticatedTrustEnvelope:
    envelope: dict[str, Any]
    snapshot: dict[str, Any]
    authority_root: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ProvenanceTrustCheckpoint:
    sequence: int
    envelope_sha256: str
    snapshot_sha256: str
    previous_envelope_sha256: str | None
    issued_at: int
    evaluation_tick: int
    authority_id: str
    key_id: str
    authority_root_sha256: str
    contract_id: str = TRUST_CHECKPOINT_CONTRACT_ID

    def as_dict(self) -> dict[str, Any]:
        receipt = {
            "contract_id": self.contract_id,
            "sequence": self.sequence,
            "envelope_sha256": self.envelope_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "previous_envelope_sha256": self.previous_envelope_sha256,
            "issued_at": self.issued_at,
            "evaluation_tick": self.evaluation_tick,
            "authority_id": self.authority_id,
            "key_id": self.key_id,
            "authority_root_sha256": self.authority_root_sha256,
            "checkpoint_sha256": "",
        }
        receipt["checkpoint_sha256"] = canonical_sha256(receipt)
        return receipt


def _checkpoint_receipt_block(code: str, path: str, message: str) -> dict[str, Any]:
    return {
        "status": "BLOCK",
        "primary_reason": "BLOCKED_BY_TRUST_CHECKPOINT_RECEIPT",
        "errors": [{"code": code, "path": path, "message": message}],
        "error_count": 1,
    }


def validate_checkpoint_receipt(value: Any) -> dict[str, Any]:
    """Validate one self-contained public checkpoint receipt."""

    try:
        receipt = materialize_json(value)
    except Exception as exc:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_materialization",
            "checkpoint_receipt",
            f"checkpoint receipt could not be materialized: {type(exc).__name__}",
        )
    if not isinstance(receipt, dict):
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_type",
            "checkpoint_receipt",
            "checkpoint receipt must be an object",
        )

    required = {
        "contract_id", "sequence", "envelope_sha256", "snapshot_sha256",
        "previous_envelope_sha256", "issued_at", "evaluation_tick",
        "authority_id", "key_id", "authority_root_sha256",
        "checkpoint_sha256",
    }
    missing = sorted(required - receipt.keys())
    if missing:
        return _checkpoint_receipt_block(
            "missing_checkpoint_receipt_field",
            f"checkpoint_receipt.{missing[0]}",
            f"missing checkpoint receipt field: {missing[0]}",
        )
    extras = sorted(receipt.keys() - required)
    if extras:
        return _checkpoint_receipt_block(
            "unknown_checkpoint_receipt_field",
            f"checkpoint_receipt.{extras[0]}",
            f"unknown checkpoint receipt field: {extras[0]}",
        )
    if receipt.get("contract_id") != TRUST_CHECKPOINT_CONTRACT_ID:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_contract",
            "checkpoint_receipt.contract_id",
            "unexpected checkpoint receipt contract",
        )

    observed_digest = receipt.get("checkpoint_sha256")
    if not isinstance(observed_digest, str) or re.fullmatch(r"[0-9a-f]{64}", observed_digest) is None:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_digest",
            "checkpoint_receipt.checkpoint_sha256",
            "checkpoint_sha256 must be 64 lowercase hexadecimal characters",
        )
    digest_payload = dict(receipt)
    digest_payload["checkpoint_sha256"] = ""
    if canonical_sha256(digest_payload) != observed_digest:
        return _checkpoint_receipt_block(
            "checkpoint_receipt_digest_mismatch",
            "checkpoint_receipt.checkpoint_sha256",
            "checkpoint receipt digest mismatch",
        )

    sequence = receipt.get("sequence")
    if type(sequence) is not int or sequence < 1:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_sequence",
            "checkpoint_receipt.sequence",
            "sequence must be an integer >= 1",
        )
    for field in ("issued_at", "evaluation_tick"):
        if type(receipt.get(field)) is not int or receipt[field] < 0:
            return _checkpoint_receipt_block(
                "invalid_checkpoint_receipt_time",
                f"checkpoint_receipt.{field}",
                f"{field} must be an integer >= 0",
            )
    if receipt["issued_at"] > receipt["evaluation_tick"]:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_time",
            "checkpoint_receipt.evaluation_tick",
            "evaluation_tick cannot precede issued_at",
        )
    for field in ("envelope_sha256", "snapshot_sha256", "authority_root_sha256"):
        value_field = receipt.get(field)
        if not isinstance(value_field, str) or re.fullmatch(r"[0-9a-f]{64}", value_field) is None:
            return _checkpoint_receipt_block(
                "invalid_checkpoint_receipt_digest",
                f"checkpoint_receipt.{field}",
                f"{field} must be 64 lowercase hexadecimal characters",
            )
    for field in ("authority_id", "key_id"):
        if not isinstance(receipt.get(field), str) or not receipt[field]:
            return _checkpoint_receipt_block(
                "invalid_checkpoint_receipt_identity",
                f"checkpoint_receipt.{field}",
                f"{field} must be a non-empty string",
            )
    parent = receipt.get("previous_envelope_sha256")
    if sequence == 1:
        if parent is not None:
            return _checkpoint_receipt_block(
                "invalid_checkpoint_receipt_parent",
                "checkpoint_receipt.previous_envelope_sha256",
                "genesis receipt parent must be null",
            )
    elif not isinstance(parent, str) or re.fullmatch(r"[0-9a-f]{64}", parent) is None:
        return _checkpoint_receipt_block(
            "invalid_checkpoint_receipt_parent",
            "checkpoint_receipt.previous_envelope_sha256",
            "successor receipt parent must be a 64-hex envelope digest",
        )
    return {
        "status": "PASS",
        "primary_reason": "CHECKPOINT_RECEIPT_VALID",
        "errors": [],
        "error_count": 0,
        "checkpoint_sha256": observed_digest,
    }


def _root_digest(root: Mapping[str, Any]) -> str:
    value = materialize_json(root)
    if not isinstance(value, dict):
        raise TrustSnapshotStateError("invalid_snapshot_authority_root", "authority root must be an object")
    observed = value.get("authority_root_sha256")
    value["authority_root_sha256"] = ""
    expected = canonical_sha256(value)
    if observed != expected:
        raise TrustSnapshotStateError("snapshot_authority_root_digest_mismatch", "authority root digest mismatch")
    return expected


def _payload_for_signature(envelope: Mapping[str, Any]) -> dict[str, Any]:
    payload = materialize_json(envelope)
    if not isinstance(payload, dict):
        raise TrustSnapshotStateError("invalid_trust_snapshot_envelope", "envelope must be an object")
    for key in ("signature_b64", "envelope_sha256"):
        payload.pop(key, None)
    return payload


class ProvenanceTrustStateGuard:
    """Process-local guard with atomic in-process checkpoint acceptance."""

    def __init__(self, *, authority_roots: Sequence[Mapping[str, Any]]) -> None:
        if not isinstance(authority_roots, Sequence) or not authority_roots:
            raise TypeError("authority_roots must be a non-empty sequence")
        roots: list[dict[str, Any]] = []
        for root in authority_roots:
            if not isinstance(root, Mapping):
                raise TypeError("authority root must be a mapping")
            materialized = materialize_json(root)
            if not isinstance(materialized, dict):
                raise TypeError("authority root must materialize to object")
            _root_digest(materialized)
            roots.append(materialized)
        self._roots = tuple(roots)
        self._checkpoint: ProvenanceTrustCheckpoint | None = None
        self._lock = RLock()

    @classmethod
    def from_checkpoint(
        cls,
        *,
        authority_roots: Sequence[Mapping[str, Any]],
        checkpoint_receipt: Mapping[str, Any],
        trust_envelope: Mapping[str, Any],
        expected_checkpoint_sha256: str,
    ) -> "ProvenanceTrustStateGuard":
        """Restore one authenticated checkpoint under an external head anchor.

        The receipt self-digest is only tamper evidence.  Restart continuity
        additionally requires the exact signed envelope and a host-controlled
        expected-head digest stored outside this process.  No state is exposed
        until every receipt, envelope, root, time and identity binding passes.
        """

        guard = cls(authority_roots=authority_roots)

        try:
            receipt_value = materialize_json(checkpoint_receipt)
        except Exception as exc:
            raise TrustSnapshotStateError(
                "invalid_checkpoint_receipt_materialization",
                f"checkpoint receipt could not be materialized: {type(exc).__name__}",
            ) from exc
        receipt_result = validate_checkpoint_receipt(receipt_value)
        if receipt_result.get("status") != "PASS":
            errors = receipt_result.get("errors")
            first = errors[0] if isinstance(errors, list) and errors else {}
            code = str(first.get("code", "invalid_checkpoint_receipt"))
            message = str(first.get("message", "checkpoint receipt invalid"))
            raise TrustSnapshotStateError(code, message)
        if not isinstance(receipt_value, dict):  # guarded by validator; type narrowing
            raise TrustSnapshotStateError(
                "invalid_checkpoint_receipt_type",
                "checkpoint receipt must be an object",
            )

        if (
            not isinstance(expected_checkpoint_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_checkpoint_sha256) is None
        ):
            raise TrustSnapshotStateError(
                "invalid_checkpoint_restore_head",
                "expected checkpoint head must be 64 lowercase hexadecimal characters",
            )
        if receipt_value["checkpoint_sha256"] != expected_checkpoint_sha256:
            raise TrustSnapshotStateError(
                "checkpoint_restore_head_mismatch",
                "checkpoint receipt does not match the host-controlled expected head",
            )

        authenticated = guard.authenticate_envelope(trust_envelope)
        envelope = authenticated.envelope
        snapshot = authenticated.snapshot
        root_digest = _root_digest(authenticated.authority_root)

        exact_pairs = (
            ("sequence", envelope.get("sequence")),
            ("envelope_sha256", envelope.get("envelope_sha256")),
            ("snapshot_sha256", envelope.get("snapshot_sha256")),
            ("previous_envelope_sha256", envelope.get("previous_envelope_sha256")),
            ("issued_at", envelope.get("issued_at")),
            ("evaluation_tick", snapshot.get("evaluation_tick")),
            ("authority_id", envelope.get("authority_id")),
            ("key_id", envelope.get("key_id")),
            ("authority_root_sha256", root_digest),
        )
        for field, expected_value in exact_pairs:
            if receipt_value.get(field) != expected_value:
                raise TrustSnapshotStateError(
                    "checkpoint_restore_envelope_mismatch",
                    f"checkpoint receipt field {field} does not match the signed envelope",
                )

        evaluation_tick = int(receipt_value["evaluation_tick"])
        if evaluation_tick < int(envelope["issued_at"]):
            raise TrustSnapshotStateError(
                "checkpoint_restore_envelope_mismatch",
                "checkpoint evaluation time precedes envelope issuance",
            )
        if evaluation_tick > int(envelope["valid_until"]):
            raise TrustSnapshotStateError(
                "checkpoint_restore_envelope_mismatch",
                "checkpoint evaluation time exceeds envelope validity",
            )

        restored = ProvenanceTrustCheckpoint(
            sequence=int(receipt_value["sequence"]),
            envelope_sha256=str(receipt_value["envelope_sha256"]),
            snapshot_sha256=str(receipt_value["snapshot_sha256"]),
            previous_envelope_sha256=receipt_value["previous_envelope_sha256"],
            issued_at=int(receipt_value["issued_at"]),
            evaluation_tick=evaluation_tick,
            authority_id=str(receipt_value["authority_id"]),
            key_id=str(receipt_value["key_id"]),
            authority_root_sha256=str(receipt_value["authority_root_sha256"]),
        )
        if restored.as_dict() != receipt_value:
            raise TrustSnapshotStateError(
                "checkpoint_restore_receipt_mismatch",
                "restored checkpoint does not reproduce the exact public receipt",
            )
        with guard._lock:
            guard._checkpoint = restored
        return guard

    @property
    def checkpoint(self) -> ProvenanceTrustCheckpoint | None:
        with self._lock:
            return self._checkpoint

    @property
    def authority_roots(self) -> tuple[dict[str, Any], ...]:
        return tuple(deepcopy(root) for root in self._roots)

    def _select_root(self, authority_id: str, key_id: str) -> dict[str, Any]:
        matches = [
            root for root in self._roots
            if root.get("authority_id") == authority_id and root.get("key_id") == key_id
        ]
        if not matches:
            raise TrustSnapshotStateError("untrusted_snapshot_authority", "no matching snapshot authority root")
        if len(matches) > 1:
            raise TrustSnapshotStateError("ambiguous_snapshot_authority_root", "multiple roots match authority/key")
        return matches[0]

    def authenticate_envelope(self, value: Mapping[str, Any]) -> AuthenticatedTrustEnvelope:
        try:
            envelope = materialize_json(value)
        except Exception as exc:
            raise TrustSnapshotStateError(
                "invalid_trust_snapshot_envelope",
                f"envelope could not be materialized: {type(exc).__name__}",
            ) from exc
        if not isinstance(envelope, dict):
            raise TrustSnapshotStateError("invalid_trust_snapshot_envelope", "envelope must be an object")
        required = {
            "contract_id", "authority_id", "key_id", "sequence",
            "previous_envelope_sha256", "issued_at", "valid_until", "snapshot",
            "snapshot_sha256", "signature_b64", "envelope_sha256",
        }
        if required - envelope.keys():
            raise TrustSnapshotStateError("invalid_trust_snapshot_envelope", "envelope fields missing")
        if envelope.get("contract_id") != TRUST_SNAPSHOT_ENVELOPE_CONTRACT_ID:
            raise TrustSnapshotStateError("invalid_trust_snapshot_envelope", "unexpected envelope contract")
        if type(envelope.get("sequence")) is not int or envelope["sequence"] < 1:
            raise TrustSnapshotStateError("invalid_trust_snapshot_sequence", "sequence must be integer >= 1")
        for field in ("issued_at", "valid_until"):
            if type(envelope.get(field)) is not int or envelope[field] < 0:
                raise TrustSnapshotStateError("invalid_trust_snapshot_time", f"{field} must be integer >= 0")
        if envelope["valid_until"] < envelope["issued_at"]:
            raise TrustSnapshotStateError("invalid_trust_snapshot_time", "valid_until precedes issued_at")

        snapshot = envelope.get("snapshot")
        if not isinstance(snapshot, Mapping):
            raise TrustSnapshotStateError("invalid_trust_snapshot", "snapshot must be an object")
        snapshot_value = materialize_json(snapshot)
        if not isinstance(snapshot_value, dict):
            raise TrustSnapshotStateError("invalid_trust_snapshot", "snapshot must materialize to object")
        if snapshot_value.get("contract_id") != TRUST_SNAPSHOT_CONTRACT_ID:
            raise TrustSnapshotStateError("invalid_trust_snapshot", "unexpected snapshot contract")
        snapshot_digest = canonical_sha256(snapshot_value)
        if snapshot_digest != envelope.get("snapshot_sha256"):
            raise TrustSnapshotStateError("trust_snapshot_digest_mismatch", "snapshot digest mismatch")
        snapshot_tick = snapshot_value.get("evaluation_tick")
        if type(snapshot_tick) is not int or snapshot_tick < 0:
            raise TrustSnapshotStateError("invalid_trust_snapshot_time", "snapshot evaluation tick invalid")
        if snapshot_tick > envelope["issued_at"]:
            raise TrustSnapshotStateError(
                "future_trust_snapshot_state",
                "snapshot observation time is after envelope issuance",
            )

        envelope_digest = canonical_sha256(_payload_for_signature(envelope))
        if envelope_digest != envelope.get("envelope_sha256"):
            raise TrustSnapshotStateError("trust_snapshot_envelope_digest_mismatch", "envelope digest mismatch")

        root = self._select_root(str(envelope["authority_id"]), str(envelope["key_id"]))
        valid_from = root.get("valid_from")
        valid_until = root.get("valid_until")
        if type(valid_from) is not int or type(valid_until) is not int:
            raise TrustSnapshotStateError("invalid_snapshot_authority_root", "root validity must be integer")
        if not (valid_from <= envelope["issued_at"] <= valid_until):
            raise TrustSnapshotStateError("snapshot_authority_not_valid_at_issuance", "authority root not valid at issuance")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(str(root["public_key_b64"]), validate=True))
            signature = base64.b64decode(str(envelope["signature_b64"]), validate=True)
            public_key.verify(signature, canonical_json_bytes(_payload_for_signature(envelope)))
        except (KeyError, ValueError, InvalidSignature) as exc:
            raise TrustSnapshotStateError("invalid_snapshot_envelope_signature", "snapshot envelope signature invalid") from exc

        return AuthenticatedTrustEnvelope(
            envelope=envelope,
            snapshot=snapshot_value,
            authority_root=deepcopy(root),
        )

    def accept(
        self,
        value: Mapping[str, Any],
        *,
        evaluation_tick: int,
        expected_bundle_sha256: str | None = None,
        expected_trust_records_sha256: str | None = None,
    ) -> ProvenanceTrustCheckpoint:
        if type(evaluation_tick) is not int or evaluation_tick < 0:
            raise TrustSnapshotStateError("invalid_trust_snapshot_evaluation_time", "evaluation_tick must be integer >= 0")
        with self._lock:
            authenticated = self.authenticate_envelope(value)
            envelope = authenticated.envelope
            root = authenticated.authority_root
            if evaluation_tick < envelope["issued_at"]:
                raise TrustSnapshotStateError("future_trust_snapshot_envelope", "envelope issued after evaluation time")
            if evaluation_tick > envelope["valid_until"]:
                raise TrustSnapshotStateError("expired_trust_snapshot_envelope", "envelope expired")

            checkpoint = self._checkpoint
            if checkpoint is None:
                if envelope["sequence"] != 1 or envelope["previous_envelope_sha256"] is not None:
                    raise TrustSnapshotStateError("invalid_trust_snapshot_genesis", "genesis must be sequence 1 without parent")
            else:
                if evaluation_tick < checkpoint.evaluation_tick:
                    raise TrustSnapshotStateError("trust_snapshot_time_rollback", "evaluation time rollback")
                if envelope["sequence"] != checkpoint.sequence + 1:
                    raise TrustSnapshotStateError("trust_snapshot_sequence_mismatch", "successor sequence mismatch")
                if envelope["previous_envelope_sha256"] != checkpoint.envelope_sha256:
                    raise TrustSnapshotStateError("trust_snapshot_parent_mismatch", "successor parent mismatch")
                if (
                    envelope["authority_id"] != checkpoint.authority_id
                    or envelope["key_id"] != checkpoint.key_id
                    or _root_digest(root) != checkpoint.authority_root_sha256
                ):
                    raise TrustSnapshotStateError("trust_snapshot_root_continuity_mismatch", "authority root continuity mismatch")

            # Defense in depth at the mutation boundary.  The authority layer
            # performs the same comparison before analytical preparation, but
            # direct guard callers must not bypass exact snapshot-time binding.
            snapshot_tick = authenticated.snapshot["evaluation_tick"]
            if snapshot_tick < evaluation_tick:
                raise TrustSnapshotStateError(
                    "stale_trust_snapshot_state",
                    "trust snapshot evaluation_tick precedes commit evaluation_tick",
                )
            if snapshot_tick > evaluation_tick:
                raise TrustSnapshotStateError(
                    "future_trust_snapshot_state",
                    "trust snapshot evaluation_tick exceeds commit evaluation_tick",
                )

            # Exact subject binding is mandatory at the mutation boundary.
            # AuthorityAnalysisSession computes these values from one frozen
            # Analysis Bundle; low-level callers must supply the same bindings.
            if not isinstance(expected_bundle_sha256, str) or len(expected_bundle_sha256) != 64:
                raise TrustSnapshotStateError(
                    "trust_snapshot_subject_binding_required",
                    "expected bundle digest is required for checkpoint acceptance",
                )
            if not isinstance(expected_trust_records_sha256, str) or len(expected_trust_records_sha256) != 64:
                raise TrustSnapshotStateError(
                    "trust_snapshot_subject_binding_required",
                    "expected provenance digest is required for checkpoint acceptance",
                )
            if authenticated.snapshot.get("source_bundle_sha256") != expected_bundle_sha256:
                raise TrustSnapshotStateError(
                    "trust_snapshot_bundle_binding_mismatch",
                    "trust snapshot source bundle digest does not match commit subject",
                )
            if authenticated.snapshot.get("trust_records_sha256") != expected_trust_records_sha256:
                raise TrustSnapshotStateError(
                    "trust_snapshot_provenance_binding_mismatch",
                    "trust snapshot provenance digest does not match commit subject",
                )

            committed = ProvenanceTrustCheckpoint(
                sequence=int(envelope["sequence"]),
                envelope_sha256=str(envelope["envelope_sha256"]),
                snapshot_sha256=str(envelope["snapshot_sha256"]),
                previous_envelope_sha256=envelope["previous_envelope_sha256"],
                issued_at=int(envelope["issued_at"]),
                evaluation_tick=evaluation_tick,
                authority_id=str(envelope["authority_id"]),
                key_id=str(envelope["key_id"]),
                authority_root_sha256=_root_digest(root),
            )
            self._checkpoint = committed
            return committed


__all__ = [
    "AuthenticatedTrustEnvelope",
    "ProvenanceTrustCheckpoint",
    "ProvenanceTrustStateGuard",
    "SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID",
    "TRUST_CHECKPOINT_CONTRACT_ID",
    "TRUST_CHECKPOINT_V2_CONTRACT_ID",
    "TRUST_SNAPSHOT_CONTRACT_ID",
    "TRUST_SNAPSHOT_ENVELOPE_CONTRACT_ID",
    "TrustSnapshotStateError",
    "validate_checkpoint_receipt",
]
