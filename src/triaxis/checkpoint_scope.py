"""Authority-signed cross-database scope binding for TRIAXIS checkpoints.

A database-local owner row can prevent reuse inside one SQLite file, but it
cannot express the authority's intended namespace when the same authenticated
checkpoint is transported to a fresh database.  This module verifies a compact
Ed25519-signed scope envelope before durable commit or scoped restore.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .integrity import canonical_json_bytes, canonical_sha256, materialize_json
from .provenance_trust_state import (
    ProvenanceTrustStateGuard,
    SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID,
)

CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID = "TRIAXIS_CHECKPOINT_SCOPE_ENVELOPE_v1"
CHECKPOINT_NAMESPACE_CONTRACT_ID = "TRIAXIS_CHECKPOINT_NAMESPACE_v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")


class CheckpointScopeError(ValueError):
    """Fail-closed scope-envelope error with a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class AuthenticatedCheckpointScope:
    """One detached, authenticated checkpoint namespace authorization."""

    envelope: dict[str, Any]
    authority_root: dict[str, Any]

    @property
    def checkpoint_sha256(self) -> str:
        return str(self.envelope["checkpoint_sha256"])

    @property
    def trust_envelope_sha256(self) -> str:
        return str(self.envelope["envelope_sha256"])

    @property
    def namespace_sha256(self) -> str:
        return str(self.envelope["namespace_sha256"])

    @property
    def scope_envelope_sha256(self) -> str:
        return str(self.envelope["scope_envelope_sha256"])


def checkpoint_namespace_sha256(namespace: str) -> str:
    """Return the canonical digest of one exact checkpoint namespace."""

    if not isinstance(namespace, str) or not namespace or len(namespace) > 512:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_namespace",
            "namespace must be a non-empty string of at most 512 characters",
        )
    if "\x00" in namespace:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_namespace",
            "namespace cannot contain NUL",
        )
    return canonical_sha256(
        {
            "contract_id": CHECKPOINT_NAMESPACE_CONTRACT_ID,
            "namespace": namespace,
        }
    )


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _materialize_scope(value: Any) -> dict[str, Any]:
    if value is None:
        raise CheckpointScopeError(
            "checkpoint_scope_envelope_required",
            "scoped checkpoint ingress requires a signed scope envelope",
        )
    try:
        envelope = materialize_json(value)
    except Exception as exc:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            f"checkpoint scope envelope could not be materialized: {type(exc).__name__}",
        ) from exc
    if not isinstance(envelope, dict):
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            "checkpoint scope envelope must be an object",
        )
    return envelope


def _scope_payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(envelope)
    payload.pop("signature_b64", None)
    payload.pop("scope_envelope_sha256", None)
    return payload


def _select_authority_root(
    authority_roots: Sequence[Mapping[str, Any]],
    *,
    authority_id: str,
    key_id: str,
) -> dict[str, Any]:
    try:
        guard = ProvenanceTrustStateGuard(authority_roots=authority_roots)
    except Exception as exc:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_authority_root",
            f"checkpoint scope authority roots are invalid: {type(exc).__name__}",
        ) from exc
    matches = [
        root
        for root in guard.authority_roots
        if root.get("authority_id") == authority_id and root.get("key_id") == key_id
    ]
    if not matches:
        raise CheckpointScopeError(
            "untrusted_checkpoint_scope_authority",
            "no authority root matches the checkpoint scope issuer",
        )
    if len(matches) != 1:
        raise CheckpointScopeError(
            "ambiguous_checkpoint_scope_authority",
            "multiple authority roots match the checkpoint scope issuer",
        )
    root = matches[0]
    if root.get("contract_id") != SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_authority_root",
            "checkpoint scope authority root uses an unexpected contract",
        )
    return root


def checkpoint_scope_schema_document() -> dict[str, Any]:
    """Return the machine-readable structural contract for scope envelope v1."""

    hash_schema = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:triaxis:checkpoint-scope-envelope:v1",
        "title": "TRIAXIS Checkpoint Scope Envelope v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "contract_id",
            "authority_id",
            "key_id",
            "namespace_sha256",
            "checkpoint_sha256",
            "envelope_sha256",
            "issued_at",
            "valid_until",
            "signature_b64",
            "scope_envelope_sha256",
        ],
        "properties": {
            "contract_id": {"const": CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID},
            "authority_id": {"type": "string", "minLength": 1},
            "key_id": {"type": "string", "minLength": 1},
            "namespace_sha256": dict(hash_schema),
            "checkpoint_sha256": dict(hash_schema),
            "envelope_sha256": dict(hash_schema),
            "issued_at": {"type": "integer", "minimum": 0},
            "valid_until": {"type": "integer", "minimum": 0},
            "signature_b64": {"type": "string", "minLength": 1},
            "scope_envelope_sha256": dict(hash_schema),
        },
    }


def verify_checkpoint_scope_envelope(
    value: Mapping[str, Any] | None,
    *,
    namespace: str,
    checkpoint_sha256: str,
    trust_envelope_sha256: str,
    authority_roots: Sequence[Mapping[str, Any]],
    trusted_evaluation_tick: int,
) -> AuthenticatedCheckpointScope:
    """Authenticate and exactly bind one checkpoint scope envelope.

    The caller-controlled host tick must be an integer and is checked against
    both the scope validity interval and the authority root validity at
    issuance.  The returned objects are detached from all caller mappings.
    """

    envelope = _materialize_scope(value)
    required = {
        "contract_id",
        "authority_id",
        "key_id",
        "namespace_sha256",
        "checkpoint_sha256",
        "envelope_sha256",
        "issued_at",
        "valid_until",
        "signature_b64",
        "scope_envelope_sha256",
    }
    missing = sorted(required - envelope.keys())
    if missing:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            f"checkpoint scope envelope is missing field {missing[0]}",
        )
    extras = sorted(envelope.keys() - required)
    if extras:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            f"checkpoint scope envelope contains unknown field {extras[0]}",
        )
    if envelope.get("contract_id") != CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            "unexpected checkpoint scope envelope contract",
        )
    for field in ("authority_id", "key_id"):
        if not isinstance(envelope.get(field), str) or not envelope[field]:
            raise CheckpointScopeError(
                "invalid_checkpoint_scope_envelope",
                f"checkpoint scope field {field} must be a non-empty string",
            )
    for field in (
        "namespace_sha256",
        "checkpoint_sha256",
        "envelope_sha256",
        "scope_envelope_sha256",
    ):
        if not _is_hex64(envelope.get(field)):
            raise CheckpointScopeError(
                "invalid_checkpoint_scope_envelope",
                f"checkpoint scope field {field} must be 64 lowercase hexadecimal characters",
            )
    for field in ("issued_at", "valid_until"):
        if type(envelope.get(field)) is not int or envelope[field] < 0:
            raise CheckpointScopeError(
                "invalid_checkpoint_scope_envelope",
                f"checkpoint scope field {field} must be an integer >= 0",
            )
    if type(trusted_evaluation_tick) is not int or trusted_evaluation_tick < 0:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_time",
            "trusted evaluation tick must be an integer >= 0",
        )
    if envelope["valid_until"] < envelope["issued_at"]:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_envelope",
            "checkpoint scope valid_until precedes issued_at",
        )

    payload = _scope_payload(envelope)
    expected_scope_digest = canonical_sha256(payload)
    if envelope["scope_envelope_sha256"] != expected_scope_digest:
        raise CheckpointScopeError(
            "checkpoint_scope_digest_mismatch",
            "checkpoint scope envelope digest mismatch",
        )

    expected_namespace_digest = checkpoint_namespace_sha256(namespace)
    if envelope["namespace_sha256"] != expected_namespace_digest:
        raise CheckpointScopeError(
            "checkpoint_scope_namespace_mismatch",
            "checkpoint scope is signed for another namespace",
        )
    if (
        envelope["checkpoint_sha256"] != checkpoint_sha256
        or envelope["envelope_sha256"] != trust_envelope_sha256
    ):
        raise CheckpointScopeError(
            "checkpoint_scope_subject_mismatch",
            "checkpoint scope subject does not match the exact receipt and trust envelope",
        )

    issued_at = int(envelope["issued_at"])
    valid_until = int(envelope["valid_until"])
    if trusted_evaluation_tick < issued_at:
        raise CheckpointScopeError(
            "future_checkpoint_scope_envelope",
            "checkpoint scope envelope was issued after the trusted evaluation time",
        )
    if trusted_evaluation_tick > valid_until:
        raise CheckpointScopeError(
            "expired_checkpoint_scope_envelope",
            "checkpoint scope envelope expired before the trusted evaluation time",
        )

    root = _select_authority_root(
        authority_roots,
        authority_id=str(envelope["authority_id"]),
        key_id=str(envelope["key_id"]),
    )
    valid_from = root.get("valid_from")
    root_valid_until = root.get("valid_until")
    if type(valid_from) is not int or type(root_valid_until) is not int:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_authority_root",
            "checkpoint scope authority root validity must be integer",
        )
    if not (valid_from <= issued_at <= root_valid_until):
        raise CheckpointScopeError(
            "checkpoint_scope_authority_not_valid_at_issuance",
            "checkpoint scope authority root was not valid at issuance",
        )
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(str(root["public_key_b64"]), validate=True)
        )
        signature = base64.b64decode(str(envelope["signature_b64"]), validate=True)
        public_key.verify(signature, canonical_json_bytes(payload))
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise CheckpointScopeError(
            "invalid_checkpoint_scope_signature",
            "checkpoint scope envelope signature is invalid",
        ) from exc

    return AuthenticatedCheckpointScope(
        envelope=deepcopy(envelope),
        authority_root=deepcopy(root),
    )


__all__ = [
    "AuthenticatedCheckpointScope",
    "CHECKPOINT_NAMESPACE_CONTRACT_ID",
    "CHECKPOINT_SCOPE_ENVELOPE_CONTRACT_ID",
    "CheckpointScopeError",
    "checkpoint_namespace_sha256",
    "checkpoint_scope_schema_document",
    "verify_checkpoint_scope_envelope",
]
