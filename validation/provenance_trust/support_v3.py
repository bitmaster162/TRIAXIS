"""Deterministic validation-only signing fixtures for Trust Snapshot envelopes."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from triaxis.integrity import canonical_json_bytes, canonical_sha256, materialize_json
from triaxis.provenance_trust_state import (
    SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID,
    TRUST_SNAPSHOT_ENVELOPE_CONTRACT_ID,
)

_AUTHORITY_ID = "authority:triaxis-recovery-validation"
_KEY_ID = "snapshot-authority-key-recovery-001"
# Public, deterministic, non-secret validation fixture.  The seed is derived
# from a domain-separated label so no operational credential or private key
# material is stored in the repository.  Never use this signer outside tests.
_VALIDATION_SEED = hashlib.sha256(
    b"TRIAXIS public deterministic validation signer v1 - NOT A SECRET"
).digest()
_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(_VALIDATION_SEED)
_PUBLIC_KEY = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def build_snapshot_authority_root(
    *,
    valid_from: int = 0,
    valid_until: int = 200,
) -> dict[str, Any]:
    root = {
        "contract_id": SNAPSHOT_AUTHORITY_ROOT_CONTRACT_ID,
        "authority_id": _AUTHORITY_ID,
        "key_id": _KEY_ID,
        "public_key_b64": base64.b64encode(_PUBLIC_KEY).decode("ascii"),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "authority_root_sha256": "",
    }
    root["authority_root_sha256"] = canonical_sha256(root)
    return root


def seal_snapshot_envelope(
    snapshot: Mapping[str, Any],
    *,
    sequence: int,
    previous_envelope_sha256: str | None,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    snapshot_value = materialize_json(snapshot)
    payload = {
        "contract_id": TRUST_SNAPSHOT_ENVELOPE_CONTRACT_ID,
        "authority_id": _AUTHORITY_ID,
        "key_id": _KEY_ID,
        "sequence": sequence,
        "previous_envelope_sha256": previous_envelope_sha256,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "snapshot": snapshot_value,
        "snapshot_sha256": canonical_sha256(snapshot_value),
    }
    digest = canonical_sha256(payload)
    signature = _PRIVATE_KEY.sign(canonical_json_bytes(payload))
    return {
        **payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "envelope_sha256": digest,
    }


__all__ = ["build_snapshot_authority_root", "seal_snapshot_envelope"]
