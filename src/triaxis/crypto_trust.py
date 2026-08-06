"""TRIAXIS v3.6 cryptographic trust boundary.

Canonical SHA-256 seals prove that bytes were not changed after sealing. They do
not prove who created the object. This module adds Ed25519 signatures, explicit
key purpose, trust-domain binding, validity windows and revocation-aware
verification around existing sealed TRIAXIS contracts.

Private keys are accepted only by signing helpers and are never stored in the
registry or returned in verification results.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .integrity import canonical_json_bytes, canonical_sha256, materialize_json, seal_mapping, verify_sealed_mapping

TRUST_KEY_RECORD_CONTRACT_ID = "TRIAXIS_ED25519_TRUST_KEY_v1"
SIGNED_CONTRACT_ENVELOPE_ID = "TRIAXIS_SIGNED_CONTRACT_ENVELOPE_v1"
SIGNATURE_ALGORITHM = "Ed25519"

PURPOSE_ASSURANCE_ATTESTATION = "ASSURANCE_ATTESTATION"
PURPOSE_STATE_WITNESS = "STATE_WITNESS"
PURPOSE_ACTION_APPROVAL = "ACTION_APPROVAL"
PURPOSE_POLICY_BUNDLE = "POLICY_BUNDLE"
PURPOSE_AUTHORIZATION_TOKEN = "AUTHORIZATION_TOKEN"
PURPOSE_EXECUTION_RECEIPT = "EXECUTION_RECEIPT"
PURPOSE_TRUST_REGISTRY_SNAPSHOT = "TRUST_REGISTRY_SNAPSHOT"
PURPOSE_TRUST_REGISTRY_ANCHOR = "TRUST_REGISTRY_ANCHOR"
PURPOSE_ANCHOR_QUORUM_POLICY = "ANCHOR_QUORUM_POLICY"
PURPOSE_POLICY_HEAD_AUTHORITY = "POLICY_HEAD_AUTHORITY"
PURPOSE_POLICY_TRANSPARENCY_WITNESS = "POLICY_TRANSPARENCY_WITNESS"
PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT = "POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT"
PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY = "POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY"
PURPOSE_SANDBOX_PROVISION_ATTESTATION = "SANDBOX_PROVISION_ATTESTATION"

KNOWN_PURPOSES = frozenset({
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_STATE_WITNESS,
    PURPOSE_ACTION_APPROVAL,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_EXECUTION_RECEIPT,
    PURPOSE_TRUST_REGISTRY_SNAPSHOT,
    PURPOSE_TRUST_REGISTRY_ANCHOR,
    PURPOSE_ANCHOR_QUORUM_POLICY,
    PURPOSE_POLICY_HEAD_AUTHORITY,
    PURPOSE_POLICY_TRANSPARENCY_WITNESS,
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_CHECKPOINT,
    PURPOSE_POLICY_TRANSPARENCY_GOSSIP_HEAD_AUTHORITY,
    PURPOSE_SANDBOX_PROVISION_ATTESTATION,
})


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("non-empty base64 string required")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("invalid base64") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"expected {expected_length} decoded bytes")
    return decoded


def generate_ed25519_keypair() -> dict[str, str]:
    """Generate a raw Ed25519 keypair for tests, local fixtures or provisioning."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return {
        "private_key_b64": _b64encode(
            private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
        "public_key_b64": _b64encode(public.public_bytes(Encoding.Raw, PublicFormat.Raw)),
    }


def make_trust_key_record(
    *,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    public_key_b64: str,
    purposes: Sequence[str],
    valid_from: int,
    valid_until: int,
    revoked_at: int | None = None,
) -> dict[str, Any]:
    record = {
        "contract_id": TRUST_KEY_RECORD_CONTRACT_ID,
        "key_id": key_id,
        "signer_id": signer_id,
        "trust_domain": trust_domain,
        "algorithm": SIGNATURE_ALGORITHM,
        "public_key_b64": public_key_b64,
        "purposes": sorted(set(purposes)),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "revoked_at": revoked_at,
        "key_record_sha256": "",
    }
    return seal_mapping(record, "key_record_sha256")


def validate_trust_key_record(value: Any) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "key", "mapping required")]}
    try:
        record = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "key", type(exc).__name__)]}
    if not isinstance(record, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "key", "object required")]}
    if record.get("contract_id") != TRUST_KEY_RECORD_CONTRACT_ID:
        errors.append(_error("invalid_contract_id", "key.contract_id", "unexpected key record contract"))
    if not verify_sealed_mapping(record, "key_record_sha256"):
        errors.append(_error("digest_mismatch", "key.key_record_sha256", "canonical digest mismatch"))
    for field in ("key_id", "signer_id", "trust_domain"):
        if not isinstance(record.get(field), str) or not record.get(field):
            errors.append(_error("missing_required", f"key.{field}", f"{field} required"))
    if record.get("algorithm") != SIGNATURE_ALGORITHM:
        errors.append(_error("unsupported_algorithm", "key.algorithm", SIGNATURE_ALGORITHM))
    try:
        _b64decode(record.get("public_key_b64"), 32)
    except ValueError as exc:
        errors.append(_error("invalid_public_key", "key.public_key_b64", str(exc)))
    purposes = record.get("purposes")
    if not isinstance(purposes, list) or not purposes or not all(isinstance(item, str) and item in KNOWN_PURPOSES for item in purposes):
        errors.append(_error("invalid_purposes", "key.purposes", "non-empty known-purpose array required"))
    elif len(set(purposes)) != len(purposes):
        errors.append(_error("duplicate_purpose", "key.purposes", "duplicate purpose"))
    valid_from, valid_until, revoked_at = record.get("valid_from"), record.get("valid_until"), record.get("revoked_at")
    if type(valid_from) is not int or valid_from < 0:
        errors.append(_error("invalid_valid_from", "key.valid_from", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "key.valid_until", "integer >= 0 required"))
    elif type(valid_from) is int and valid_until <= valid_from:
        errors.append(_error("invalid_key_window", "key.valid_until", "must be after valid_from"))
    if revoked_at is not None and (type(revoked_at) is not int or revoked_at < 0):
        errors.append(_error("invalid_revoked_at", "key.revoked_at", "integer >= 0 or null required"))
    return {"status": "PASS" if not errors else "BLOCK", "errors": errors, "record": record}


@dataclass(frozen=True)
class VerifiedSigner:
    key_id: str
    signer_id: str
    trust_domain: str
    purpose: str


class TrustKeyRegistry:
    """Out-of-band trust registry for Ed25519 public keys.

    Adding a record is an administrative trust decision. A content digest alone
    cannot enroll or replace a key.
    """

    def __init__(self, records: Sequence[Mapping[str, Any]] | None = None) -> None:
        self._records: dict[str, dict[str, Any]] = {}
        for record in records or []:
            self.add(record)

    def add(self, value: Mapping[str, Any]) -> None:
        result = validate_trust_key_record(value)
        if result["status"] != "PASS":
            raise ValueError(str(result["errors"]))
        record = result["record"]
        key_id = record["key_id"]
        current = self._records.get(key_id)
        if current is not None and current["key_record_sha256"] != record["key_record_sha256"]:
            raise ValueError("key_id already bound to another key record")
        self._records[key_id] = record

    def get(self, key_id: str) -> dict[str, Any] | None:
        value = self._records.get(key_id)
        return deepcopy(value) if value is not None else None

    def as_records(self) -> list[dict[str, Any]]:
        return [deepcopy(self._records[key]) for key in sorted(self._records)]


def _unsigned_envelope(value: Mapping[str, Any]) -> dict[str, Any]:
    result = materialize_json(value)
    if not isinstance(result, dict):
        raise TypeError("signed envelope must be an object")
    result["signature_b64"] = ""
    result["envelope_sha256"] = ""
    result["envelope_sha256"] = canonical_sha256(result)
    return result


def sign_contract_envelope(
    contract: Mapping[str, Any],
    *,
    digest_field: str,
    purpose: str,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    private_key_b64: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    if purpose not in KNOWN_PURPOSES:
        raise ValueError("unknown signing purpose")
    if not verify_sealed_mapping(contract, digest_field):
        raise ValueError("inner contract canonical digest is invalid")
    inner = materialize_json(contract)
    if not isinstance(inner, dict):
        raise TypeError("inner contract must be object")
    private = Ed25519PrivateKey.from_private_bytes(_b64decode(private_key_b64, 32))
    envelope = {
        "contract_id": SIGNED_CONTRACT_ENVELOPE_ID,
        "purpose": purpose,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signer_id": signer_id,
        "trust_domain": trust_domain,
        "issued_at": issued_at,
        "valid_until": valid_until,
        "inner_contract_id": inner.get("contract_id"),
        "inner_digest_field": digest_field,
        "inner_digest": inner.get(digest_field),
        "inner_contract": inner,
        "envelope_sha256": "",
        "signature_b64": "",
    }
    unsigned = _unsigned_envelope(envelope)
    signature = private.sign(canonical_json_bytes(unsigned))
    unsigned["signature_b64"] = _b64encode(signature)
    return unsigned


def verify_contract_envelope(
    value: Any,
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_purpose: str,
    expected_digest_field: str,
    expected_inner_contract_id: str | None = None,
    expected_signer_id: str | None = None,
    expected_trust_domain: str | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    if not isinstance(value, Mapping):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "signed", "mapping required")]}
    try:
        envelope = materialize_json(value)
    except Exception as exc:
        return {"status": "BLOCK", "errors": [_error("materialization_failed", "signed", type(exc).__name__)]}
    if not isinstance(envelope, dict):
        return {"status": "BLOCK", "errors": [_error("invalid_type", "signed", "object required")]}
    if envelope.get("contract_id") != SIGNED_CONTRACT_ENVELOPE_ID:
        errors.append(_error("invalid_contract_id", "signed.contract_id", "unexpected signed-envelope contract"))
    if envelope.get("purpose") != expected_purpose:
        errors.append(_error("purpose_mismatch", "signed.purpose", expected_purpose))
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        errors.append(_error("unsupported_algorithm", "signed.algorithm", SIGNATURE_ALGORITHM))
    if envelope.get("inner_digest_field") != expected_digest_field:
        errors.append(_error("digest_field_mismatch", "signed.inner_digest_field", expected_digest_field))
    inner = envelope.get("inner_contract")
    if not isinstance(inner, Mapping):
        errors.append(_error("invalid_inner_contract", "signed.inner_contract", "mapping required"))
        inner_obj = None
    else:
        inner_obj = materialize_json(inner)
        if not verify_sealed_mapping(inner_obj, expected_digest_field):
            errors.append(_error("inner_digest_mismatch", f"signed.inner_contract.{expected_digest_field}", "canonical digest mismatch"))
        if envelope.get("inner_digest") != inner_obj.get(expected_digest_field):
            errors.append(_error("inner_digest_binding_mismatch", "signed.inner_digest", "does not match inner contract"))
        if envelope.get("inner_contract_id") != inner_obj.get("contract_id"):
            errors.append(_error("inner_contract_id_binding_mismatch", "signed.inner_contract_id", "does not match inner contract"))
        if expected_inner_contract_id is not None and inner_obj.get("contract_id") != expected_inner_contract_id:
            errors.append(_error("inner_contract_id_mismatch", "signed.inner_contract.contract_id", expected_inner_contract_id))

    observed_envelope_digest = envelope.get("envelope_sha256")
    try:
        unsigned = _unsigned_envelope(envelope)
    except Exception as exc:
        errors.append(_error("invalid_envelope", "signed", type(exc).__name__))
        unsigned = None
    if unsigned is not None and observed_envelope_digest != unsigned.get("envelope_sha256"):
        errors.append(_error("envelope_digest_mismatch", "signed.envelope_sha256", "canonical envelope digest mismatch"))

    key_id = envelope.get("key_id")
    key_record = registry.get(key_id) if isinstance(key_id, str) else None
    if key_record is None:
        errors.append(_error("unknown_signing_key", "signed.key_id", "key not in trusted registry"))
    else:
        if envelope.get("signer_id") != key_record.get("signer_id"):
            errors.append(_error("signer_binding_mismatch", "signed.signer_id", "does not match key record"))
        if envelope.get("trust_domain") != key_record.get("trust_domain"):
            errors.append(_error("trust_domain_binding_mismatch", "signed.trust_domain", "does not match key record"))
        if expected_signer_id is not None and envelope.get("signer_id") != expected_signer_id:
            errors.append(_error("unexpected_signer", "signed.signer_id", expected_signer_id))
        if expected_trust_domain is not None and envelope.get("trust_domain") != expected_trust_domain:
            errors.append(_error("unexpected_trust_domain", "signed.trust_domain", expected_trust_domain))
        purposes = key_record.get("purposes")
        if not isinstance(purposes, list) or expected_purpose not in purposes:
            errors.append(_error("key_purpose_denied", "signed.purpose", "key not authorized for purpose"))

    issued_at, valid_until = envelope.get("issued_at"), envelope.get("valid_until")
    if type(issued_at) is not int or issued_at < 0:
        errors.append(_error("invalid_issued_at", "signed.issued_at", "integer >= 0 required"))
    if type(valid_until) is not int or valid_until < 0:
        errors.append(_error("invalid_valid_until", "signed.valid_until", "integer >= 0 required"))
    elif type(issued_at) is int and valid_until <= issued_at:
        errors.append(_error("invalid_signature_window", "signed.valid_until", "must be after issued_at"))
    if type(issued_at) is int and issued_at > evaluation_tick:
        errors.append(_error("future_signature", "signed.issued_at", "signature from the future"))
    if type(valid_until) is int and evaluation_tick >= valid_until:
        errors.append(_error("expired_signature", "signed.valid_until", "signature expired"))
    if key_record is not None:
        key_from, key_until, revoked_at = key_record.get("valid_from"), key_record.get("valid_until"), key_record.get("revoked_at")
        if type(issued_at) is int and type(key_from) is int and issued_at < key_from:
            errors.append(_error("key_not_yet_valid", "signed.issued_at", "signature predates key validity"))
        if type(valid_until) is int and type(key_until) is int and valid_until > key_until:
            errors.append(_error("signature_outlives_key", "signed.valid_until", "signature validity exceeds key validity"))
        if type(revoked_at) is int and evaluation_tick >= revoked_at:
            errors.append(_error("signing_key_revoked", "signed.key_id", "key revoked"))

    if key_record is not None and unsigned is not None:
        try:
            signature = _b64decode(envelope.get("signature_b64"), 64)
            public = Ed25519PublicKey.from_public_bytes(_b64decode(key_record.get("public_key_b64"), 32))
            public.verify(signature, canonical_json_bytes(unsigned))
        except InvalidSignature:
            errors.append(_error("invalid_signature", "signed.signature_b64", "Ed25519 verification failed"))
        except ValueError as exc:
            errors.append(_error("invalid_signature_encoding", "signed.signature_b64", str(exc)))

    signer = None
    if not errors and key_record is not None:
        signer = VerifiedSigner(
            key_id=str(key_record["key_id"]),
            signer_id=str(key_record["signer_id"]),
            trust_domain=str(key_record["trust_domain"]),
            purpose=expected_purpose,
        )
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "envelope": envelope,
        "inner_contract": inner_obj,
        "verified_signer": signer,
    }


__all__ = [
    "KNOWN_PURPOSES",
    "PURPOSE_ACTION_APPROVAL",
    "PURPOSE_ANCHOR_QUORUM_POLICY",
    "PURPOSE_ASSURANCE_ATTESTATION",
    "PURPOSE_AUTHORIZATION_TOKEN",
    "PURPOSE_EXECUTION_RECEIPT",
    "PURPOSE_POLICY_BUNDLE",
    "PURPOSE_POLICY_HEAD_AUTHORITY",
    "PURPOSE_POLICY_TRANSPARENCY_WITNESS",
    "PURPOSE_STATE_WITNESS",
    "PURPOSE_SANDBOX_PROVISION_ATTESTATION",
    "PURPOSE_TRUST_REGISTRY_SNAPSHOT",
    "PURPOSE_TRUST_REGISTRY_ANCHOR",
    "SIGNED_CONTRACT_ENVELOPE_ID",
    "SIGNATURE_ALGORITHM",
    "TRUST_KEY_RECORD_CONTRACT_ID",
    "TrustKeyRegistry",
    "VerifiedSigner",
    "generate_ed25519_keypair",
    "make_trust_key_record",
    "sign_contract_envelope",
    "validate_trust_key_record",
    "verify_contract_envelope",
]
