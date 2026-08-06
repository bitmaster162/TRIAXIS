"""TRIAXIS v3.23 external sandbox-provision attestation.

A canonical sandbox provision receipt only proves that a JSON object was not
modified after sealing.  It does not prove that an independent provisioner
observed the runtime state described by the receipt.  This module adds a
purpose-bound Ed25519 attestation and binds it to an exact bounded-subagent
contract.

The attestation is still a statement by the provisioner.  It is not remote
attestation, measured boot, TPM/HSM evidence, or proof that namespace IDs are
truthful.  Those remain an explicit physical trust boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .crypto_trust import (
    PURPOSE_SANDBOX_PROVISION_ATTESTATION,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .harness_v1 import (
    SANDBOX_PROVISION_RECEIPT_CONTRACT_ID,
    build_subagent_contract,
)
from .integrity import materialize_json, seal_mapping, verify_sealed_mapping

SANDBOX_PROVISION_ATTESTATION_CONTRACT_ID = "TRIAXIS_SANDBOX_PROVISION_ATTESTATION_v1"
ATTESTED_SUBAGENT_CONTRACT_ID = "TRIAXIS_ATTESTED_SUBAGENT_v1"


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def seal_sandbox_provision_attestation(
    sandbox_receipt: Mapping[str, Any],
    *,
    attestor_id: str,
    runtime_measurement_sha256: str,
    observed_features: Sequence[str],
    observed_at_tick: int,
    expires_at_tick: int,
) -> dict[str, Any]:
    """Create an exact subject for an external provisioner signature."""

    receipt = materialize_json(sandbox_receipt)
    if not isinstance(receipt, dict):
        raise TypeError("sandbox receipt must be an object")
    if receipt.get("contract_id") != SANDBOX_PROVISION_RECEIPT_CONTRACT_ID:
        raise ValueError("unexpected sandbox receipt contract")
    if not verify_sealed_mapping(receipt, "receipt_sha256"):
        raise ValueError("sandbox receipt digest mismatch")
    if receipt.get("status") != "PASS":
        raise ValueError("only PASS provision receipts may be attested")
    if not isinstance(attestor_id, str) or not attestor_id:
        raise ValueError("attestor_id required")
    if not _is_sha256(runtime_measurement_sha256):
        raise ValueError("runtime_measurement_sha256 required")
    features = sorted(set(observed_features))
    if not features or not all(isinstance(item, str) and item for item in features):
        raise ValueError("non-empty observed_features required")
    if type(observed_at_tick) is not int or type(expires_at_tick) is not int:
        raise TypeError("attestation time window must be integers")
    if observed_at_tick < 0 or expires_at_tick <= observed_at_tick:
        raise ValueError("invalid attestation time window")
    receipt_expires = receipt.get("expires_at_tick")
    if type(receipt_expires) is not int or expires_at_tick > receipt_expires:
        raise ValueError("attestation cannot outlive provision receipt")

    body = {
        "contract_id": SANDBOX_PROVISION_ATTESTATION_CONTRACT_ID,
        "attestor_id": attestor_id,
        "sandbox_receipt_sha256": receipt["receipt_sha256"],
        "plan_sha256": receipt["plan_sha256"],
        "sandbox_id": receipt["sandbox_id"],
        "profile_id": receipt["profile_id"],
        "child_session_id": receipt["child_session_id"],
        "repository_manifest_sha256": receipt.get("repository_manifest_sha256"),
        "backend_id": receipt["backend_id"],
        "state_dir_id": receipt["state_dir_id"],
        "pid_namespace_id": receipt["pid_namespace_id"],
        "mount_namespace_id": receipt["mount_namespace_id"],
        "network_namespace_id": receipt["network_namespace_id"],
        "effective_capabilities": sorted(set(receipt.get("effective_capabilities", []))),
        "network_mode": receipt["network_mode"],
        "runtime_measurement_sha256": runtime_measurement_sha256,
        "observed_features": features,
        "observed_at_tick": observed_at_tick,
        "expires_at_tick": expires_at_tick,
        "attestation_sha256": "",
    }
    return seal_mapping(body, "attestation_sha256")


def sign_sandbox_provision_attestation(
    attestation: Mapping[str, Any],
    *,
    key_id: str,
    signer_id: str,
    trust_domain: str,
    private_key_b64: str,
    issued_at: int,
    valid_until: int,
) -> dict[str, Any]:
    return sign_contract_envelope(
        attestation,
        digest_field="attestation_sha256",
        purpose=PURPOSE_SANDBOX_PROVISION_ATTESTATION,
        key_id=key_id,
        signer_id=signer_id,
        trust_domain=trust_domain,
        private_key_b64=private_key_b64,
        issued_at=issued_at,
        valid_until=valid_until,
    )


def verify_sandbox_provision_attestation(
    signed_attestation: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_sandbox_receipt: Mapping[str, Any],
    required_features: Sequence[str] = (),
    allowed_trust_domains: Sequence[str] = (),
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    receipt = materialize_json(expected_sandbox_receipt)
    if not isinstance(receipt, dict) or not verify_sealed_mapping(receipt, "receipt_sha256"):
        return {"status": "BLOCK", "errors": [_error("invalid_sandbox_receipt", "receipt", "sealed receipt required")]}

    verified = verify_contract_envelope(
        signed_attestation,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_SANDBOX_PROVISION_ATTESTATION,
        expected_digest_field="attestation_sha256",
        expected_inner_contract_id=SANDBOX_PROVISION_ATTESTATION_CONTRACT_ID,
    )
    errors.extend(verified["errors"])
    attestation = verified.get("inner_contract")
    signer = verified.get("verified_signer")
    if isinstance(attestation, Mapping):
        exact_fields = {
            "sandbox_receipt_sha256": "receipt_sha256",
            "plan_sha256": "plan_sha256",
            "sandbox_id": "sandbox_id",
            "profile_id": "profile_id",
            "child_session_id": "child_session_id",
            "repository_manifest_sha256": "repository_manifest_sha256",
            "backend_id": "backend_id",
            "state_dir_id": "state_dir_id",
            "pid_namespace_id": "pid_namespace_id",
            "mount_namespace_id": "mount_namespace_id",
            "network_namespace_id": "network_namespace_id",
            "network_mode": "network_mode",
        }
        for attestation_field, receipt_field in exact_fields.items():
            if attestation.get(attestation_field) != receipt.get(receipt_field):
                errors.append(_error("attestation_subject_mismatch", f"attestation.{attestation_field}", receipt_field))
        if sorted(attestation.get("effective_capabilities", [])) != sorted(receipt.get("effective_capabilities", [])):
            errors.append(_error("attestation_capability_mismatch", "attestation.effective_capabilities", "receipt mismatch"))
        if not _is_sha256(attestation.get("runtime_measurement_sha256")):
            errors.append(_error("invalid_runtime_measurement", "attestation.runtime_measurement_sha256", "SHA-256 required"))
        observed_features = attestation.get("observed_features")
        if not isinstance(observed_features, list) or not all(isinstance(item, str) and item for item in observed_features):
            errors.append(_error("invalid_observed_features", "attestation.observed_features", "string array required"))
            observed_feature_set: set[str] = set()
        else:
            observed_feature_set = set(observed_features)
        missing = set(required_features) - observed_feature_set
        if missing:
            errors.append(_error("required_feature_missing", "attestation.observed_features", str(sorted(missing))))
        observed_at = attestation.get("observed_at_tick")
        expires_at = attestation.get("expires_at_tick")
        if type(observed_at) is not int or type(expires_at) is not int or observed_at > evaluation_tick or evaluation_tick >= expires_at:
            errors.append(_error("attestation_time_invalid", "attestation.expires_at_tick", str(evaluation_tick)))
        if isinstance(signer, object) and signer is not None:
            if attestation.get("attestor_id") != signer.signer_id:
                errors.append(_error("attestor_signer_mismatch", "attestation.attestor_id", signer.signer_id))
            if allowed_trust_domains and signer.trust_domain not in set(allowed_trust_domains):
                errors.append(_error("attestor_trust_domain_denied", "signed.trust_domain", signer.trust_domain))

    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "attestation": materialize_json(attestation) if isinstance(attestation, Mapping) else None,
        "signed_envelope": verified.get("envelope"),
        "verified_signer": signer,
    }


def build_attested_subagent_contract(
    parent_session: Mapping[str, Any],
    request: Mapping[str, Any],
    effective_config: Mapping[str, Any],
    *,
    repository_manifest: Mapping[str, Any],
    sandbox_receipt: Mapping[str, Any],
    signed_sandbox_attestation: Mapping[str, Any],
    trust_registry: TrustKeyRegistry,
    evaluation_tick: int,
    required_features: Sequence[str] = (),
    allowed_trust_domains: Sequence[str] = (),
) -> dict[str, Any]:
    """Build a v2 subagent contract requiring external provisioner identity."""

    base = build_subagent_contract(
        parent_session,
        request,
        effective_config,
        repository_manifest=repository_manifest,
        sandbox_receipt=sandbox_receipt,
        evaluation_tick=evaluation_tick,
    )
    errors = list(base.get("errors", []))
    attested = verify_sandbox_provision_attestation(
        signed_sandbox_attestation,
        registry=trust_registry,
        evaluation_tick=evaluation_tick,
        expected_sandbox_receipt=sandbox_receipt,
        required_features=required_features,
        allowed_trust_domains=allowed_trust_domains,
    )
    errors.extend(attested["errors"])
    envelope = attested.get("signed_envelope") or {}
    expected_envelope_digest = request.get("sandbox_attestation_envelope_sha256")
    if expected_envelope_digest != envelope.get("envelope_sha256"):
        errors.append(_error("sandbox_attestation_binding_mismatch", "request.sandbox_attestation_envelope_sha256", "exact signed envelope required"))
    signer = attested.get("verified_signer")
    inner = attested.get("attestation") or {}
    result = {
        "contract_id": ATTESTED_SUBAGENT_CONTRACT_ID,
        "base_subagent_sha256": base.get("subagent_sha256"),
        "parent_session_id": base.get("parent_session_id"),
        "child_session_id": base.get("child_session_id"),
        "capability_mode": base.get("capability_mode"),
        "effective_capabilities": base.get("effective_capabilities", []),
        "repository_manifest_sha256": base.get("repository_manifest_sha256"),
        "sandbox_receipt_sha256": base.get("sandbox_receipt_sha256"),
        "sandbox_attestation_envelope_sha256": envelope.get("envelope_sha256"),
        "sandbox_attestation_sha256": inner.get("attestation_sha256"),
        "runtime_measurement_sha256": inner.get("runtime_measurement_sha256"),
        "observed_features": inner.get("observed_features", []),
        "attestor_key_id": getattr(signer, "key_id", None),
        "attestor_id": getattr(signer, "signer_id", None),
        "attestor_trust_domain": getattr(signer, "trust_domain", None),
        "status": "PASS" if not errors and base.get("status") == "PASS" and attested.get("status") == "PASS" else "BLOCK",
        "errors": errors,
        "attested_subagent_sha256": "",
    }
    return seal_mapping(result, "attested_subagent_sha256")


__all__ = [
    "ATTESTED_SUBAGENT_CONTRACT_ID",
    "SANDBOX_PROVISION_ATTESTATION_CONTRACT_ID",
    "build_attested_subagent_contract",
    "seal_sandbox_provision_attestation",
    "sign_sandbox_provision_attestation",
    "verify_sandbox_provision_attestation",
]
