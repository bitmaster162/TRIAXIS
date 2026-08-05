"""Authenticated TRIAXIS v3.6 action authorization and execution boundary."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .action_assurance import (
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    AUTHORIZATION_TOKEN_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    SQLiteExecutionLedger,
    authorize_action,
    seal_contract,
    validate_authorization_token,
)
from .crypto_trust import (
    PURPOSE_ACTION_APPROVAL,
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import materialize_json
from .policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID


def _error(code: str, path: str, message: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _same_digest(left: Mapping[str, Any] | None, right: Mapping[str, Any] | None, digest_field: str) -> bool:
    return isinstance(left, Mapping) and isinstance(right, Mapping) and left.get(digest_field) == right.get(digest_field)


def authorize_authenticated_action(
    *,
    action_value: Mapping[str, Any],
    policy_value: Mapping[str, Any],
    evaluation_tick: int,
    registry: TrustKeyRegistry,
    signed_assurance_attestation: Mapping[str, Any],
    signed_state_witness: Mapping[str, Any],
    signed_policy_bundle: Mapping[str, Any],
    signed_approvals: Sequence[Mapping[str, Any]],
    gate_key_id: str,
    gate_signer_id: str,
    gate_trust_domain: str,
    gate_private_key_b64: str,
) -> dict[str, Any]:
    """Authorize only when every authority-bearing input has a valid signature."""
    action = materialize_json(action_value)
    policy = materialize_json(policy_value)
    errors: list[dict[str, str]] = []

    assurance = action.get("assurance_attestation") if isinstance(action, dict) else None
    state = action.get("state_witness") if isinstance(action, dict) else None
    approvals = action.get("approvals") if isinstance(action, dict) else None
    if not isinstance(approvals, list):
        approvals = []

    assurance_result = verify_contract_envelope(
        signed_assurance_attestation,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
        expected_digest_field="attestation_sha256",
        expected_inner_contract_id=ASSURANCE_ATTESTATION_CONTRACT_ID,
        expected_signer_id=assurance.get("issuer_id") if isinstance(assurance, Mapping) else None,
        expected_trust_domain=assurance.get("trust_domain") if isinstance(assurance, Mapping) else None,
    )
    errors.extend(assurance_result["errors"])
    if not _same_digest(assurance_result.get("inner_contract"), assurance, "attestation_sha256"):
        errors.append(_error("assurance_signature_subject_mismatch", "signed_assurance_attestation", "signature does not wrap action attestation"))

    state_result = verify_contract_envelope(
        signed_state_witness,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_STATE_WITNESS,
        expected_digest_field="witness_sha256",
        expected_inner_contract_id=STATE_WITNESS_CONTRACT_ID,
        expected_signer_id=state.get("adapter_id") if isinstance(state, Mapping) else None,
    )
    errors.extend(state_result["errors"])
    if not _same_digest(state_result.get("inner_contract"), state, "witness_sha256"):
        errors.append(_error("state_signature_subject_mismatch", "signed_state_witness", "signature does not wrap action state witness"))

    policy_result = verify_contract_envelope(
        signed_policy_bundle,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_POLICY_BUNDLE,
        expected_digest_field="policy_sha256",
        expected_inner_contract_id=POLICY_BUNDLE_CONTRACT_ID,
        expected_signer_id=policy.get("issuer_id") if isinstance(policy, Mapping) else None,
    )
    errors.extend(policy_result["errors"])
    if not _same_digest(policy_result.get("inner_contract"), policy, "policy_sha256"):
        errors.append(_error("policy_signature_subject_mismatch", "signed_policy_bundle", "signature does not wrap exact policy"))

    by_digest: dict[str, Mapping[str, Any]] = {}
    for index, signed in enumerate(signed_approvals):
        result = verify_contract_envelope(
            signed,
            registry=registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_ACTION_APPROVAL,
            expected_digest_field="approval_sha256",
            expected_inner_contract_id=APPROVAL_CONTRACT_ID,
        )
        errors.extend({**item, "path": f"signed_approvals[{index}].{item['path']}"} for item in result["errors"])
        inner = result.get("inner_contract")
        if isinstance(inner, Mapping) and isinstance(inner.get("approval_sha256"), str):
            if result.get("verified_signer") is not None:
                if result["verified_signer"].signer_id != inner.get("principal_id"):
                    errors.append(_error("approval_signer_mismatch", f"signed_approvals[{index}]", "signer is not approval principal"))
                if result["verified_signer"].trust_domain != inner.get("trust_domain"):
                    errors.append(_error("approval_domain_mismatch", f"signed_approvals[{index}]", "signer trust domain mismatch"))
            by_digest[str(inner["approval_sha256"])] = inner

    expected_approval_digests = [item.get("approval_sha256") for item in approvals if isinstance(item, Mapping)]
    if len(signed_approvals) != len(expected_approval_digests):
        errors.append(_error("approval_signature_count_mismatch", "signed_approvals", "one signature required per approval"))
    for digest in expected_approval_digests:
        if not isinstance(digest, str) or digest not in by_digest:
            errors.append(_error("missing_approval_signature", "signed_approvals", str(digest)))

    trusted_assurance = {}
    signer = assurance_result.get("verified_signer")
    if signer is not None:
        trusted_assurance[signer.signer_id] = signer.trust_domain
    token = authorize_action(
        action,
        policy,
        evaluation_tick,
        gate_signer_id,
        trusted_assurance,
    )
    if errors:
        token = dict(token)
        token["outcome"] = "DENY"
        token["errors"] = list(token.get("errors", [])) + errors
        token = seal_contract(token, "token_sha256")

    signed_token = sign_contract_envelope(
        token,
        digest_field="token_sha256",
        purpose=PURPOSE_AUTHORIZATION_TOKEN,
        key_id=gate_key_id,
        signer_id=gate_signer_id,
        trust_domain=gate_trust_domain,
        private_key_b64=gate_private_key_b64,
        issued_at=evaluation_tick,
        valid_until=max(evaluation_tick + 1, int(token.get("expires_at", evaluation_tick + 1))),
    )
    gate_signature_result = verify_contract_envelope(
        signed_token,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_AUTHORIZATION_TOKEN,
        expected_digest_field="token_sha256",
        expected_inner_contract_id=AUTHORIZATION_TOKEN_CONTRACT_ID,
        expected_signer_id=gate_signer_id,
        expected_trust_domain=gate_trust_domain,
    )
    if gate_signature_result["status"] != "PASS":
        token = dict(token)
        token["outcome"] = "DENY"
        token["errors"] = list(token.get("errors", [])) + list(gate_signature_result["errors"])
        token = seal_contract(token, "token_sha256")
        signed_token = sign_contract_envelope(
            token,
            digest_field="token_sha256",
            purpose=PURPOSE_AUTHORIZATION_TOKEN,
            key_id=gate_key_id,
            signer_id=gate_signer_id,
            trust_domain=gate_trust_domain,
            private_key_b64=gate_private_key_b64,
            issued_at=evaluation_tick,
            valid_until=max(evaluation_tick + 1, int(token.get("expires_at", evaluation_tick + 1))),
        )
    return {
        "status": "PASS" if token.get("outcome") == "ALLOW" else "BLOCK",
        "errors": list(token.get("errors", [])),
        "token": token,
        "signed_token": signed_token,
        "verified_inputs": {
            "assurance": assurance_result["status"],
            "state": state_result["status"],
            "policy": policy_result["status"],
            "approvals": len(by_digest),
        },
    }


def validate_authenticated_authorization(
    signed_token_value: Mapping[str, Any],
    *,
    registry: TrustKeyRegistry,
    evaluation_tick: int,
) -> dict[str, Any]:
    signed_result = verify_contract_envelope(
        signed_token_value,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_AUTHORIZATION_TOKEN,
        expected_digest_field="token_sha256",
        expected_inner_contract_id=AUTHORIZATION_TOKEN_CONTRACT_ID,
    )
    token = signed_result.get("inner_contract")
    token_result = validate_authorization_token(token, evaluation_tick, require_allow=True) if isinstance(token, Mapping) else {"status": "BLOCK", "errors": []}
    errors = list(signed_result["errors"]) + list(token_result.get("errors", []))
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "token": token,
        "verified_signer": signed_result.get("verified_signer"),
    }


class AuthenticatedSQLiteExecutionLedger(SQLiteExecutionLedger):
    """Execution ledger that accepts only a cryptographically authenticated token and state."""

    def __init__(self, path: str | Path, registry: TrustKeyRegistry) -> None:
        super().__init__(path)
        self.registry = registry

    def prepare_authenticated(
        self,
        signed_token_value: Mapping[str, Any],
        signed_observed_state_value: Mapping[str, Any],
        evaluation_tick: int,
    ) -> dict[str, Any]:
        token_result = validate_authenticated_authorization(
            signed_token_value,
            registry=self.registry,
            evaluation_tick=evaluation_tick,
        )
        if token_result["status"] != "PASS":
            from .action_assurance import ExecutionLedgerError
            raise ExecutionLedgerError("invalid_authenticated_authorization", str(token_result["errors"]))
        token = token_result["token"]
        state_result = verify_contract_envelope(
            signed_observed_state_value,
            registry=self.registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_STATE_WITNESS,
            expected_digest_field="witness_sha256",
            expected_inner_contract_id=STATE_WITNESS_CONTRACT_ID,
        )
        if state_result["status"] != "PASS":
            from .action_assurance import ExecutionLedgerError
            raise ExecutionLedgerError("invalid_authenticated_state", str(state_result["errors"]))
        state = state_result["inner_contract"]
        signer = state_result.get("verified_signer")
        if signer is None or signer.signer_id != state.get("adapter_id"):
            from .action_assurance import ExecutionLedgerError
            raise ExecutionLedgerError("state_signer_mismatch", "state signer is not adapter")
        return super().prepare(token, state, evaluation_tick)


__all__ = [
    "AuthenticatedSQLiteExecutionLedger",
    "authorize_authenticated_action",
    "validate_authenticated_authorization",
]
