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
    PURPOSE_RISK_MEDIATION_RECEIPT,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    sign_contract_envelope,
    verify_contract_envelope,
)
from .integrity import canonical_sha256, materialize_json
from .policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID
from .risk_mediation import (
    RISK_MEDIATION_RECEIPT_CONTRACT_ID,
    RiskFactsAdapter,
    RiskMediatedAuthorizationBoundary,
    RiskMediationError,
    TrustedRiskFactsAdapterRegistry,
    validate_risk_mediation_receipt,
)


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
    authorization_mode: str | Any = "legacy",
    pep: Any = None,
    identity_mode: str = "explicit_reference",
    workload_identity_provider: Any = None,
    trusted_provider_registry: Any = None,
    provider_id: str = "spiffe_spire_local",
    allow_unregistered_providers: bool = False,
    risk_adapter: RiskFactsAdapter | None = None,
    trusted_risk_adapter_registry: TrustedRiskFactsAdapterRegistry | None = None,
    risk_adapter_id: str | None = None,
    risk_adapter_version: int | None = None,
) -> dict[str, Any]:
    """Authorize authenticated inputs, optionally with mandatory risk mediation.

    Risk mediation wraps the exact existing ``authorize_action`` configuration,
    including Cedar/PEP and workload-identity modes. It does not replace the
    selected authorization implementation. Pre-authorization authentication or
    mediation failures return a local sealed DENY without invoking the selected
    PDP or workload-identity provider.

    Legacy callers that omit mediation retain historical signed-token issuance
    behavior, while authenticated PREPARED boundaries require a separately
    authenticated mediation receipt.
    """

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

    risk_config = (
        risk_adapter,
        trusted_risk_adapter_registry,
        risk_adapter_id,
        risk_adapter_version,
    )
    risk_mediation_requested = any(item is not None for item in risk_config)
    risk_mediation_complete = all(item is not None for item in risk_config)
    if risk_mediation_requested and not risk_mediation_complete:
        errors.append(
            _error(
                "RISK_MEDIATION_CONFIGURATION_INCOMPLETE",
                "risk_mediation",
                "adapter, trusted registry, adapter id and adapter version are all required",
            )
        )

    trusted_assurance = {}
    signer = assurance_result.get("verified_signer")
    if signer is not None:
        trusted_assurance[signer.signer_id] = signer.trust_domain

    def _authorize_existing(
        exact_action: Mapping[str, Any],
        *,
        evaluation_tick: int,
    ) -> Mapping[str, Any]:
        return authorize_action(
            exact_action,
            policy,
            evaluation_tick,
            gate_signer_id,
            trusted_assurance,
            authorization_mode=authorization_mode,
            pep=pep,
            identity_mode=identity_mode,
            workload_identity_provider=workload_identity_provider,
            trusted_provider_registry=trusted_provider_registry,
            provider_id=provider_id,
            allow_unregistered_providers=allow_unregistered_providers,
        )

    def _preauthorization_deny(current_errors: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        expiry_sources = {
            "action_expires_at": action.get("expires_at") if isinstance(action, Mapping) else None,
            "policy_valid_until": policy.get("valid_until") if isinstance(policy, Mapping) else None,
            "assurance_valid_until": assurance.get("valid_until") if isinstance(assurance, Mapping) else None,
            "state_valid_until": state.get("valid_until") if isinstance(state, Mapping) else None,
            "approval_expires_at": sorted(
                item.get("expires_at")
                for item in approvals
                if isinstance(item, Mapping) and type(item.get("expires_at")) is int
            ),
        }
        candidates = [
            value
            for key, value in expiry_sources.items()
            if key != "approval_expires_at" and type(value) is int
        ] + list(expiry_sources["approval_expires_at"])
        effective_expires_at = min(candidates) if candidates else evaluation_tick + 1
        decision_sha256 = canonical_sha256(
            {
                "stage": "AUTHENTICATED_PREAUTHORIZATION_DENY",
                "errors": list(current_errors),
            }
        )
        token = {
            "contract_id": AUTHORIZATION_TOKEN_CONTRACT_ID,
            "issuer_id": gate_signer_id,
            "outcome": "DENY",
            "action_sha256": action.get("action_sha256") if isinstance(action, Mapping) else None,
            "scope_sha256": action.get("scope_sha256") if isinstance(action, Mapping) else None,
            "decision_case_sha256": action.get("decision_case_sha256") if isinstance(action, Mapping) else None,
            "evidence_report_sha256": action.get("evidence_report_sha256") if isinstance(action, Mapping) else None,
            "assured_action_request_sha256": action.get("assured_action_request_sha256") if isinstance(action, Mapping) else None,
            "assurance_attestation_sha256": assurance.get("attestation_sha256") if isinstance(assurance, Mapping) else None,
            "assurance_issuer_id": assurance.get("issuer_id") if isinstance(assurance, Mapping) else None,
            "subject_id": action.get("subject_id") if isinstance(action, Mapping) else None,
            "object_id": action.get("object_id") if isinstance(action, Mapping) else None,
            "capability": action.get("capability") if isinstance(action, Mapping) else None,
            "tool_id": action.get("tool_id") if isinstance(action, Mapping) else None,
            "execution_target": action.get("execution_target") if isinstance(action, Mapping) else None,
            "payload_sha256": action.get("payload_sha256") if isinstance(action, Mapping) else None,
            "policy_id": action.get("policy_id") if isinstance(action, Mapping) else None,
            "policy_sequence": action.get("policy_sequence") if isinstance(action, Mapping) else None,
            "policy_sha256": policy.get("policy_sha256") if isinstance(policy, Mapping) else None,
            "policy_decision_sha256": decision_sha256,
            "state_witness_sha256": state.get("witness_sha256") if isinstance(state, Mapping) else None,
            "state_version": state.get("version") if isinstance(state, Mapping) else None,
            "risk_class": action.get("risk_class") if isinstance(action, Mapping) else None,
            "nonce": action.get("nonce") if isinstance(action, Mapping) else None,
            "issued_at": evaluation_tick,
            "expires_at": effective_expires_at,
            "expiry_sources": expiry_sources,
            "errors": list(current_errors),
            "token_sha256": "",
        }
        return seal_contract(token, "token_sha256")

    risk_mediation_receipt: dict[str, Any] | None = None

    if errors:
        token = _preauthorization_deny(errors)
    elif risk_mediation_complete:
        try:
            mediated = RiskMediatedAuthorizationBoundary(
                authorizer=_authorize_existing,
                risk_adapter=risk_adapter,
                trusted_registry=trusted_risk_adapter_registry,
                adapter_id=risk_adapter_id,
                adapter_version=risk_adapter_version,
            ).authorize(
                action,
                evaluation_tick=evaluation_tick,
            )
        except RiskMediationError as exc:
            errors.append(_error(exc.code, "risk_mediation", str(exc)))
            token = _preauthorization_deny(errors)
        except (TypeError, ValueError) as exc:
            errors.append(
                _error(
                    "RISK_MEDIATION_CONFIGURATION_INVALID",
                    "risk_mediation",
                    str(exc),
                )
            )
            token = _preauthorization_deny(errors)
        else:
            token = mediated.authorization
            risk_mediation_receipt = mediated.risk_mediation_receipt
    else:
        token = _authorize_existing(action, evaluation_tick=evaluation_tick)

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
        risk_mediation_receipt = None

    signed_risk_mediation_receipt: dict[str, Any] | None = None
    risk_mediation_signature_errors: list[dict[str, str]] = []
    if risk_mediation_receipt is not None and gate_signature_result["status"] == "PASS":
        try:
            signed_risk_mediation_receipt = sign_contract_envelope(
                risk_mediation_receipt,
                digest_field="receipt_sha256",
                purpose=PURPOSE_RISK_MEDIATION_RECEIPT,
                key_id=gate_key_id,
                signer_id=gate_signer_id,
                trust_domain=gate_trust_domain,
                private_key_b64=gate_private_key_b64,
                issued_at=evaluation_tick,
                valid_until=max(
                    evaluation_tick + 1,
                    int(token.get("expires_at", evaluation_tick + 1)),
                ),
            )
        except Exception as exc:
            risk_mediation_signature_errors.append(
                _error(
                    "RISK_MEDIATION_RECEIPT_SIGNING_FAILED",
                    "signed_risk_mediation_receipt",
                    type(exc).__name__,
                )
            )
        else:
            mediation_auth = validate_authenticated_risk_mediation(
                signed_risk_mediation_receipt,
                authorization_token_value=token,
                registry=registry,
                evaluation_tick=evaluation_tick,
                expected_signer_id=gate_signer_id,
                expected_trust_domain=gate_trust_domain,
            )
            if mediation_auth["status"] != "PASS":
                risk_mediation_signature_errors.extend(mediation_auth["errors"])
                signed_risk_mediation_receipt = None

    if (
        risk_mediation_requested
        and signed_risk_mediation_receipt is None
        and token.get("outcome") == "ALLOW"
    ):
        terminal_mediation_errors = list(risk_mediation_signature_errors)
        if not terminal_mediation_errors:
            terminal_mediation_errors = [
                _error(
                    "RISK_MEDIATION_AUTHENTICATION_REQUIRED",
                    "signed_risk_mediation_receipt",
                    "usable ALLOW requires authenticated risk mediation",
                )
            ]
        token = _preauthorization_deny(terminal_mediation_errors)
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
        risk_mediation_receipt = None
        risk_mediation_signature_errors = []

    result_errors = list(token.get("errors", [])) + risk_mediation_signature_errors
    mediated_required_and_missing = (
        risk_mediation_requested and signed_risk_mediation_receipt is None
    )
    status = (
        "PASS"
        if token.get("outcome") == "ALLOW"
        and not risk_mediation_signature_errors
        and not mediated_required_and_missing
        else "BLOCK"
    )
    return {
        "status": status,
        "errors": result_errors,
        "token": token,
        "signed_token": signed_token,
        "risk_mediation_receipt": risk_mediation_receipt,
        "signed_risk_mediation_receipt": signed_risk_mediation_receipt,
        "verified_inputs": {
            "assurance": assurance_result["status"],
            "state": state_result["status"],
            "policy": policy_result["status"],
            "approvals": len(by_digest),
            "risk_mediation": (
                "PASS"
                if signed_risk_mediation_receipt is not None
                else "BLOCK"
                if risk_mediation_requested
                else "NOT_REQUESTED"
            ),
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
    verified_signer = signed_result.get("verified_signer")
    if isinstance(token, Mapping) and verified_signer is not None and verified_signer.signer_id != token.get("issuer_id"):
        errors.append(
            _error(
                "authorization_token_signer_mismatch",
                "signed_token",
                "verified signer does not match token issuer_id",
            )
        )
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "token": token,
        "verified_signer": verified_signer,
    }


def validate_authenticated_risk_mediation(
    signed_receipt_value: Mapping[str, Any],
    *,
    authorization_token_value: Mapping[str, Any],
    registry: TrustKeyRegistry,
    evaluation_tick: int,
    expected_signer_id: str | None = None,
    expected_trust_domain: str | None = None,
) -> dict[str, Any]:
    """Authenticate one risk-mediation receipt and bind it to the exact token."""

    signed_result = verify_contract_envelope(
        signed_receipt_value,
        registry=registry,
        evaluation_tick=evaluation_tick,
        expected_purpose=PURPOSE_RISK_MEDIATION_RECEIPT,
        expected_digest_field="receipt_sha256",
        expected_inner_contract_id=RISK_MEDIATION_RECEIPT_CONTRACT_ID,
        expected_signer_id=expected_signer_id,
        expected_trust_domain=expected_trust_domain,
    )
    receipt = signed_result.get("inner_contract")
    receipt_result = (
        validate_risk_mediation_receipt(
            receipt,
            authorization_token_value=authorization_token_value,
            evaluation_tick=evaluation_tick,
        )
        if isinstance(receipt, Mapping)
        else {"status": "BLOCK", "errors": []}
    )
    errors = list(signed_result["errors"]) + list(receipt_result.get("errors", []))
    return {
        "status": "PASS" if not errors else "BLOCK",
        "errors": errors,
        "receipt": receipt,
        "verified_signer": signed_result.get("verified_signer"),
    }


class AuthenticatedSQLiteExecutionLedger(SQLiteExecutionLedger):
    """Execution ledger requiring authenticated token, mediation receipt and state."""

    _requires_authenticated_prepare = True

    def __init__(self, path: str | Path, registry: TrustKeyRegistry) -> None:
        super().__init__(path)
        self.registry = registry

    def prepare(
        self,
        token_value: Mapping[str, Any],
        observed_state_witness: Mapping[str, Any],
        evaluation_tick: int,
        current_workload_identity: Any = None,
        trusted_provider_registry: Any = None,
        provider_id: str = "spiffe_spire_local",
        provider_instance: Any = None,
    ) -> dict[str, Any]:
        """Reject the inherited unauthenticated PREPARED entrypoint.

        Authenticated ledgers may only reach the parent implementation after
        signed authorization, signed risk mediation and signed state checks in
        ``prepare_authenticated``.
        """
        from .action_assurance import ExecutionLedgerError
        raise ExecutionLedgerError(
            "RISK_MEDIATION_AUTHENTICATION_REQUIRED",
            "raw prepare disabled on authenticated ledger; use prepare_authenticated",
        )

    def prepare_authenticated(
        self,
        signed_token_value: Mapping[str, Any],
        signed_observed_state_value: Mapping[str, Any],
        evaluation_tick: int,
        *,
        signed_risk_mediation_receipt_value: Mapping[str, Any] | None = None,
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
        token_signer = token_result.get("verified_signer")

        if not isinstance(signed_risk_mediation_receipt_value, Mapping):
            from .action_assurance import ExecutionLedgerError
            raise ExecutionLedgerError(
                "RISK_MEDIATION_AUTHENTICATION_REQUIRED",
                "authenticated risk mediation receipt required before PREPARED",
            )
        mediation_result = validate_authenticated_risk_mediation(
            signed_risk_mediation_receipt_value,
            authorization_token_value=token,
            registry=self.registry,
            evaluation_tick=evaluation_tick,
            expected_signer_id=token_signer.signer_id if token_signer is not None else None,
            expected_trust_domain=token_signer.trust_domain if token_signer is not None else None,
        )
        if mediation_result["status"] != "PASS":
            from .action_assurance import ExecutionLedgerError
            raise ExecutionLedgerError(
                "invalid_authenticated_risk_mediation",
                str(mediation_result["errors"]),
            )

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
        return super()._prepare_legacy(token, state, evaluation_tick)


__all__ = [
    "AuthenticatedSQLiteExecutionLedger",
    "authorize_authenticated_action",
    "validate_authenticated_authorization",
    "validate_authenticated_risk_mediation",
]
