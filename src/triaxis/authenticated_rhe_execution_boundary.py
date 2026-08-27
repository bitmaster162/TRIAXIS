"""Authenticated + SPIFFE-bound RHE PREPARED boundary.

This module composes two existing TRIAXIS controls without replacing either:
1) v3.6 Ed25519 authentication of the authorization token and observed state;
2) the strict RHE workload-provenance boundary that performs a fresh trusted
   workload identity fetch immediately before the PREPARED transition.

No external effect is performed here.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .action_assurance import (
    STATE_WITNESS_CONTRACT_ID,
    ExecutionLedgerError,
)
from .authenticated_action_assurance import validate_authenticated_authorization
from .crypto_trust import (
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    verify_contract_envelope,
)
from .rhe_execution_boundary import TrustedWorkloadExecutionBoundary


class AuthenticatedTrustedWorkloadExecutionBoundary:
    """Require issuer-authenticated token/state and fresh trusted workload identity."""

    def __init__(
        self,
        workload_boundary: TrustedWorkloadExecutionBoundary,
        *,
        crypto_registry: TrustKeyRegistry,
        expected_token_signer_id: str,
        expected_token_trust_domain: str,
    ) -> None:
        if not isinstance(workload_boundary, TrustedWorkloadExecutionBoundary):
            raise TypeError("workload_boundary must be TrustedWorkloadExecutionBoundary")
        if not isinstance(crypto_registry, TrustKeyRegistry):
            raise TypeError("crypto_registry must be TrustKeyRegistry")
        if not isinstance(expected_token_signer_id, str) or not expected_token_signer_id:
            raise ValueError("expected_token_signer_id must be non-empty")
        if not isinstance(expected_token_trust_domain, str) or not expected_token_trust_domain:
            raise ValueError("expected_token_trust_domain must be non-empty")

        self._workload_boundary = workload_boundary
        self._crypto_registry = crypto_registry
        self._expected_token_signer_id = expected_token_signer_id
        self._expected_token_trust_domain = expected_token_trust_domain

    def prepare(
        self,
        signed_token_value: Mapping[str, Any],
        signed_observed_state_value: Mapping[str, Any],
        evaluation_tick: int,
    ) -> dict[str, Any]:
        """Verify signed token/state, then enter the strict workload PREPARED path."""

        token_result = validate_authenticated_authorization(
            signed_token_value,
            registry=self._crypto_registry,
            evaluation_tick=evaluation_tick,
        )
        if token_result["status"] != "PASS":
            raise ExecutionLedgerError(
                "invalid_authenticated_authorization",
                str(token_result["errors"]),
            )

        verified_token_signer = token_result.get("verified_signer")
        if (
            verified_token_signer is None
            or verified_token_signer.signer_id != self._expected_token_signer_id
            or verified_token_signer.trust_domain != self._expected_token_trust_domain
        ):
            raise ExecutionLedgerError(
                "AUTHORIZATION_TOKEN_SIGNER_MISMATCH",
                "authenticated token signer/trust domain does not match configured gate authority",
            )

        token = token_result.get("token")
        if not isinstance(token, Mapping):
            raise ExecutionLedgerError(
                "invalid_authenticated_authorization",
                "authenticated authorization did not yield a token mapping",
            )

        state_result = verify_contract_envelope(
            signed_observed_state_value,
            registry=self._crypto_registry,
            evaluation_tick=evaluation_tick,
            expected_purpose=PURPOSE_STATE_WITNESS,
            expected_digest_field="witness_sha256",
            expected_inner_contract_id=STATE_WITNESS_CONTRACT_ID,
        )
        if state_result["status"] != "PASS":
            raise ExecutionLedgerError(
                "invalid_authenticated_state",
                str(state_result["errors"]),
            )

        state = state_result.get("inner_contract")
        state_signer = state_result.get("verified_signer")
        if not isinstance(state, Mapping):
            raise ExecutionLedgerError(
                "invalid_authenticated_state",
                "authenticated state did not yield a state mapping",
            )
        if state_signer is None or state_signer.signer_id != state.get("adapter_id"):
            raise ExecutionLedgerError(
                "state_signer_mismatch",
                "state signer is not the state adapter",
            )

        return self._workload_boundary.prepare(
            token,
            state,
            evaluation_tick,
        )


__all__ = ["AuthenticatedTrustedWorkloadExecutionBoundary"]
