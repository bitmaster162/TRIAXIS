"""Strict RHE execution-preparation boundary over the legacy SQLite ledger.

This module makes execution-time workload-identity provenance explicit. Callers
cannot provide a preconstructed ``VerifiedWorkloadIdentity`` to this boundary;
the exact provider instance registered in the trusted provider registry is
queried immediately before the PREPARED transition.

The boundary performs no external effect itself. It only validates a SPIFFE-
bound authorization token, obtains current identity evidence, and delegates to
``SQLiteExecutionLedger.prepare_for_workload``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .action_assurance import (
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    validate_authorization_token,
)


class TrustedWorkloadExecutionBoundary:
    """Fail-closed SPIFFE workload boundary for the PREPARED transition."""

    def __init__(
        self,
        ledger: SQLiteExecutionLedger,
        *,
        trusted_provider_registry: Any,
        provider_id: str,
        provider_instance: Any,
    ) -> None:
        if not isinstance(ledger, SQLiteExecutionLedger):
            raise TypeError("ledger must be SQLiteExecutionLedger")
        if trusted_provider_registry is None:
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                "trusted provider registry is required",
            )
        if provider_instance is None:
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                "workload identity provider instance is required",
            )
        if not isinstance(provider_id, str) or not provider_id:
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                "non-empty provider_id is required",
            )
        if not trusted_provider_registry.is_provider_trusted(
            provider_id, provider_instance
        ):
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                f"untrusted workload identity provider '{provider_id}'",
            )

        self._ledger = ledger
        self._registry = trusted_provider_registry
        self._provider_id = provider_id
        self._provider = provider_instance

    def prepare(
        self,
        token_value: Mapping[str, Any],
        observed_state_witness: Mapping[str, Any],
        evaluation_tick: int,
    ) -> dict[str, Any]:
        """Validate token, fetch trusted current identity, then enter PREPARED.

        Provider trust is rechecked on every call so a registry/configuration
        change fails closed rather than relying on constructor-time trust.
        """

        token_result = validate_authorization_token(
            token_value,
            evaluation_tick,
            require_allow=True,
        )
        if token_result["status"] != "PASS":
            raise ExecutionLedgerError(
                "invalid_authorization_token",
                str(token_result["errors"]),
            )
        token = token_result["token"]

        workload_meta = (
            token.get("workload_identity")
            or token.get("authorization_provenance")
            or {}
        )
        identity_mode = workload_meta.get("identity_mode") or (
            "spiffe_workload" if workload_meta.get("spiffe_id") else None
        )
        if identity_mode != "spiffe_workload":
            raise ExecutionLedgerError(
                "SPIFFE_WORKLOAD_TOKEN_REQUIRED",
                "strict RHE execution boundary requires a SPIFFE-bound token",
            )

        if not self._registry.is_provider_trusted(
            self._provider_id, self._provider
        ):
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                f"untrusted workload identity provider '{self._provider_id}'",
            )

        nonce = token.get("nonce")
        request_id = f"prepare:{nonce}" if isinstance(nonce, str) else ""

        try:
            current_identity = self._provider.fetch_and_verify_identity(
                request_id=request_id
            )
        except Exception as exc:
            raise ExecutionLedgerError(
                "WORKLOAD_IDENTITY_PROVIDER_ERROR",
                f"workload identity provider failed: {type(exc).__name__}",
            ) from exc

        if getattr(current_identity, "verification_status", None) != "VERIFIED":
            reason = getattr(
                current_identity,
                "verification_reason",
                "current workload identity is not VERIFIED",
            )
            raise ExecutionLedgerError(
                "EXECUTION_WORKLOAD_IDENTITY_MISMATCH",
                str(reason),
            )

        return self._ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=observed_state_witness,
            evaluation_tick=evaluation_tick,
            current_workload_identity=current_identity,
            trusted_provider_registry=self._registry,
            provider_id=self._provider_id,
            provider_instance=self._provider,
        )


__all__ = ["TrustedWorkloadExecutionBoundary"]
