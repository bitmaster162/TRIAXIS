"""Strict RHE execution-preparation boundary over the legacy SQLite ledger.

This module makes execution-time workload-identity provenance explicit.  Callers
cannot provide a preconstructed ``VerifiedWorkloadIdentity`` to this boundary;
the exact provider instance registered in the trusted provider registry is
queried immediately before the PREPARED transition.

The boundary performs no external effect itself.  It only obtains current
identity evidence and delegates to ``SQLiteExecutionLedger.prepare_for_workload``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .action_assurance import ExecutionLedgerError, SQLiteExecutionLedger


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
        """Fetch trusted current identity and prepare exactly one ledger nonce.

        Provider trust is rechecked on every call so a registry/configuration
        change fails closed rather than relying on constructor-time trust.
        """

        if not self._registry.is_provider_trusted(
            self._provider_id, self._provider
        ):
            raise ExecutionLedgerError(
                "UNTRUSTED_IDENTITY_PROVIDER",
                f"untrusted workload identity provider '{self._provider_id}'",
            )

        request_id = ""
        if isinstance(token_value, Mapping):
            nonce = token_value.get("nonce")
            if isinstance(nonce, str):
                request_id = f"prepare:{nonce}"

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
            token_value=token_value,
            observed_state_witness=observed_state_witness,
            evaluation_tick=evaluation_tick,
            current_workload_identity=current_identity,
            trusted_provider_registry=self._registry,
            provider_id=self._provider_id,
            provider_instance=self._provider,
        )


__all__ = ["TrustedWorkloadExecutionBoundary"]
