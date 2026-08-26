"""Focused authority-binding controls for the strict RHE PREPARED boundary."""

from __future__ import annotations

from dataclasses import replace

import pytest

from triaxis.action_assurance import ExecutionLedgerError
from tests.test_rhe_execution_identity_provenance_r1 import (
    issue_token,
    make_boundary,
    registered_provider,
)


def test_identity_mapping_change_requires_new_authorization(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)

    provider.identity = replace(
        provider.identity,
        identity_mapping_sha256="9" * 64,
    )

    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, action["state_witness"], 150)
        assert (
            exc_info.value.code
            == "EXECUTION_WORKLOAD_IDENTITY_PROVENANCE_MISMATCH"
        )
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()


def test_identity_provider_change_requires_new_authorization(tmp_path):
    provider, registry = registered_provider()
    token, action = issue_token(provider, registry)

    provider.identity = replace(
        provider.identity,
        identity_provider="different-trusted-provider-authority",
    )

    ledger, boundary = make_boundary(tmp_path, provider, registry)
    try:
        with pytest.raises(ExecutionLedgerError) as exc_info:
            boundary.prepare(token, action["state_witness"], 150)
        assert (
            exc_info.value.code
            == "EXECUTION_WORKLOAD_IDENTITY_PROVENANCE_MISMATCH"
        )
        assert ledger.get(token["nonce"]) is None
    finally:
        ledger.close()
