"""Review-hardening controls for the RHE R1 zero-effect canary.

These tests close proof gaps in the original canary without changing product
source: exact DENY-preparation failure semantics, whole-ledger no-mutation, and
physical idempotency of same-token retry.
"""

from __future__ import annotations

import pytest

from triaxis.action_assurance import ExecutionLedgerError, SQLiteExecutionLedger
from tests.test_rhe_execution_boundary_canary_r1 import (
    CanaryPDP,
    action_envelope,
    authorize,
    policy_bundle,
    registered_provider,
)


def _row_count(ledger: SQLiteExecutionLedger) -> int:
    return int(ledger._conn.execute("SELECT COUNT(*) FROM execution_ledger").fetchone()[0])


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("delegation_grant_id", "bad_grant_review"),
        ("task_id", "bad_task_review"),
        ("capability", "bad_capability_review"),
        ("execution_target", "bad_target_review"),
    ],
)
def test_denied_token_has_exact_failure_reason_and_zero_new_rows(
    tmp_path, field, bad_value
):
    policy = policy_bundle()
    action = action_envelope(policy, **{field: bad_value})
    provider, registry = registered_provider()
    token, pep = authorize(action, policy, provider, registry, CanaryPDP())

    assert token["outcome"] == "DENY"
    assert pep.last_receipt is not None
    assert not pep.last_receipt.is_verified_allow

    with SQLiteExecutionLedger(tmp_path / f"denied_{field}.sqlite") as ledger:
        before = _row_count(ledger)
        with pytest.raises(ExecutionLedgerError) as exc_info:
            ledger.prepare(
                token,
                observed_state_witness=action["state_witness"],
                evaluation_tick=50,
            )
        assert exc_info.value.code == "invalid_authorization_token"
        assert "token_not_allow" in str(exc_info.value)
        assert _row_count(ledger) == before


def test_same_token_retry_performs_no_second_ledger_write(tmp_path):
    policy = policy_bundle()
    action = action_envelope(policy, nonce="nonce_review_idempotency")
    provider, registry = registered_provider()
    token, pep = authorize(action, policy, provider, registry, CanaryPDP())

    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow

    with SQLiteExecutionLedger(tmp_path / "retry_physical.sqlite") as ledger:
        current_identity = provider.fetch_and_verify_identity("prepare_review_idempotency")
        first = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=50,
            current_workload_identity=current_identity,
            trusted_provider_registry=registry,
            provider_id="canary_spiffe_test",
            provider_instance=provider,
        )
        count_after_first = _row_count(ledger)

        second = ledger.prepare_for_workload(
            token_value=token,
            observed_state_witness=action["state_witness"],
            evaluation_tick=51,
            current_workload_identity=current_identity,
            trusted_provider_registry=registry,
            provider_id="canary_spiffe_test",
            provider_instance=provider,
        )

        assert second == first
        assert _row_count(ledger) == count_after_first == 1
        assert second["prepared_at"] == first["prepared_at"] == 50
        assert second["updated_at"] == first["updated_at"] == 50


def test_authorization_token_is_bound_to_exact_action_semantics():
    policy = policy_bundle()
    action = action_envelope(policy, nonce="nonce_review_binding")
    provider, registry = registered_provider()
    token, pep = authorize(action, policy, provider, registry, CanaryPDP())

    assert token["outcome"] == "ALLOW"
    assert pep.last_receipt is not None
    assert pep.last_receipt.is_verified_allow
    assert token["action_sha256"] == action["action_sha256"]
    assert token["scope_sha256"] == action["scope_sha256"]
    assert token["assured_action_request_sha256"] == action["assured_action_request_sha256"]
    assert token["capability"] == action["capability"]
    assert token["execution_target"] == action["execution_target"]
    assert token["payload_sha256"] == action["payload_sha256"]

    different_action = action_envelope(
        policy,
        capability="different_capability",
        nonce="nonce_review_binding",
    )
    assert different_action["action_sha256"] != token["action_sha256"]
    assert different_action["scope_sha256"] != token["scope_sha256"]
    assert different_action["assured_action_request_sha256"] != token["assured_action_request_sha256"]
    assert different_action["capability"] != token["capability"]
