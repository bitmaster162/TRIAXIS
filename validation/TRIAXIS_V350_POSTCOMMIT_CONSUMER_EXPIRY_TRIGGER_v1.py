"""Fresh post-product consumer-boundary trigger for TRIAXIS v3.5-RC1.

Created after product commit ee1dae92cdb93c02bc5f46405bd79a85fbacea7f.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
from typing import Any, Callable

from triaxis.action_assurance import (
    ExecutionLedgerError,
    SQLiteExecutionLedger,
    authorize_action,
    validate_authorization_token,
)
from validation.TRIAXIS_EFFECTIVE_AUTHORIZATION_EXPIRY_TRIGGER_v1 import (
    TRUSTED,
    build_action,
    policy,
)

PROTOCOL_ID = "TRIAXIS_V350_POSTCOMMIT_CONSUMER_EXPIRY_TRIGGER_v1"
PRODUCT_COMMIT = "ee1dae92cdb93c02bc5f46405bd79a85fbacea7f"


def ledger_result(token: dict[str, Any], witness: dict[str, Any], tick: int) -> str:
    with tempfile.TemporaryDirectory() as td:
        try:
            with SQLiteExecutionLedger(Path(td) / "ledger.sqlite3") as ledger:
                result = ledger.prepare(token, witness, tick)
            return result["state"]
        except ExecutionLedgerError as exc:
            return exc.code


def policy_expiry_blocks_consumer() -> tuple[str, int | None]:
    p = policy(7)
    a = build_action(p, state_until=20, assurance_until=20, action_until=20, nonce="pc-policy")
    token = authorize_action(a, p, 6, "gate:postcommit", TRUSTED)
    return ledger_result(token, a["state_witness"], 8), token.get("expires_at")


def action_expiry_blocks_consumer() -> tuple[str, int | None]:
    p = policy(20)
    a = build_action(p, state_until=20, assurance_until=20, action_until=7, nonce="pc-action")
    token = authorize_action(a, p, 6, "gate:postcommit", TRUSTED)
    return ledger_result(token, a["state_witness"], 8), token.get("expires_at")


def all_sources_intersect_exactly() -> tuple[str, int | None]:
    p = policy(12)
    a = build_action(
        p,
        state_until=9,
        assurance_until=11,
        action_until=14,
        approval_until=7,
        nonce="pc-intersection",
    )
    token = authorize_action(a, p, 6, "gate:postcommit", TRUSTED)
    return validate_authorization_token(token, 6)["status"], token.get("expires_at")


def tampered_expiry_sources_block() -> tuple[str, int | None]:
    p = policy(20)
    a = build_action(p, state_until=20, assurance_until=20, action_until=20, nonce="pc-tamper")
    token = authorize_action(a, p, 6, "gate:postcommit", TRUSTED)
    tampered = deepcopy(token)
    tampered["expiry_sources"]["policy_valid_until"] = 999
    # Preserve the original token digest: consumer validation must detect tampering.
    return validate_authorization_token(tampered, 6)["status"], tampered.get("expires_at")


def positive_current_token_prepares() -> tuple[str, int | None]:
    p = policy(20)
    a = build_action(p, state_until=20, assurance_until=20, action_until=20, nonce="pc-positive")
    token = authorize_action(a, p, 6, "gate:postcommit", TRUSTED)
    return ledger_result(token, a["state_witness"], 8), token.get("expires_at")


def row(case_id: str, description: str, fn: Callable[[], tuple[str, int | None]], expected_status: str, expected_expiry: int, positive: bool = False) -> dict[str, Any]:
    try:
        actual_status, actual_expiry = fn()
        exception = None
    except Exception as exc:  # trigger must report rather than conceal exceptions
        actual_status, actual_expiry = "EXCEPTION", None
        exception = f"{type(exc).__name__}: {exc}"
    return {
        "protocol_id": PROTOCOL_ID,
        "product_commit": PRODUCT_COMMIT,
        "case_id": case_id,
        "description": description,
        "positive_control": positive,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_expiry": expected_expiry,
        "actual_expiry": actual_expiry,
        "pass": actual_status == expected_status and actual_expiry == expected_expiry,
        "exception": exception,
    }


def run_trigger() -> dict[str, Any]:
    rows = [
        row("OA35-PC-P01", "Current token remains consumable by execution ledger", positive_current_token_prepares, "PREPARED", 20, True),
        row("OA35-PC-N01", "Ledger rejects token after policy basis expires", policy_expiry_blocks_consumer, "invalid_authorization_token", 7),
        row("OA35-PC-N02", "Ledger rejects token after action request expires", action_expiry_blocks_consumer, "invalid_authorization_token", 7),
        row("OA35-PC-N03", "Token expiry equals minimum across policy, assurance, state, action and approvals", all_sources_intersect_exactly, "PASS", 7),
        row("OA35-PC-N04", "Consumer rejects expiry-source tampering under original token digest", tampered_expiry_sources_block, "BLOCK", 20),
    ]
    return {
        "protocol_id": PROTOCOL_ID,
        "product_commit": PRODUCT_COMMIT,
        "case_count": len(rows),
        "pass_count": sum(item["pass"] for item in rows),
        "fail_count": sum(not item["pass"] for item in rows),
        "status": "PASS" if all(item["pass"] for item in rows) else "FAIL",
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), ensure_ascii=False, sort_keys=True, indent=2))
