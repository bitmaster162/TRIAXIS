"""Closure trigger for authorization lifetime intersection."""
from __future__ import annotations

import json
from typing import Any, Callable

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
    validate_authorization_token,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

PROTOCOL_ID = "TRIAXIS_EFFECTIVE_AUTHORIZATION_EXPIRY_TRIGGER_v1"
TRUSTED = {"assurance:1": "domain:1"}


def policy(valid_until: int = 20) -> dict[str, Any]:
    return seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "p1",
            "subject_id": "subject:1",
            "issuer_id": "policy:1",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": valid_until,
            "allowed_capabilities": ["WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:1"],
            "max_risk_class": "R4",
            "required_approval_types": [],
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        }
    )


def state(valid_until: int = 20) -> dict[str, Any]:
    return seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "s1",
            "subject_id": "subject:1",
            "object_id": "repo:1",
            "adapter_id": "adapter:1",
            "version": 1,
            "state_sha256": "a" * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 5,
            "valid_until": valid_until,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def build_action(
    p: dict[str, Any],
    *,
    state_until: int = 20,
    assurance_until: int = 20,
    action_until: int = 20,
    approval_until: int | None = None,
    nonce: str,
) -> dict[str, Any]:
    risk = "R3" if approval_until is not None else "R2"
    value = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:1",
        "intent_id": "intent:1",
        "decision_case_sha256": "b" * 64,
        "evidence_report_sha256": "c" * 64,
        "subject_id": "subject:1",
        "object_id": "repo:1",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:1",
        "payload_sha256": "d" * 64,
        "policy_id": "p1",
        "policy_sequence": 1,
        "policy_sha256": p["policy_sha256"],
        "state_witness": state(state_until),
        "risk_class": risk,
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": action_until,
        "approvals": [],
        "assured_action_request_sha256": "",
        "scope_sha256": "",
        "action_sha256": "",
    }
    value["assured_action_request_sha256"] = assured_action_request_sha256(value)
    value["assurance_attestation"] = seal_contract(
        {
            "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
            "attestation_id": "a1",
            "issuer_id": "assurance:1",
            "trust_domain": "domain:1",
            "subject_id": "subject:1",
            "decision_case_sha256": "b" * 64,
            "evidence_report_sha256": "c" * 64,
            "assured_action_request_sha256": value["assured_action_request_sha256"],
            "assurance_status": "PASS",
            "synthesis_decision": "ACCEPT",
            "attestation_level": "AUTHENTICATED",
            "issued_at": 5,
            "valid_until": assurance_until,
            "attestation_sha256": "",
        },
        "attestation_sha256",
    )
    value["scope_sha256"] = action_scope_sha256(value)
    if approval_until is not None:
        value["approvals"] = [
            seal_contract(
                {
                    "contract_id": APPROVAL_CONTRACT_ID,
                    "approval_id": aid,
                    "principal_id": f"principal:{aid}",
                    "trust_domain": domain,
                    "approval_type": atype,
                    "scope_sha256": value["scope_sha256"],
                    "issued_at": 5,
                    "expires_at": expiry,
                    "approval_sha256": "",
                },
                "approval_sha256",
            )
            for aid, domain, atype, expiry in (
                ("A1", "domain:one", "OPERATOR", 20),
                ("A2", "domain:two", "SECURITY", approval_until),
            )
        ]
    return seal_contract(value, "action_sha256")


def token_status_at(
    p: dict[str, Any],
    later_tick: int,
    **kwargs: Any,
) -> tuple[str, int | None]:
    action = build_action(p, **kwargs)
    token = authorize_action(action, p, 6, "gate:1", TRUSTED)
    if token["outcome"] != "ALLOW":
        return "AUTHORIZE_DENY", token.get("expires_at")
    return validate_authorization_token(token, later_tick)["status"], token["expires_at"]


def row(case_id: str, description: str, fn: Callable[[], tuple[str, int | None]], expected_status: str, expected_expiry: int, positive: bool = False) -> dict[str, Any]:
    try:
        actual_status, actual_expiry = fn()
        exception = None
    except Exception as exc:
        actual_status, actual_expiry = "EXCEPTION", None
        exception = f"{type(exc).__name__}: {exc}"
    return {
        "protocol_id": PROTOCOL_ID,
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
        row("OA35-P01", "All trust sources remain current", lambda: token_status_at(policy(20), 8, state_until=20, assurance_until=20, action_until=20, nonce="positive"), "PASS", 20, True),
        row("OA35-N01", "Policy expiry caps token", lambda: token_status_at(policy(7), 8, state_until=20, assurance_until=20, action_until=20, nonce="policy"), "BLOCK", 7),
        row("OA35-N02", "Assurance expiry caps token", lambda: token_status_at(policy(20), 8, state_until=20, assurance_until=7, action_until=20, nonce="assurance"), "BLOCK", 7),
        row("OA35-N03", "State expiry caps token", lambda: token_status_at(policy(20), 8, state_until=7, assurance_until=20, action_until=20, nonce="state"), "BLOCK", 7),
        row("OA35-N04", "Approval expiry caps token", lambda: token_status_at(policy(20), 8, state_until=20, assurance_until=20, action_until=20, approval_until=7, nonce="approval"), "BLOCK", 7),
    ]
    return {
        "protocol_id": PROTOCOL_ID,
        "case_count": len(rows),
        "pass_count": sum(item["pass"] for item in rows),
        "fail_count": sum(not item["pass"] for item in rows),
        "status": "PASS" if all(item["pass"] for item in rows) else "FAIL",
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), ensure_ascii=False, sort_keys=True, indent=2))
