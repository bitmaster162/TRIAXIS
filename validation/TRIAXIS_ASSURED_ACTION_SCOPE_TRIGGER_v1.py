"""Closure trigger for exact assured-action binding and strict trust registries."""
from __future__ import annotations

import json
from typing import Any, Callable

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

PROTOCOL_ID = "TRIAXIS_ASSURED_ACTION_SCOPE_TRIGGER_v1"
TRUSTED = {"assurance:1": "domain:1"}


def state(object_id: str = "repo:1") -> dict[str, Any]:
    return seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": f"state:{object_id}",
            "subject_id": "subject:1",
            "object_id": object_id,
            "adapter_id": "adapter:1",
            "version": 1,
            "state_sha256": "a" * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 5,
            "valid_until": 20,
            "witness_sha256": "",
        },
        "witness_sha256",
    )


def policy() -> dict[str, Any]:
    return seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy:1",
            "subject_id": "subject:1",
            "issuer_id": "policy:issuer",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": 20,
            "allowed_capabilities": ["WRITE"],
            "allowed_tools": ["git", "shell"],
            "allowed_targets": ["repo:1", "repo:2"],
            "max_risk_class": "R2",
            "required_approval_types": [],
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        }
    )


def build_action(
    *,
    nonce: str,
    payload_sha256: str = "d" * 64,
    tool_id: str = "git",
    target: str = "repo:1",
    reused_attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:1",
        "intent_id": "intent:1",
        "decision_case_sha256": "b" * 64,
        "evidence_report_sha256": "c" * 64,
        "subject_id": "subject:1",
        "object_id": target,
        "capability": "WRITE",
        "tool_id": tool_id,
        "execution_target": target,
        "payload_sha256": payload_sha256,
        "policy_id": "policy:1",
        "policy_sequence": 1,
        "policy_sha256": policy()["policy_sha256"],
        "state_witness": state(target),
        "risk_class": "R2",
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": 15,
        "approvals": [],
        "assured_action_request_sha256": "",
        "scope_sha256": "",
        "action_sha256": "",
    }
    value["assured_action_request_sha256"] = assured_action_request_sha256(value)
    if reused_attestation is None:
        attestation = seal_contract(
            {
                "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
                "attestation_id": "attestation:1",
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
                "valid_until": 15,
                "attestation_sha256": "",
            },
            "attestation_sha256",
        )
    else:
        attestation = reused_attestation
    value["assurance_attestation"] = attestation
    value["scope_sha256"] = action_scope_sha256(value)
    return seal_contract(value, "action_sha256")


def outcome(value: dict[str, Any], trusted: Any = TRUSTED) -> str:
    return authorize_action(value, policy(), 6, "gate:1", trusted)["outcome"]


def row(case_id: str, description: str, fn: Callable[[], str], expected: str, positive: bool = False) -> dict[str, Any]:
    try:
        actual = fn()
        exception = None
    except Exception as exc:
        actual = "EXCEPTION"
        exception = f"{type(exc).__name__}: {exc}"
    return {
        "protocol_id": PROTOCOL_ID,
        "case_id": case_id,
        "description": description,
        "positive_control": positive,
        "expected_outcome": expected,
        "actual_outcome": actual,
        "pass": actual == expected,
        "exception": exception,
    }


def run_trigger() -> dict[str, Any]:
    original = build_action(nonce="original")
    attestation = original["assurance_attestation"]
    rows = [
        row("OA34-P01", "Exact assured action remains allowed", lambda: outcome(original), "ALLOW", True),
        row(
            "OA34-N01",
            "PASS attestation cannot be replayed over another payload",
            lambda: outcome(build_action(nonce="payload", payload_sha256="e" * 64, reused_attestation=attestation)),
            "DENY",
        ),
        row(
            "OA34-N02",
            "PASS attestation cannot be replayed over another allowed tool/target",
            lambda: outcome(build_action(nonce="route", tool_id="shell", target="repo:2", reused_attestation=attestation)),
            "DENY",
        ),
        row(
            "OA34-N03",
            "Set-only issuer registry cannot erase trust-domain binding",
            lambda: outcome(original, {"assurance:1"}),
            "DENY",
        ),
        row(
            "OA34-N04",
            "Issuer mapped to wrong trust domain fails closed",
            lambda: outcome(original, {"assurance:1": "wrong-domain"}),
            "DENY",
        ),
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
