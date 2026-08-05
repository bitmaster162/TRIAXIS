"""Post-product trigger for exact TRIAXIS v3.2-RC1.

The trigger asks whether syntactically valid decision/evidence digests can be
substituted without a trusted attestation that those artifacts actually passed.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

PROTOCOL_ID = "TRIAXIS_OPERATIONAL_ASSURANCE_POSTCOMMIT_TRIGGER_v1"
CANDIDATE_COMMIT = "1daa9b342be36c16b77e7e7b29d75ed6e8398fd7"
CANDIDATE_TREE = "af26508be20bc9c4590e495dd5e6a9a41813678d"


def state() -> dict[str, Any]:
    return seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "state:1",
            "subject_id": "subject:1",
            "object_id": "repo:1",
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
            "issuer_id": "policy-engine:1",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": 20,
            "allowed_capabilities": ["WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:1"],
            "max_risk_class": "R2",
            "required_approval_types": [],
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        }
    )


def action(decision_digest: str, evidence_digest: str, nonce: str) -> dict[str, Any]:
    value = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:1",
        "intent_id": "intent:1",
        "decision_case_sha256": decision_digest,
        "evidence_report_sha256": evidence_digest,
        "subject_id": "subject:1",
        "object_id": "repo:1",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:1",
        "payload_sha256": "d" * 64,
        "policy_id": "policy:1",
        "policy_sequence": 1,
        "state_witness": state(),
        "risk_class": "R2",
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": 15,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }
    value["scope_sha256"] = action_scope_sha256(value)
    return seal_contract(value, "action_sha256")


def outcome(a: dict[str, Any]) -> str:
    return authorize_action(a, policy(), 6, "gate:1")["outcome"]


def row(case_id: str, description: str, fn: Callable[[], str], expected: str, positive: bool) -> dict[str, Any]:
    try:
        actual = fn()
        exception = None
    except Exception as exc:
        actual = "EXCEPTION"
        exception = f"{type(exc).__name__}: {exc}"
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "description": description,
        "positive_control": positive,
        "expected_outcome": expected,
        "actual_outcome": actual,
        "pass": actual == expected,
        "exception": exception,
    }


def run_trigger() -> dict[str, Any]:
    rows = [
        row(
            "OA-P01",
            "A structurally valid action remains an authorization positive control",
            lambda: outcome(action("b" * 64, "c" * 64, "positive")),
            "ALLOW",
            True,
        ),
        row(
            "OA-N01",
            "An arbitrary decision digest without a trusted PASS attestation must not authorize",
            lambda: outcome(action("0" * 64, "c" * 64, "phantom-decision")),
            "DENY",
            False,
        ),
        row(
            "OA-N02",
            "An arbitrary evidence-report digest without a trusted PASS attestation must not authorize",
            lambda: outcome(action("b" * 64, "0" * 64, "phantom-evidence")),
            "DENY",
            False,
        ),
        row(
            "OA-N03",
            "Two unrelated but well-formed digests must not be laundered as an assurance chain",
            lambda: outcome(action("1" * 64, "2" * 64, "phantom-chain")),
            "DENY",
            False,
        ),
    ]
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_count": len(rows),
        "pass_count": sum(item["pass"] for item in rows),
        "fail_count": sum(not item["pass"] for item in rows),
        "status": "PASS" if all(item["pass"] for item in rows) else "FAIL",
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), ensure_ascii=False, sort_keys=True, indent=2))
