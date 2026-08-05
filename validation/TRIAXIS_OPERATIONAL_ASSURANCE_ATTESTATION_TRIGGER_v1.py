"""Closure trigger for TRIAXIS assurance-attestation binding.

The trigger is intentionally small and deterministic. It proves that a valid
trusted assurance attestation preserves the positive path while decision,
evidence, issuer and trust-domain substitution fail closed.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

PROTOCOL_ID = "TRIAXIS_OPERATIONAL_ASSURANCE_ATTESTATION_TRIGGER_v1"
TRUSTED_ASSURANCE = {"assurance-compiler:1": "assurance-domain:1"}


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


def attestation(
    decision_digest: str = "b" * 64,
    evidence_digest: str = "c" * 64,
    issuer_id: str = "assurance-compiler:1",
    trust_domain: str = "assurance-domain:1",
) -> dict[str, Any]:
    return seal_contract(
        {
            "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
            "attestation_id": "attestation:1",
            "issuer_id": issuer_id,
            "trust_domain": trust_domain,
            "subject_id": "subject:1",
            "decision_case_sha256": decision_digest,
            "evidence_report_sha256": evidence_digest,
            "assurance_status": "PASS",
            "synthesis_decision": "ACCEPT",
            "attestation_level": "AUTHENTICATED",
            "issued_at": 5,
            "valid_until": 15,
            "attestation_sha256": "",
        },
        "attestation_sha256",
    )


def action(
    decision_digest: str,
    evidence_digest: str,
    nonce: str,
    assurance_attestation: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:1",
        "intent_id": "intent:1",
        "decision_case_sha256": decision_digest,
        "evidence_report_sha256": evidence_digest,
        "assurance_attestation": assurance_attestation,
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


def outcome(value: dict[str, Any], trusted=TRUSTED_ASSURANCE) -> str:
    return authorize_action(value, policy(), 6, "gate:1", trusted)["outcome"]


def row(case_id: str, description: str, fn: Callable[[], str], expected: str, positive: bool) -> dict[str, Any]:
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
    valid = attestation()
    rows = [
        row(
            "OA33-P01",
            "Trusted PASS attestation bound to the exact decision/evidence pair preserves ALLOW",
            lambda: outcome(action("b" * 64, "c" * 64, "positive", valid)),
            "ALLOW",
            True,
        ),
        row(
            "OA33-N01",
            "Decision digest substitution fails closed",
            lambda: outcome(action("0" * 64, "c" * 64, "decision-substitution", valid)),
            "DENY",
            False,
        ),
        row(
            "OA33-N02",
            "Evidence digest substitution fails closed",
            lambda: outcome(action("b" * 64, "0" * 64, "evidence-substitution", valid)),
            "DENY",
            False,
        ),
        row(
            "OA33-N03",
            "Untrusted assurance issuer fails closed",
            lambda: outcome(
                action("b" * 64, "c" * 64, "issuer-substitution", attestation(issuer_id="attacker:1", trust_domain="attacker"))
            ),
            "DENY",
            False,
        ),
        row(
            "OA33-N04",
            "Trusted issuer in the wrong trust domain fails closed",
            lambda: outcome(
                action("b" * 64, "c" * 64, "domain-substitution", attestation(trust_domain="wrong-domain"))
            ),
            "DENY",
            False,
        ),
        row(
            "OA33-N05",
            "Missing external trust registry fails closed",
            lambda: outcome(action("b" * 64, "c" * 64, "missing-registry", valid), None),
            "DENY",
            False,
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
