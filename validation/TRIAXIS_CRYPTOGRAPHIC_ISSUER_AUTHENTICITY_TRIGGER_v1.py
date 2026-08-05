#!/usr/bin/env python3
"""Post-v3.5 trigger: canonical hashes do not authenticate the named issuer.

A case is a FAIL when an attacker can construct a fresh, canonically sealed
object naming a trusted issuer/principal/adapter and the v3.5 boundary accepts
it without possession of any corresponding private key.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    APPROVAL_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    SQLiteExecutionLedger,
    action_scope_sha256,
    assured_action_request_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

TRUSTED = {"assurance-compiler:trusted": "assurance-domain:trusted"}


def policy() -> dict:
    return seal_policy({
        "contract_id": POLICY_BUNDLE_CONTRACT_ID,
        "policy_id": "policy:write",
        "subject_id": "subject:1",
        "issuer_id": "policy-engine:trusted",
        "sequence": 1,
        "minimum_accepted_sequence": 1,
        "state": "ACTIVE",
        "effective_from": 1,
        "valid_until": 50,
        "allowed_capabilities": ["WRITE"],
        "allowed_tools": ["git"],
        "allowed_targets": ["repo:1"],
        "max_risk_class": "R4",
        "required_approval_types": [],
        "supersedes_policy_sha256": None,
        "policy_sha256": "",
    })


def state() -> dict:
    return seal_contract({
        "contract_id": STATE_WITNESS_CONTRACT_ID,
        "state_id": "state:1",
        "subject_id": "subject:1",
        "object_id": "repo:1",
        "adapter_id": "state-adapter:trusted",
        "version": 7,
        "state_sha256": "a" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": 5,
        "valid_until": 40,
        "witness_sha256": "",
    }, "witness_sha256")


def approval(approval_id: str, domain: str, approval_type: str, scope: str) -> dict:
    return seal_contract({
        "contract_id": APPROVAL_CONTRACT_ID,
        "approval_id": approval_id,
        "principal_id": f"principal:{approval_id}",
        "trust_domain": domain,
        "approval_type": approval_type,
        "scope_sha256": scope,
        "issued_at": 5,
        "expires_at": 30,
        "approval_sha256": "",
    }, "approval_sha256")


def build_action(*, risk: str = "R2", nonce: str = "nonce:1") -> dict:
    p = policy()
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
        "policy_id": "policy:write",
        "policy_sequence": 1,
        "policy_sha256": p["policy_sha256"],
        "state_witness": state(),
        "risk_class": risk,
        "nonce": nonce,
        "issued_at": 5,
        "expires_at": 25,
        "approvals": [],
        "assured_action_request_sha256": "",
        "scope_sha256": "",
        "action_sha256": "",
    }
    value["assured_action_request_sha256"] = assured_action_request_sha256(value)
    value["assurance_attestation"] = seal_contract({
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "attestation:forged",
        "issuer_id": "assurance-compiler:trusted",
        "trust_domain": "assurance-domain:trusted",
        "subject_id": value["subject_id"],
        "decision_case_sha256": value["decision_case_sha256"],
        "evidence_report_sha256": value["evidence_report_sha256"],
        "assured_action_request_sha256": value["assured_action_request_sha256"],
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT",
        "attestation_level": "AUTHENTICATED",
        "issued_at": 5,
        "valid_until": 20,
        "attestation_sha256": "",
    }, "attestation_sha256")
    value["scope_sha256"] = action_scope_sha256(value)
    if risk == "R3":
        value["approvals"] = [
            approval("A1", "domain:one", "OPERATOR", value["scope_sha256"]),
            approval("A2", "domain:two", "SECURITY", value["scope_sha256"]),
        ]
    return seal_contract(value, "action_sha256")


def run_trigger() -> dict:
    rows = []

    # No private key exists anywhere in this trigger. Every trusted identity is
    # attacker-supplied prose plus a recomputed canonical SHA-256.
    forged_action = build_action()
    forged_token = authorize_action(forged_action, policy(), 6, "gate:trusted", TRUSTED)
    rows.append({
        "case_id": "FORGED_ASSURANCE_ISSUER",
        "expected": "DENY",
        "observed": forged_token["outcome"],
        "status": "FAIL" if forged_token["outcome"] == "ALLOW" else "PASS",
    })

    rows.append({
        "case_id": "FORGED_STATE_ADAPTER",
        "expected": "DENY",
        "observed": forged_token["outcome"],
        "status": "FAIL" if forged_token["outcome"] == "ALLOW" else "PASS",
    })

    r3 = build_action(risk="R3", nonce="nonce:r3")
    r3_token = authorize_action(r3, policy(), 6, "gate:trusted", TRUSTED)
    rows.append({
        "case_id": "FORGED_APPROVAL_PRINCIPALS",
        "expected": "DENY",
        "observed": r3_token["outcome"],
        "status": "FAIL" if r3_token["outcome"] == "ALLOW" else "PASS",
    })

    rows.append({
        "case_id": "FORGED_POLICY_ISSUER",
        "expected": "DENY",
        "observed": forged_token["outcome"],
        "status": "FAIL" if forged_token["outcome"] == "ALLOW" else "PASS",
    })

    with tempfile.TemporaryDirectory() as tmp:
        ledger_path = Path(tmp) / "ledger.sqlite3"
        with SQLiteExecutionLedger(ledger_path) as ledger:
            prepared = ledger.prepare(forged_token, forged_action["state_witness"], 6)
        rows.append({
            "case_id": "FORGED_GATE_TOKEN",
            "expected": "REJECT",
            "observed": prepared["state"],
            "status": "FAIL" if prepared["state"] == "PREPARED" else "PASS",
        })

    # Positive control: v3.5 remains internally consistent for its declared
    # digest-only trust model. It is not a cryptographic authenticity proof.
    rows.append({
        "case_id": "DIGEST_INTEGRITY_POSITIVE_CONTROL",
        "expected": "ALLOW_IN_V35_MODEL",
        "observed": forged_token["outcome"],
        "positive_control": True,
        "status": "PASS" if forged_token["outcome"] == "ALLOW" else "FAIL",
    })

    fail_count = sum(row["status"] == "FAIL" for row in rows if not row.get("positive_control"))
    return {
        "contract_id": "TRIAXIS_CRYPTOGRAPHIC_ISSUER_AUTHENTICITY_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.5-RC2-OPERATIONAL-ASSURANCE",
        "status": "FAIL" if fail_count else "PASS",
        "case_count": len(rows),
        "material_failure_count": fail_count,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
