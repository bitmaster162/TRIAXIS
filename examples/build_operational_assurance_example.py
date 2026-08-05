#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    SQLiteExecutionLedger,
    action_scope_sha256,
    authorize_action,
    seal_contract,
)
from triaxis.evidence_broker import (
    CLAIM_RECORD_CONTRACT_ID,
    EVIDENCE_PACKAGE_CONTRACT_ID,
    SOURCE_RECORD_CONTRACT_ID,
    validate_evidence_package,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy

ROOT = Path(__file__).resolve().parent


def dump(name: str, value) -> None:
    (ROOT / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    sources = []
    for source_id, group, char in (("E1", "git", "a"), ("E2", "tests", "b")):
        sources.append(
            seal_contract(
                {
                    "contract_id": SOURCE_RECORD_CONTRACT_ID,
                    "source_id": source_id,
                    "subject_id": "subject:triaxis",
                    "source_group": group,
                    "publisher_id": f"adapter:{group}",
                    "source_type": "AUTHORITATIVE_ADAPTER" if source_id == "E1" else "TEST_ARTIFACT",
                    "polarity": "SUPPORTS",
                    "attestation_level": "AUTHENTICATED",
                    "content_sha256": char * 64,
                    "observed_at": 5,
                    "valid_until": 20,
                    "upstream_ids": [],
                    "source_sha256": "",
                },
                "source_sha256",
            )
        )
    claim = seal_contract(
        {
            "contract_id": CLAIM_RECORD_CONTRACT_ID,
            "claim_id": "C1",
            "subject_id": "subject:triaxis",
            "claim_kind": "STATE_FACT",
            "load_bearing": True,
            "required_independent_groups": 2,
            "required_attestation": "AUTHENTICATED",
            "requires_authoritative_adapter": True,
            "evidence_ids": ["E1", "E2"],
            "claim_sha256": "",
        },
        "claim_sha256",
    )
    evidence_package = seal_contract(
        {
            "contract_id": EVIDENCE_PACKAGE_CONTRACT_ID,
            "evaluation_tick": 6,
            "sources": sources,
            "claims": [claim],
            "package_sha256": "",
        },
        "package_sha256",
    )
    evidence_result = validate_evidence_package(evidence_package)
    evidence_report = evidence_result["report"]

    policy = seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy:example",
            "subject_id": "subject:triaxis",
            "issuer_id": "policy-engine:example",
            "sequence": 1,
            "minimum_accepted_sequence": 1,
            "state": "ACTIVE",
            "effective_from": 1,
            "valid_until": 20,
            "allowed_capabilities": ["WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:triaxis"],
            "max_risk_class": "R2",
            "required_approval_types": [],
            "supersedes_policy_sha256": None,
            "policy_sha256": "",
        }
    )
    state = seal_contract(
        {
            "contract_id": STATE_WITNESS_CONTRACT_ID,
            "state_id": "state:triaxis",
            "subject_id": "subject:triaxis",
            "object_id": "repo:triaxis",
            "adapter_id": "git-adapter:example",
            "version": 1,
            "state_sha256": "c" * 64,
            "attestation_level": "AUTHENTICATED",
            "observed_at": 5,
            "valid_until": 20,
            "witness_sha256": "",
        },
        "witness_sha256",
    )
    action = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:example",
        "intent_id": "intent:example",
        "decision_case_sha256": "d" * 64,
        "evidence_report_sha256": evidence_report["report_sha256"],
        "subject_id": "subject:triaxis",
        "object_id": "repo:triaxis",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:triaxis",
        "payload_sha256": "e" * 64,
        "policy_id": "policy:example",
        "policy_sequence": 1,
        "state_witness": state,
        "risk_class": "R2",
        "nonce": "nonce:example",
        "issued_at": 6,
        "expires_at": 10,
        "approvals": [],
        "scope_sha256": "",
        "action_sha256": "",
    }
    action["scope_sha256"] = action_scope_sha256(action)
    action = seal_contract(action, "action_sha256")
    token = authorize_action(action, policy, 6, "gate:example")

    ledger_path = ROOT / "example_execution_ledger.sqlite3"
    ledger_path.unlink(missing_ok=True)
    with SQLiteExecutionLedger(ledger_path) as ledger:
        prepared = ledger.prepare(token, state, 6)
        completed = ledger.complete(token["nonce"], token["token_sha256"], "f" * 64, "effect:example", 7)

    dump("example_evidence_package.json", evidence_package)
    dump("example_evidence_report.json", evidence_report)
    dump("example_policy.json", policy)
    dump("example_state_witness.json", state)
    dump("example_action_envelope.json", action)
    dump("example_authorization_token.json", token)
    dump("example_execution_receipt.json", completed["receipt"])
    ledger_path.unlink(missing_ok=True)
    print(json.dumps({"evidence": evidence_result["status"], "authorization": token["outcome"], "ledger": prepared["state"], "completion": completed["state"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
