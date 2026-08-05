#!/usr/bin/env python3
"""Build a non-production v3.6 authenticated action flow.

Fresh ephemeral private keys remain in memory only. The output contains public
trust records, signed envelopes, the signed gate token and the execution row.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from triaxis.action_assurance import (
    ACTION_ENVELOPE_CONTRACT_ID,
    ASSURANCE_ATTESTATION_CONTRACT_ID,
    STATE_WITNESS_CONTRACT_ID,
    action_scope_sha256,
    assured_action_request_sha256,
    seal_contract,
)
from triaxis.authenticated_action_assurance import AuthenticatedSQLiteExecutionLedger, authorize_authenticated_action
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    PURPOSE_AUTHORIZATION_TOKEN,
    PURPOSE_POLICY_BUNDLE,
    PURPOSE_STATE_WITNESS,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
)
from triaxis.policy_lifecycle import POLICY_BUNDLE_CONTRACT_ID, seal_policy


def _write(directory: Path, name: str, value) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build(output_dir: Path) -> dict:
    identities = {
        "assurance": ("assurance:example", "domain:assurance", PURPOSE_ASSURANCE_ATTESTATION),
        "state": ("adapter:state-example", "domain:state", PURPOSE_STATE_WITNESS),
        "policy": ("policy-engine:example", "domain:policy", PURPOSE_POLICY_BUNDLE),
        "gate": ("gate:example", "domain:gate", PURPOSE_AUTHORIZATION_TOKEN),
    }
    keys = {name: generate_ed25519_keypair() for name in identities}
    records = []
    for name, (signer, domain, purpose) in identities.items():
        records.append(make_trust_key_record(
            key_id=f"key:{name}",
            signer_id=signer,
            trust_domain=domain,
            public_key_b64=keys[name]["public_key_b64"],
            purposes=[purpose],
            valid_from=1,
            valid_until=100,
        ))
    registry = TrustKeyRegistry(records)

    policy = seal_policy({
        "contract_id": POLICY_BUNDLE_CONTRACT_ID,
        "policy_id": "policy:example",
        "subject_id": "subject:example",
        "issuer_id": "policy-engine:example",
        "sequence": 1,
        "minimum_accepted_sequence": 1,
        "state": "ACTIVE",
        "effective_from": 1,
        "valid_until": 30,
        "allowed_capabilities": ["WRITE"],
        "allowed_tools": ["git"],
        "allowed_targets": ["repo:example"],
        "max_risk_class": "R2",
        "required_approval_types": [],
        "supersedes_policy_sha256": None,
        "policy_sha256": "",
    })
    state = seal_contract({
        "contract_id": STATE_WITNESS_CONTRACT_ID,
        "state_id": "state:example",
        "subject_id": "subject:example",
        "object_id": "repo:example",
        "adapter_id": "adapter:state-example",
        "version": 1,
        "state_sha256": "a" * 64,
        "attestation_level": "AUTHENTICATED",
        "observed_at": 5,
        "valid_until": 25,
        "witness_sha256": "",
    }, "witness_sha256")
    action = {
        "contract_id": ACTION_ENVELOPE_CONTRACT_ID,
        "principal_id": "human:example",
        "intent_id": "intent:example",
        "decision_case_sha256": "b" * 64,
        "evidence_report_sha256": "c" * 64,
        "subject_id": "subject:example",
        "object_id": "repo:example",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:example",
        "payload_sha256": "d" * 64,
        "policy_id": policy["policy_id"],
        "policy_sequence": policy["sequence"],
        "policy_sha256": policy["policy_sha256"],
        "state_witness": state,
        "risk_class": "R2",
        "nonce": "nonce:example-authenticated",
        "issued_at": 6,
        "expires_at": 20,
        "approvals": [],
        "assured_action_request_sha256": "",
        "scope_sha256": "",
        "action_sha256": "",
    }
    action["assured_action_request_sha256"] = assured_action_request_sha256(action)
    attestation = seal_contract({
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "attestation:example",
        "issuer_id": "assurance:example",
        "trust_domain": "domain:assurance",
        "subject_id": action["subject_id"],
        "decision_case_sha256": action["decision_case_sha256"],
        "evidence_report_sha256": action["evidence_report_sha256"],
        "assured_action_request_sha256": action["assured_action_request_sha256"],
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT_WITH_CONTROLS",
        "attestation_level": "AUTHENTICATED",
        "issued_at": 6,
        "valid_until": 18,
        "attestation_sha256": "",
    }, "attestation_sha256")
    action["assurance_attestation"] = attestation
    action["scope_sha256"] = action_scope_sha256(action)
    action = seal_contract(action, "action_sha256")

    signed_attestation = sign_contract_envelope(
        attestation, digest_field="attestation_sha256", purpose=PURPOSE_ASSURANCE_ATTESTATION,
        key_id="key:assurance", signer_id="assurance:example", trust_domain="domain:assurance",
        private_key_b64=keys["assurance"]["private_key_b64"], issued_at=6, valid_until=18,
    )
    signed_state = sign_contract_envelope(
        state, digest_field="witness_sha256", purpose=PURPOSE_STATE_WITNESS,
        key_id="key:state", signer_id="adapter:state-example", trust_domain="domain:state",
        private_key_b64=keys["state"]["private_key_b64"], issued_at=5, valid_until=25,
    )
    signed_policy = sign_contract_envelope(
        policy, digest_field="policy_sha256", purpose=PURPOSE_POLICY_BUNDLE,
        key_id="key:policy", signer_id="policy-engine:example", trust_domain="domain:policy",
        private_key_b64=keys["policy"]["private_key_b64"], issued_at=5, valid_until=30,
    )
    authorization = authorize_authenticated_action(
        action_value=action,
        policy_value=policy,
        evaluation_tick=6,
        registry=registry,
        signed_assurance_attestation=signed_attestation,
        signed_state_witness=signed_state,
        signed_policy_bundle=signed_policy,
        signed_approvals=[],
        gate_key_id="key:gate",
        gate_signer_id="gate:example",
        gate_trust_domain="domain:gate",
        gate_private_key_b64=keys["gate"]["private_key_b64"],
    )

    with tempfile.TemporaryDirectory() as tmp:
        with AuthenticatedSQLiteExecutionLedger(Path(tmp) / "ledger.sqlite3", registry) as ledger:
            prepared = ledger.prepare_authenticated(authorization["signed_token"], signed_state, 6)
            completed = ledger.complete(
                authorization["token"]["nonce"],
                authorization["token"]["token_sha256"],
                "e" * 64,
                "effect:example",
                7,
            )

    outputs = {
        "trust_registry": records,
        "policy": policy,
        "state": state,
        "action": action,
        "signed_policy": signed_policy,
        "signed_state": signed_state,
        "signed_assurance_attestation": signed_attestation,
        "signed_authorization_token": authorization["signed_token"],
        "execution_receipt": completed["receipt"],
        "summary": {
            "authorization": authorization["status"],
            "token_outcome": authorization["token"]["outcome"],
            "prepared_state": prepared["state"],
            "completed_state": completed["state"],
            "private_keys_written": False,
        },
    }
    for name, value in outputs.items():
        _write(output_dir, f"authenticated_{name}.json", value)
    return outputs["summary"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("examples/authenticated_output"))
    args = parser.parse_args()
    summary = build(args.output_dir)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["authorization"] == "PASS" and summary["completed_state"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
