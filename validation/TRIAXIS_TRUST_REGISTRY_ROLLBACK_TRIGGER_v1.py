#!/usr/bin/env python3
"""Post-v3.6 trigger: rollback of the public-key registry resurrects revoked keys."""
from __future__ import annotations

import json

from triaxis.action_assurance import ASSURANCE_ATTESTATION_CONTRACT_ID, seal_contract
from triaxis.crypto_trust import (
    PURPOSE_ASSURANCE_ATTESTATION,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
    sign_contract_envelope,
    verify_contract_envelope,
)


def run_trigger() -> dict:
    pair = generate_ed25519_keypair()
    attestation = seal_contract({
        "contract_id": ASSURANCE_ATTESTATION_CONTRACT_ID,
        "attestation_id": "attestation:rollback-test",
        "issuer_id": "assurance:rollback-test",
        "trust_domain": "domain:assurance",
        "subject_id": "subject:1",
        "decision_case_sha256": "a" * 64,
        "evidence_report_sha256": "b" * 64,
        "assured_action_request_sha256": "c" * 64,
        "assurance_status": "PASS",
        "synthesis_decision": "ACCEPT",
        "attestation_level": "AUTHENTICATED",
        "issued_at": 5,
        "valid_until": 50,
        "attestation_sha256": "",
    }, "attestation_sha256")
    signed = sign_contract_envelope(
        attestation,
        digest_field="attestation_sha256",
        purpose=PURPOSE_ASSURANCE_ATTESTATION,
        key_id="key:assurance:v1",
        signer_id="assurance:rollback-test",
        trust_domain="domain:assurance",
        private_key_b64=pair["private_key_b64"],
        issued_at=5,
        valid_until=50,
    )

    old_record = make_trust_key_record(
        key_id="key:assurance:v1",
        signer_id="assurance:rollback-test",
        trust_domain="domain:assurance",
        public_key_b64=pair["public_key_b64"],
        purposes=[PURPOSE_ASSURANCE_ATTESTATION],
        valid_from=1,
        valid_until=100,
        revoked_at=None,
    )
    current_record = make_trust_key_record(
        key_id="key:assurance:v1",
        signer_id="assurance:rollback-test",
        trust_domain="domain:assurance",
        public_key_b64=pair["public_key_b64"],
        purposes=[PURPOSE_ASSURANCE_ATTESTATION],
        valid_from=1,
        valid_until=100,
        revoked_at=7,
    )
    current_registry = TrustKeyRegistry([current_record])
    rolled_back_registry = TrustKeyRegistry([old_record])

    current = verify_contract_envelope(
        signed,
        registry=current_registry,
        evaluation_tick=8,
        expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
        expected_digest_field="attestation_sha256",
    )
    rolled_back = verify_contract_envelope(
        signed,
        registry=rolled_back_registry,
        evaluation_tick=8,
        expected_purpose=PURPOSE_ASSURANCE_ATTESTATION,
        expected_digest_field="attestation_sha256",
    )

    rows = [
        {
            "case_id": "CURRENT_REGISTRY_REVOKES_KEY",
            "expected": "BLOCK",
            "observed": current["status"],
            "status": "PASS" if current["status"] == "BLOCK" else "FAIL",
            "positive_control": True,
        },
        {
            "case_id": "ROLLED_BACK_REGISTRY_RESURRECTS_KEY",
            "expected": "BLOCK",
            "observed": rolled_back["status"],
            "status": "FAIL" if rolled_back["status"] == "PASS" else "PASS",
        },
        {
            "case_id": "REGISTRY_HAS_NO_SEQUENCE_OR_PARENT_ANCHOR",
            "expected": "MONOTONIC_REGISTRY_REQUIRED",
            "observed": "ARBITRARY_REGISTRY_ACCEPTED",
            "status": "FAIL",
        },
    ]
    failures = sum(row["status"] == "FAIL" for row in rows)
    return {
        "contract_id": "TRIAXIS_TRUST_REGISTRY_ROLLBACK_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.6-RC1-CRYPTOGRAPHIC-AUTHENTICITY",
        "status": "FAIL" if failures else "PASS",
        "case_count": len(rows),
        "material_failure_count": failures,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
