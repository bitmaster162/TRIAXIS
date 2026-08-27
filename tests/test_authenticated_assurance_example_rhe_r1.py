"""Regression test for the authenticated risk-mediated reference example.

The test is zero-provider and zero-production-effect. It uses only ephemeral
Ed25519 keys, disposable local SQLite state and a temporary output directory.
"""
from __future__ import annotations

import json
from pathlib import Path

from examples.build_authenticated_assurance_example import build
from triaxis.crypto_trust import PURPOSE_RISK_MEDIATION_RECEIPT
from triaxis.risk_mediation import RISK_MEDIATION_RECEIPT_CONTRACT_ID


def test_authenticated_example_requires_and_persists_signed_risk_mediation(tmp_path: Path):
    summary = build(tmp_path)

    assert summary == {
        "authorization": "PASS",
        "token_outcome": "ALLOW",
        "risk_mediation": "PASS",
        "prepared_state": "PREPARED",
        "completed_state": "COMPLETED",
        "private_keys_written": False,
    }

    signed_receipt = json.loads(
        (tmp_path / "authenticated_signed_risk_mediation_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert signed_receipt["purpose"] == PURPOSE_RISK_MEDIATION_RECEIPT
    assert signed_receipt["signer_id"] == "gate:example"
    assert signed_receipt["trust_domain"] == "domain:gate"
    assert (
        signed_receipt["inner_contract"]["contract_id"]
        == RISK_MEDIATION_RECEIPT_CONTRACT_ID
    )
    assert signed_receipt["inner_contract"]["effective_risk"] == "R2"

    trust_registry = json.loads(
        (tmp_path / "authenticated_trust_registry.json").read_text(encoding="utf-8")
    )
    gate = next(record for record in trust_registry if record["key_id"] == "key:gate")
    assert PURPOSE_RISK_MEDIATION_RECEIPT in gate["purposes"]
