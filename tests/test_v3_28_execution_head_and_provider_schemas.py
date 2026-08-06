from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_28_execution_head_and_provider import (
    B,
    LEDGER_ID,
    make_identities,
    make_intent,
    open_head_authority,
    open_ledger,
    open_provider,
)
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class V328SchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_execution_ledger_head_response_schema(self):
        ids = make_identities()
        ledger = open_ledger(":memory:", ids)
        authority = open_head_authority(":memory:", ids)
        session = VerifierFreshnessSession.create("verifier:schema", 0)
        challenges = SQLiteEpochChallengeLedger(":memory:", session)
        try:
            head = ledger.head(now_tick=1)
            authority.install_advance(head, [], evaluation_tick=1)
            challenge = challenges.issue(2, 20)
            response = authority.issue_head(
                ledger_id=LEDGER_ID,
                challenge=challenge,
                verifier_id=session.verifier_id,
                verifier_epoch_sha256=session.epoch_sha256,
                requested_at=2,
                issued_at=2,
            )
            self.validate(
                "triaxis_execution_ledger_head_response_v1.schema.json",
                response["inner_contract"],
            )
        finally:
            challenges.close()
            authority.close()
            ledger.close()

    def test_provider_effect_status_schema_for_absent_and_completed(self):
        ids = make_identities()
        provider = open_provider(":memory:", ids)
        intent = make_intent()
        try:
            session1 = VerifierFreshnessSession.create("verifier:schema:1", 0)
            challenges1 = SQLiteEpochChallengeLedger(":memory:", session1)
            challenge1 = challenges1.issue(1, 20)
            absent = provider.issue_status(
                effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                challenge=challenge1,
                verifier_id=session1.verifier_id,
                verifier_epoch_sha256=session1.epoch_sha256,
                requested_at=1,
                issued_at=1,
            )
            self.validate("triaxis_provider_effect_status_v1.schema.json", absent["inner_contract"])
            challenges1.close()

            provider.begin(
                effect_id=intent["effect_id"], payload_sha256=B,
                provider_request_id="provider-request:schema", now_tick=2,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"], provider_request_id="provider-request:schema",
                outcome="COMPLETED", provider_response_sha256="e" * 64,
                evidence_sha256="f" * 64, now_tick=3,
            )
            session2 = VerifierFreshnessSession.create("verifier:schema:2", 0)
            challenges2 = SQLiteEpochChallengeLedger(":memory:", session2)
            challenge2 = challenges2.issue(4, 20)
            completed = provider.issue_status(
                effect_id=intent["effect_id"],
                expected_payload_sha256=B,
                challenge=challenge2,
                verifier_id=session2.verifier_id,
                verifier_epoch_sha256=session2.epoch_sha256,
                requested_at=4,
                issued_at=4,
            )
            self.validate("triaxis_provider_effect_status_v1.schema.json", completed["inner_contract"])
            challenges2.close()
        finally:
            provider.close()


if __name__ == "__main__":
    unittest.main()
