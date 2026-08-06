from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_29_execution_head_quorum_and_completion_witness import (
    B,
    E,
    F,
    LEDGER_AUTHORITY_ID,
    LEDGER_DOMAIN,
    LEDGER_ID,
    LEDGER_SIGNER_ID,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    WITNESS_AUTHORITY_ID,
    WITNESS_DOMAIN,
    WITNESS_ID,
    WITNESS_SERVICE_ID,
    WITNESS_SIGNER_ID,
    anchor,
    identities,
    issue_head_responses,
    make_intent,
    open_head,
    open_ledger,
    open_provider,
    open_witness,
    quorum_config,
)
from triaxis.execution_ledger_head_quorum import verify_execution_ledger_head_quorum
from triaxis.integrity import canonical_sha256
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class V329SchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_execution_ledger_head_quorum_config_schema(self):
        self.validate(
            "triaxis_execution_ledger_head_quorum_config_v1.schema.json",
            quorum_config(identities()),
        )

    def test_execution_ledger_head_quorum_witness_schema(self):
        ids = identities()
        with ExitStack() as stack:
            ledger = stack.enter_context(open_ledger(":memory:", ids))
            heads = [stack.enter_context(open_head(":memory:", ids, index)) for index in range(2)]
            anchor(heads, ledger, 1)
            session = VerifierFreshnessSession.create("verifier:v329:schema:head", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            responses = issue_head_responses(
                heads,
                session=session,
                challenge=challenge,
                requested_at=2,
                issued_at=2,
            )
            config = quorum_config(ids)
            result = verify_execution_ledger_head_quorum(
                ledger.head(now_tick=2),
                responses,
                ledger_registry=ids["ledger_registry"],
                authority_registry=ids["head_registry"],
                expected_ledger_id=LEDGER_ID,
                expected_ledger_authority_id=LEDGER_AUTHORITY_ID,
                expected_ledger_signer_id=LEDGER_SIGNER_ID,
                expected_ledger_trust_domain=LEDGER_DOMAIN,
                quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                challenge_ledger=challenges,
                expected_challenge=challenge,
                evaluation_tick=2,
            )
            self.validate(
                "triaxis_execution_ledger_head_quorum_witness_v1.schema.json",
                result["quorum_witness"],
            )

    def test_provider_outcome_receipt_schema(self):
        ids = identities()
        intent = make_intent()
        with open_provider(":memory:", ids) as provider:
            provider.begin(
                effect_id=intent["effect_id"],
                payload_sha256=B,
                provider_request_id="provider-request:v329:schema",
                now_tick=1,
            )
            provider.record_outcome(
                effect_id=intent["effect_id"],
                provider_request_id="provider-request:v329:schema",
                outcome="COMPLETED",
                provider_response_sha256=E,
                evidence_sha256=F,
                now_tick=2,
            )
            receipt = provider.issue_outcome_receipt(
                effect_id=intent["effect_id"], issued_at=2, valid_until=20
            )
            self.validate(
                "triaxis_provider_outcome_receipt_v1.schema.json",
                receipt["inner_contract"],
            )

    def test_external_completion_witness_event_schema(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            result = witness.reserve(
                effect_id=intent["effect_id"],
                payload_sha256=B,
                provider_id=PROVIDER_ID,
                provider_service_id=PROVIDER_SERVICE_ID,
                provider_request_id="provider-request:v329:schema:event",
                now_tick=1,
            )
            self.validate(
                "triaxis_external_completion_witness_event_v1.schema.json",
                result["signed_witness_event"]["inner_contract"],
            )

    def test_external_completion_witness_head_schema(self):
        ids = identities()
        with open_witness(":memory:", ids) as witness:
            self.validate(
                "triaxis_external_completion_witness_head_v1.schema.json",
                witness.head(now_tick=1)["inner_contract"],
            )

    def test_external_completion_witness_status_schema(self):
        ids = identities()
        intent = make_intent()
        with open_witness(":memory:", ids) as witness:
            session = VerifierFreshnessSession.create("verifier:v329:schema:witness", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(1, 20)
                status = witness.issue_status(
                    effect_id=intent["effect_id"],
                    expected_payload_sha256=B,
                    expected_provider_id=PROVIDER_ID,
                    expected_provider_service_id=PROVIDER_SERVICE_ID,
                    challenge=challenge,
                    verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256,
                    requested_at=1,
                    issued_at=1,
                    valid_until=20,
                )
                self.validate(
                    "triaxis_external_completion_witness_status_v1.schema.json",
                    status["inner_contract"],
                )


if __name__ == "__main__":
    unittest.main()
