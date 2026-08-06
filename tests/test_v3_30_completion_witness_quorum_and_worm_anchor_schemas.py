from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_30_completion_witness_quorum_and_worm_anchor import (
    ANCHOR_AUTHORITY_ID,
    ANCHOR_DOMAIN,
    ANCHOR_ID,
    ANCHOR_SERVICE_ID,
    ANCHOR_SIGNER_ID,
    B,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    completion_quorum_config,
    issue_completion_statuses,
    make_intent,
    open_completion_witness,
    open_provider,
    open_worm,
    provider_outcome,
    v330_identities,
)
from triaxis.completion_witness_quorum import verify_completion_witness_quorum
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


class V330SchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_completion_witness_quorum_config_schema(self):
        ids = v330_identities()
        self.validate(
            "triaxis_completion_witness_quorum_config_v1.schema.json",
            completion_quorum_config(ids),
        )

    def test_completion_witness_quorum_witness_schema(self):
        ids = v330_identities()
        effect_id = make_intent()["effect_id"]
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            session = VerifierFreshnessSession.create("verifier:v330:schema:quorum", 0)
            challenges = stack.enter_context(SQLiteEpochChallengeLedger(":memory:", session))
            challenge = challenges.issue(2, 20)
            statuses = issue_completion_statuses(
                witnesses,
                session=session,
                challenge=challenge,
                effect_id=effect_id,
                requested_at=2,
                issued_at=2,
            )
            config = completion_quorum_config(ids)
            result = verify_completion_witness_quorum(
                statuses,
                registry=ids["completion_witness_registry"],
                quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                expected_effect_id=effect_id,
                expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge_ledger=challenges,
                expected_challenge=challenge,
                evaluation_tick=2,
            )
            self.validate(
                "triaxis_completion_witness_quorum_witness_v1.schema.json",
                result["quorum_witness"],
            )

    def test_completion_worm_anchor_event_schema(self):
        ids = v330_identities()
        effect_id = make_intent()["effect_id"]
        with open_provider(":memory:", ids) as provider, open_worm(":memory:", ids) as anchor:
            receipt = provider_outcome(
                provider,
                effect_id=effect_id,
                request_id="provider-request:v330:schema:event",
                outcome="COMPLETED",
                begin_tick=1,
                outcome_tick=2,
            )
            result = anchor.ingest_provider_outcome(
                receipt,
                provider_registry=ids["provider_registry"],
                expected_provider_signer_id=PROVIDER_SIGNER_ID,
                expected_provider_trust_domain=PROVIDER_DOMAIN,
                evaluation_tick=2,
            )
            self.validate(
                "triaxis_completion_worm_anchor_event_v1.schema.json",
                result["signed_anchor_event"]["inner_contract"],
            )

    def test_completion_worm_anchor_head_schema(self):
        ids = v330_identities()
        with open_worm(":memory:", ids) as anchor:
            self.validate(
                "triaxis_completion_worm_anchor_head_v1.schema.json",
                anchor.head(now_tick=1)["inner_contract"],
            )

    def test_completion_worm_anchor_status_schema(self):
        ids = v330_identities()
        effect_id = make_intent()["effect_id"]
        with open_worm(":memory:", ids) as anchor:
            session = VerifierFreshnessSession.create("verifier:v330:schema:anchor", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(1, 20)
                status = anchor.issue_status(
                    effect_id=effect_id,
                    expected_payload_sha256=B,
                    challenge=challenge,
                    verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256,
                    requested_at=1,
                    issued_at=1,
                    valid_until=20,
                )
                self.validate(
                    "triaxis_completion_worm_anchor_status_v1.schema.json",
                    status["inner_contract"],
                )


if __name__ == "__main__":
    unittest.main()
