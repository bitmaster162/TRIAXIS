from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_31_availability_closed_and_immutable_anchor import (
    B,
    IMMUTABLE_ANCHOR_ID,
    PROVIDER_DOMAIN,
    PROVIDER_ID,
    PROVIDER_SERVICE_ID,
    PROVIDER_SIGNER_ID,
    all_absent_statuses,
    availability_policy,
    completion_quorum_config,
    identities_v331,
    make_intent,
    open_completion_witness,
    open_immutable_anchor,
    open_provider,
    provider_outcome,
)
from triaxis.completion_availability_control import (
    verify_availability_closed_completion_quorum,
)
from triaxis.trust_registry_quorum import (
    SQLiteEpochChallengeLedger,
    VerifierFreshnessSession,
)


class V331SchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_completion_availability_policy_schema(self):
        ids = identities_v331()
        self.validate(
            "triaxis_completion_availability_policy_v1.schema.json",
            availability_policy(ids),
        )

    def test_completion_availability_witness_schema(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        config = completion_quorum_config(ids)
        policy = availability_policy(ids)
        with ExitStack() as stack:
            witnesses = [
                stack.enter_context(open_completion_witness(":memory:", ids, index))
                for index in range(3)
            ]
            _, challenges, challenge, statuses = all_absent_statuses(
                ids, witnesses, effect_id, tick=2
            )
            stack.callback(challenges.close)
            result = verify_availability_closed_completion_quorum(
                statuses,
                registry=ids["completion_witness_registry"],
                quorum_config=config,
                expected_quorum_config_sha256=config["config_sha256"],
                availability_policy=policy,
                expected_availability_policy_sha256=policy["policy_sha256"],
                expected_effect_id=effect_id,
                expected_payload_sha256=B,
                expected_provider_id=PROVIDER_ID,
                expected_provider_service_id=PROVIDER_SERVICE_ID,
                challenge_ledger=challenges,
                expected_challenge=challenge,
                evaluation_tick=2,
            )
            self.validate(
                "triaxis_completion_availability_witness_v1.schema.json",
                result["availability_witness"],
            )

    def _immutable_fixture(self):
        ids = identities_v331()
        effect_id = make_intent()["effect_id"]
        temporary = tempfile.TemporaryDirectory(prefix="triaxis-v331-schema-")
        anchor = open_immutable_anchor(temporary.name, ids)
        provider = open_provider(":memory:", ids)
        receipt = provider_outcome(
            provider,
            effect_id=effect_id,
            request_id="provider-request:v331:schema",
            outcome="COMPLETED",
            begin_tick=1,
            outcome_tick=2,
        )
        stored = anchor.store_provider_outcome(
            receipt,
            provider_registry=ids["provider_registry"],
            expected_provider_signer_id=PROVIDER_SIGNER_ID,
            expected_provider_trust_domain=PROVIDER_DOMAIN,
            evaluation_tick=2,
            retention_until_tick=500,
        )
        return temporary, ids, effect_id, anchor, provider, stored

    def test_completion_immutable_object_receipt_schema(self):
        temporary, _, _, anchor, provider, stored = self._immutable_fixture()
        try:
            self.validate(
                "triaxis_completion_immutable_object_receipt_v1.schema.json",
                stored["signed_object_receipt"]["inner_contract"],
            )
        finally:
            provider.close()
            anchor.close()
            temporary.cleanup()

    def test_completion_immutable_anchor_event_schema(self):
        temporary, _, _, anchor, provider, stored = self._immutable_fixture()
        try:
            self.validate(
                "triaxis_completion_immutable_anchor_event_v1.schema.json",
                stored["signed_anchor_event"]["inner_contract"],
            )
        finally:
            provider.close()
            anchor.close()
            temporary.cleanup()

    def test_completion_immutable_anchor_head_schema(self):
        temporary, _, _, anchor, provider, _ = self._immutable_fixture()
        try:
            self.validate(
                "triaxis_completion_immutable_anchor_head_v1.schema.json",
                anchor.head(now_tick=2)["inner_contract"],
            )
        finally:
            provider.close()
            anchor.close()
            temporary.cleanup()

    def test_completion_immutable_anchor_status_schema(self):
        temporary, ids, effect_id, anchor, provider, _ = self._immutable_fixture()
        try:
            session = VerifierFreshnessSession.create("verifier:v331:schema:status", 0)
            with SQLiteEpochChallengeLedger(":memory:", session) as challenges:
                challenge = challenges.issue(3, 20)
                status = anchor.issue_status(
                    effect_id=effect_id,
                    expected_payload_sha256=B,
                    challenge=challenge,
                    verifier_id=session.verifier_id,
                    verifier_epoch_sha256=session.epoch_sha256,
                    requested_at=3,
                    issued_at=3,
                    valid_until=20,
                )
                self.validate(
                    "triaxis_completion_immutable_anchor_status_v1.schema.json",
                    status["inner_contract"],
                )
        finally:
            provider.close()
            anchor.close()
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
