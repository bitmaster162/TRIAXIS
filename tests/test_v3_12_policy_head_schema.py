from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from tests.test_v3_12_policy_head_authority import PolicyHeadFixture
from triaxis.policy_head_authority import validate_policy_head_response


class PolicyHeadSchemaTests(unittest.TestCase):
    def test_schema_is_valid_and_accepts_reference_response(self):
        schema = json.loads(Path("schemas/triaxis_policy_head_authority_response_v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        fx = PolicyHeadFixture()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with fx.store(root / "policy.db") as store:
                fx.install(store, fx.policy1, fx.policy2)
                with fx.service(root / "responses.db", store) as service:
                    session, ledger, challenge = fx.challenge(root)
                    with ledger:
                        signed = fx.response(service, session, challenge)
                        response = signed["inner_contract"]
        Draft202012Validator(schema).validate(response)
        self.assertEqual(validate_policy_head_response(response, 9)["status"], "PASS")

    def test_trust_key_schema_knows_new_purposes(self):
        schema = json.loads(Path("schemas/triaxis_ed25519_trust_key_v1.schema.json").read_text())
        purposes = schema["properties"]["purposes"]["items"]["enum"]
        self.assertIn("ANCHOR_QUORUM_POLICY", purposes)
        self.assertIn("POLICY_HEAD_AUTHORITY", purposes)


if __name__ == "__main__":
    unittest.main()
