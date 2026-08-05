from __future__ import annotations
import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator
from tests.test_v3_13_policy_head_quorum import PolicyHeadQuorumFixture


class PolicyHeadQuorumSchemaTests(unittest.TestCase):
    def test_schema_accepts_reference_config(self):
        schema = json.loads(Path("schemas/triaxis_policy_head_quorum_config_v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(PolicyHeadQuorumFixture().config)


if __name__ == "__main__":
    unittest.main()
