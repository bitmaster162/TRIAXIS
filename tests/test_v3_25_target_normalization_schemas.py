from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from triaxis.harness_governance_v2 import canonicalize_tool_target, evaluate_tool_policy
from tests.test_v3_25_target_normalization import allow_rule, request


class TargetNormalizationSchemaTests(unittest.TestCase):
    def validate(self, name, value):
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_reference_contracts(self):
        identity = canonicalize_tool_target("https://repo.example/safe/readme.md")
        self.validate("triaxis_canonical_tool_target_v1.schema.json", identity)
        rule = allow_rule()
        self.validate("triaxis_tool_policy_rule_v2.schema.json", rule)
        decision = evaluate_tool_policy([rule], request("https://repo.example/safe/readme.md"), mode="DEFAULT")
        self.validate("triaxis_tool_policy_decision_v2.schema.json", decision)


if __name__ == "__main__":
    unittest.main()
