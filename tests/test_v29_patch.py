from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.input_contract import (  # noqa: E402
    INPUT_CONTRACT_V1_ID,
    INPUT_CONTRACT_V2_ID,
    schema_document,
    validate_scenario,
)
from triaxis.projection import evaluate_candidate, evaluate_ingress  # noqa: E402
from triaxis.semantic_ingress import ingress_schema_document  # noqa: E402
from validation.framework.case_bank import base_case  # noqa: E402
from validation.routing_semantics.template_bank import templates as routing_templates  # noqa: E402
from validation.semantic_ingress.case_bank import templates as semantic_templates  # noqa: E402


class V29PatchTests(unittest.TestCase):
    def test_v28_remains_bound_to_v1_contract(self) -> None:
        scenario = base_case()
        decision = evaluate_candidate("2.8-RC2", scenario)
        self.assertNotEqual(decision["primary_reason"], "BLOCKED_BY_INPUT_CONTRACT")

    def test_v29_requires_action_identity(self) -> None:
        scenario = base_case()
        decision = evaluate_candidate("2.9-RC1", scenario)
        self.assertEqual(decision["status"], "BLOCK")
        self.assertEqual(decision["primary_reason"], "BLOCKED_BY_INPUT_CONTRACT")
        self.assertEqual(decision["input_contract"], INPUT_CONTRACT_V2_ID)
        self.assertIn("declared_action_type", {row["path"] for row in decision["input_errors"]})

    def test_v29_rejects_action_risk_underclassification(self) -> None:
        scenario = base_case()
        scenario.update(declared_action_type="SEND", x_level=0)
        errors = validate_scenario(scenario, INPUT_CONTRACT_V2_ID)
        self.assertIn("risk_underclassification", {row["code"] for row in errors})

    def test_routing_semantics_full_bank(self) -> None:
        for row in routing_templates():
            with self.subTest(template=row["template_name"]):
                decision = evaluate_candidate("2.9-RC1", row["scenario"])
                self.assertEqual(decision["status"], row["expected_status"])
                self.assertEqual(decision["primary_reason"], row["expected_reason"])

    def test_semantic_ingress_full_bank(self) -> None:
        for row in semantic_templates():
            with self.subTest(template=row["template_name"]):
                decision = evaluate_ingress("2.9-RC1", row["record"])
                self.assertEqual(decision["status"], row["expected_status"])
                self.assertEqual(decision["primary_reason"], row["expected_reason"])

    def test_v2_schema_artifact_matches_runtime(self) -> None:
        path = ROOT / "validation" / "schemas" / "triaxis_structured_scenario_v2.schema.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), schema_document(INPUT_CONTRACT_V2_ID))

    def test_semantic_schema_artifact_matches_runtime(self) -> None:
        path = ROOT / "validation" / "schemas" / "triaxis_semantic_ingress_v1.schema.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), ingress_schema_document())

    def test_v1_schema_contract_is_stable(self) -> None:
        path = ROOT / "validation" / "schemas" / "triaxis_structured_scenario_v1.schema.json"
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), schema_document(INPUT_CONTRACT_V1_ID))


if __name__ == "__main__":
    unittest.main()
