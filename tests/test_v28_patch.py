from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.input_contract import schema_document, validate_scenario
from triaxis.projection import evaluate_candidate
from validation.framework.case_bank import templates as holdout_templates
from validation.input_contract.fault_bank import templates as fault_templates
from validation.metamorphic.template_bank import templates as metamorphic_templates


class V28PatchTests(unittest.TestCase):
    def test_entire_fault_bank_fails_closed_at_input_gate(self) -> None:
        for row in fault_templates():
            with self.subTest(case=row["template_name"]):
                decision = evaluate_candidate("2.8-RC1", row["scenario"])
                self.assertEqual(decision["status"], "BLOCK")
                self.assertEqual(decision["primary_reason"], "BLOCKED_BY_INPUT_CONTRACT")
                self.assertEqual(decision["controls"], ["INPUT_CONTRACT_GATE"])
                self.assertTrue(decision["input_errors"])

    def test_valid_holdouts_preserve_v27_decision_semantics(self) -> None:
        for scenario in holdout_templates():
            with self.subTest(case=scenario["template_name"]):
                old = evaluate_candidate("2.7-RC2", scenario)
                new = evaluate_candidate("2.8-RC1", scenario)
                self.assertEqual((new["status"], new["primary_reason"]), (old["status"], old["primary_reason"]))
                self.assertNotEqual(new["primary_reason"], "BLOCKED_BY_INPUT_CONTRACT")

    def test_valid_metamorphic_inputs_preserve_v27_decision_semantics(self) -> None:
        for row in metamorphic_templates():
            for side in ("base", "mutant"):
                with self.subTest(case=row["template_name"], side=side):
                    old = evaluate_candidate("2.7-RC2", row[side])
                    new = evaluate_candidate("2.8-RC1", row[side])
                    self.assertEqual((new["status"], new["primary_reason"]), (old["status"], old["primary_reason"]))

    def test_non_mapping_never_crashes(self) -> None:
        decision = evaluate_candidate("2.8-RC1", ["not", "an", "object"])  # type: ignore[arg-type]
        self.assertEqual(decision["primary_reason"], "BLOCKED_BY_INPUT_CONTRACT")
        self.assertEqual(decision["input_errors"][0]["path"], "$")

    def test_schema_artifact_matches_runtime_projection(self) -> None:
        schema_path = ROOT / "validation" / "schemas" / "triaxis_structured_scenario_v1.schema.json"
        self.assertEqual(json.loads(schema_path.read_text(encoding="utf-8")), schema_document())

    def test_validator_does_not_coerce_boolean_strings(self) -> None:
        scenario = holdout_templates()[0]
        scenario["principal_authenticated"] = "false"
        errors = validate_scenario(scenario)
        self.assertTrue(any(error["code"] == "invalid_type" and error["path"] == "principal_authenticated" for error in errors))


if __name__ == "__main__":
    unittest.main()
