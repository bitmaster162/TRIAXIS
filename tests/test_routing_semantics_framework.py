from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from validation.routing_semantics.template_bank import templates


class RoutingSemanticsFrameworkTests(unittest.TestCase):
    def test_material_families_are_present(self) -> None:
        families = {row["family"] for row in templates()}
        self.assertTrue(
            {
                "action_risk_lower_bound",
                "action_risk_positive",
                "x0_binding",
                "x0_precondition",
                "x0_verification",
                "x0_budget",
                "x0_limit_propagation",
                "x0_blocker_precedence",
                "x0_positive",
                "metadata_invariance",
            }.issubset(families)
        )

    def test_case_names_are_unique(self) -> None:
        names = [row["template_name"] for row in templates()]
        self.assertEqual(len(names), len(set(names)))

    def test_exact_oracle_fields_exist(self) -> None:
        for row in templates():
            with self.subTest(case=row["template_name"]):
                self.assertIn("expected_status", row)
                self.assertIn("expected_reason", row)
                self.assertIn("scenario", row)


if __name__ == "__main__":
    unittest.main()
