from __future__ import annotations

import unittest

from validation.composition_state.case_bank import templates


class CompositionStateFrameworkTests(unittest.TestCase):
    def test_required_families_exist(self) -> None:
        families = {row["family"] for row in templates()}
        self.assertTrue({"graph_order", "completion", "role_separation", "lexical_ambiguity", "imperative_positive", "severity", "integrity"} <= families)

    def test_templates_have_exact_oracles(self) -> None:
        names = set()
        for row in templates():
            self.assertNotIn(row["template_name"], names)
            names.add(row["template_name"])
            self.assertIn(row["expected_status"], {"ALLOW", "ALLOW_WITH_LIMITS", "HOLD", "HUMAN_DECISION_REQUIRED", "BLOCK"})
            self.assertIsInstance(row["expected_reason"], str)
            self.assertTrue(row["record"]["nodes"])


if __name__ == "__main__":
    unittest.main()
