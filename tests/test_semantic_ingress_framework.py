from __future__ import annotations

import unittest

from validation.semantic_ingress.case_bank import templates


class SemanticIngressFrameworkTests(unittest.TestCase):
    def test_bank_has_required_families(self) -> None:
        families = {row["family"] for row in templates()}
        self.assertTrue({"positive", "integrity", "schema", "provenance", "authority_laundering", "modality", "ambiguity", "action_coverage", "data_surface", "task_graph"} <= families)

    def test_templates_are_unbound(self) -> None:
        for row in templates():
            self.assertNotIn("case_id", row)
            self.assertNotIn("nonce", row)

    def test_every_template_has_expected_terminal(self) -> None:
        for row in templates():
            self.assertIn(row["expected_status"], {"ALLOW", "ALLOW_WITH_LIMITS", "HUMAN_DECISION_REQUIRED", "BLOCK"})
            self.assertIsInstance(row["expected_reason"], str)
            self.assertTrue(row["record"]["nodes"])


if __name__ == "__main__":
    unittest.main()
