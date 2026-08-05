from __future__ import annotations

import unittest

from triaxis.assurance_router import select_assurance_plan
from triaxis.integrity import verify_sealed_mapping


class AssuranceRouterTests(unittest.TestCase):
    def test_r0_low_budget_uses_minimal_plan(self):
        plan = select_assurance_plan(
            {
                "risk_class": "R0",
                "ambiguity": "LOW",
                "budget_tier": "LOW",
                "external_side_effect": False,
                "irreversible": False,
                "over_refusal_sensitive": False,
                "factual_load_bearing": False,
            }
        )
        self.assertEqual(plan["passes"], ["PRIMARY"])
        self.assertFalse(plan["synthesizer_can_authorize"])

    def test_r2_adds_blind_devil_and_falsifier(self):
        plan = select_assurance_plan(
            {
                "risk_class": "R2",
                "ambiguity": "MEDIUM",
                "external_side_effect": False,
                "irreversible": False,
                "over_refusal_sensitive": False,
                "factual_load_bearing": True,
            }
        )
        self.assertIn("DEVIL", plan["passes"])
        self.assertIn("FALSIFIER", plan["passes"])
        self.assertEqual(plan["input_modes"]["DEVIL"], "BLIND_ARTIFACT")
        self.assertEqual(plan["input_modes"]["FALSIFIER"], "INDEPENDENT_RETRIEVAL")

    def test_angel_only_for_over_refusal_sensitive_cases(self):
        base = {
            "risk_class": "R2",
            "ambiguity": "MEDIUM",
            "external_side_effect": False,
            "irreversible": False,
            "factual_load_bearing": False,
        }
        self.assertNotIn("ANGEL", select_assurance_plan({**base, "over_refusal_sensitive": False})["passes"])
        self.assertIn("ANGEL", select_assurance_plan({**base, "over_refusal_sensitive": True})["passes"])

    def test_empirically_disabled_role_is_removed(self):
        plan = select_assurance_plan(
            {
                "risk_class": "R3",
                "ambiguity": "HIGH",
                "external_side_effect": True,
                "irreversible": False,
                "over_refusal_sensitive": True,
                "factual_load_bearing": True,
                "role_evidence": {"DEVIL": "DISABLED_LOW_VALUE", "ANGEL": "DISABLED_LOW_VALUE"},
            }
        )
        self.assertNotIn("DEVIL", plan["passes"])
        self.assertNotIn("ANGEL", plan["passes"])
        self.assertIn("INDEPENDENT_REVIEW", plan["passes"])

    def test_r4_requires_human_and_recovery_controls(self):
        plan = select_assurance_plan(
            {
                "risk_class": "R4",
                "ambiguity": "HIGH",
                "external_side_effect": True,
                "irreversible": True,
                "over_refusal_sensitive": True,
                "factual_load_bearing": True,
            }
        )
        self.assertTrue(plan["human_approval_required"])
        self.assertTrue(plan["independent_review_required"])
        self.assertIn("COMPLETE_MEDIATION", plan["deterministic_checks"])
        self.assertIn("RECOVERY_OR_COMPENSATION_PLAN", plan["deterministic_checks"])
        self.assertFalse(plan["write_credentials_in_reasoning_plane"])
        self.assertTrue(verify_sealed_mapping(plan, "plan_sha256"))


if __name__ == "__main__":
    unittest.main()
