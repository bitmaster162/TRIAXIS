from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "validation" / "framework"))

from triaxis.projection import evaluate_candidate
from oracle import evaluate_oracle
from case_bank import templates


class ProjectionTests(unittest.TestCase):
    def test_v23_legacy_controls_match_oracle(self) -> None:
        for case in templates():
            if case["family"] != "legacy":
                continue
            with self.subTest(case=case["template_name"]):
                candidate = evaluate_candidate("2.3-RC1", case)
                expected = evaluate_oracle(case)
                self.assertEqual(candidate["status"], expected["status"])
                self.assertEqual(candidate["primary_reason"], expected["primary_reason"])

    def test_known_new_family_gap_exists_before_holdout(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "open_policy_conflict")
        candidate = evaluate_candidate("2.3-RC1", case)
        expected = evaluate_oracle(case)
        self.assertNotEqual(candidate, expected)


if __name__ == "__main__":
    unittest.main()
