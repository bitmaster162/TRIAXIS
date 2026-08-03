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


class V25PatchTests(unittest.TestCase):
    def test_correlated_evidence_is_blocked(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "correlated_independent_sources")
        candidate = evaluate_candidate("2.5-RC1", case)
        expected = evaluate_oracle(case)
        self.assertEqual(candidate["status"], expected["status"])
        self.assertEqual(candidate["primary_reason"], expected["primary_reason"])

    def test_v24_remains_frozen_for_same_case(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "correlated_independent_sources")
        self.assertEqual(evaluate_candidate("2.4-RC1", case)["status"], "ALLOW")
        self.assertEqual(evaluate_candidate("2.5-RC1", case)["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
