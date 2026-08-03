from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.projection import evaluate_candidate
from validation.framework.case_bank import templates as holdout_templates
from validation.metamorphic.template_bank import templates as metamorphic_templates


class V27RC2Tests(unittest.TestCase):
    def test_rc2_matches_rc1_on_holdout_bank(self) -> None:
        for case in holdout_templates():
            with self.subTest(case=case["template_name"]):
                self.assertEqual(evaluate_candidate("2.7-RC2", case), evaluate_candidate("2.7-RC1", case))

    def test_rc2_matches_rc1_on_metamorphic_bank(self) -> None:
        for row in metamorphic_templates():
            with self.subTest(case=row["template_name"]):
                self.assertEqual(evaluate_candidate("2.7-RC2", row["base"]), evaluate_candidate("2.7-RC1", row["base"]))
                self.assertEqual(evaluate_candidate("2.7-RC2", row["mutant"]), evaluate_candidate("2.7-RC1", row["mutant"]))


if __name__ == "__main__":
    unittest.main()
