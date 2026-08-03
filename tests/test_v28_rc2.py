from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.projection import evaluate_candidate
from validation.framework.case_bank import templates as holdout_templates
from validation.input_contract.fault_bank import templates as fault_templates
from validation.metamorphic.template_bank import templates as metamorphic_templates


class V28RC2Tests(unittest.TestCase):
    def test_rc2_is_logic_identical_to_rc1_on_all_frozen_banks(self) -> None:
        scenarios: list[dict] = list(holdout_templates())
        for row in metamorphic_templates():
            scenarios.extend([row["base"], row["mutant"]])
        scenarios.extend(row["scenario"] for row in fault_templates())

        for index, scenario in enumerate(scenarios):
            with self.subTest(index=index):
                self.assertEqual(
                    evaluate_candidate("2.8-RC2", scenario),
                    evaluate_candidate("2.8-RC1", scenario),
                )


if __name__ == "__main__":
    unittest.main()
