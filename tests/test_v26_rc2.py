from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "validation" / "framework"))

from triaxis.projection import evaluate_candidate
from case_bank import templates


class V26RC2Tests(unittest.TestCase):
    def test_rc2_is_logic_identical_to_rc1_on_frozen_bank(self) -> None:
        for case in templates():
            with self.subTest(case=case["template_name"]):
                self.assertEqual(
                    evaluate_candidate("2.6-RC2", case),
                    evaluate_candidate("2.6-RC1", case),
                )


if __name__ == "__main__":
    unittest.main()
