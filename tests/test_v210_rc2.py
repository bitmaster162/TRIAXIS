from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.projection import evaluate_candidate, evaluate_ingress  # noqa: E402
from validation.composition_state.case_bank import templates as composition_templates  # noqa: E402
from validation.routing_semantics.template_bank import templates as routing_templates  # noqa: E402
from validation.semantic_ingress.case_bank import templates as semantic_templates  # noqa: E402


class V210RC2Tests(unittest.TestCase):
    def test_rc2_is_logic_identical_to_rc1_across_all_frozen_banks(self) -> None:
        for row in routing_templates():
            with self.subTest(bank="routing", template=row["template_name"]):
                self.assertEqual(
                    evaluate_candidate("2.10-RC2", row["scenario"]),
                    evaluate_candidate("2.10-RC1", row["scenario"]),
                )
        for bank_name, rows in (("semantic", semantic_templates()), ("composition", composition_templates())):
            for row in rows:
                with self.subTest(bank=bank_name, template=row["template_name"]):
                    self.assertEqual(
                        evaluate_ingress("2.10-RC2", row["record"]),
                        evaluate_ingress("2.10-RC1", row["record"]),
                    )


if __name__ == "__main__":
    unittest.main()
