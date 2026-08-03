from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from validation.input_contract.fault_bank import templates


class InputContractFrameworkTests(unittest.TestCase):
    def test_fault_bank_covers_required_classes(self) -> None:
        rows = templates()
        families = {row["family"] for row in rows}
        self.assertGreaterEqual(len(rows), 35)
        for family in {"missing_required", "missing_conditional", "invalid_type", "invalid_enum", "unsafe_coercion", "unknown_field", "semantic_inconsistency"}:
            self.assertIn(family, families)

    def test_each_fault_has_scenario(self) -> None:
        self.assertTrue(all(isinstance(row.get("scenario"), dict) for row in templates()))


if __name__ == "__main__":
    unittest.main()
