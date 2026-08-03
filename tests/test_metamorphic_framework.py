from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from validation.metamorphic.template_bank import templates


class MetamorphicFrameworkTests(unittest.TestCase):
    def test_bank_has_multiple_relation_families(self) -> None:
        rows = templates()
        self.assertGreaterEqual(len(rows), 30)
        self.assertGreaterEqual(len({row["family"] for row in rows}), 6)
        self.assertIn("MUST_BLOCK", {row["relation"] for row in rows})
        self.assertIn("SAME_DECISION", {row["relation"] for row in rows})
        self.assertIn("MUTANT_MUST_ALLOW", {row["relation"] for row in rows})

    def test_case_ids_are_not_preassigned(self) -> None:
        self.assertTrue(all("case_id" not in row for row in templates()))


if __name__ == "__main__":
    unittest.main()
