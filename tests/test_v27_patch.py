from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.projection import evaluate_candidate
from validation.metamorphic.template_bank import templates


PATCHED = {
    "material_contradiction_x1",
    "material_contradiction_x2",
    "reliance_plus_broken_lineage",
    "reliance_plus_invalid_release",
    "reliance_plus_secret_trace",
    "tampered_ledger_x0",
    "untrusted_tool_receipt_x0",
    "toolchain_mismatch_x0",
}


class V27PatchTests(unittest.TestCase):
    def test_p1_observed_failures_are_closed(self) -> None:
        by_name = {row["template_name"]: row for row in templates()}
        for name in sorted(PATCHED):
            with self.subTest(case=name):
                row = by_name[name]
                decision = evaluate_candidate("2.7-RC1", row["mutant"])
                self.assertEqual(decision["status"], "BLOCK")
                self.assertEqual(decision["primary_reason"], row["expected_reason"])

    def test_reliance_no_longer_masks_trace_block(self) -> None:
        row = next(item for item in templates() if item["template_name"] == "reliance_plus_secret_trace")
        self.assertEqual(evaluate_candidate("2.6-RC2", row["mutant"])["status"], "ALLOW_WITH_LIMITS")
        self.assertEqual(evaluate_candidate("2.7-RC1", row["mutant"])["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
