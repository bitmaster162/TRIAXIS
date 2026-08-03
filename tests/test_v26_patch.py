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


class V26PatchTests(unittest.TestCase):
    def test_invalid_release_manifest_is_blocked(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "release_manifest_mismatch")
        candidate = evaluate_candidate("2.6-RC1", case)
        expected = evaluate_oracle(case)
        self.assertEqual(candidate["status"], expected["status"])
        self.assertEqual(candidate["primary_reason"], expected["primary_reason"])

    def test_valid_release_manifest_is_allowed(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "release_manifest_valid")
        candidate = evaluate_candidate("2.6-RC1", case)
        expected = evaluate_oracle(case)
        self.assertEqual(candidate["status"], expected["status"])
        self.assertEqual(candidate["primary_reason"], expected["primary_reason"])

    def test_v25_remains_frozen_for_invalid_release(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "release_manifest_mismatch")
        self.assertEqual(evaluate_candidate("2.5-RC1", case)["status"], "ALLOW")
        self.assertEqual(evaluate_candidate("2.6-RC1", case)["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
