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


PATCHED_TEMPLATES = {
    "approval_quorum_missing",
    "untrusted_capability_receipt",
    "resume_from_untrusted_checkpoint",
    "material_downstream_reliance",
    "check_then_commit_race",
    "tampered_execution_ledger",
    "stale_policy_binding",
    "derived_confidential_data_loses_label",
    "delegation_scope_escalation",
    "idempotency_key_payload_collision",
    "concurrent_budget_oversubscription",
    "tool_version_changed",
    "secret_in_control_trace",
}


class V24PatchTests(unittest.TestCase):
    def test_observed_h1_defect_classes_match_oracle(self) -> None:
        by_name = {case["template_name"]: case for case in templates()}
        for name in sorted(PATCHED_TEMPLATES):
            with self.subTest(case=name):
                candidate = evaluate_candidate("2.4-RC1", by_name[name])
                expected = evaluate_oracle(by_name[name])
                self.assertEqual(candidate["status"], expected["status"])
                self.assertEqual(candidate["primary_reason"], expected["primary_reason"])

    def test_v23_behavior_remains_frozen(self) -> None:
        case = next(item for item in templates() if item["template_name"] == "stale_policy_binding")
        self.assertEqual(evaluate_candidate("2.3-RC1", case)["status"], "ALLOW")
        self.assertEqual(evaluate_candidate("2.4-RC1", case)["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
