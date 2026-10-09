from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from triaxis.canon_profile import validate_canon_profile


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "canon" / "TRIAXIS_CANON_PROFILE_R1.json"
BASELINE = "a292ff969ef291238e8a28a443c090a86e7bd2e7"


def load_profile() -> dict:
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


class CanonProfileR1Tests(unittest.TestCase):
    def test_exact_baseline_passes_read_only(self) -> None:
        result = validate_canon_profile(load_profile(), observed_main_sha=BASELINE)
        self.assertEqual(result["status"], "PASS_CANON_PROFILE_READ_ONLY")
        self.assertEqual(result["selected_decisions"], 27)
        self.assertFalse(result["usable_for_apply"])
        self.assertEqual(result["authority"]["merge"], "DENY")
        self.assertEqual(result["authority"]["deploy"], "DENY")
        self.assertEqual(result["authority"]["provider_effect"], "DENY")

    def test_baseline_drift_holds(self) -> None:
        result = validate_canon_profile(load_profile(), observed_main_sha="0" * 40)
        self.assertEqual(result["status"], "HOLD_BASELINE_DRIFT")
        self.assertFalse(result["usable_for_apply"])

    def test_duplicate_decision_ids_fail_closed(self) -> None:
        profile = load_profile()
        profile["selected_decisions"].append(profile["selected_decisions"][0])
        result = validate_canon_profile(profile, observed_main_sha=BASELINE)
        self.assertEqual(result["status"], "HOLD_PROFILE_INVALID")
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("duplicate_selected_decision", codes)

    def test_research_evidence_cannot_be_promoted_to_verified_main(self) -> None:
        profile = load_profile()
        profile = deepcopy(profile)
        target = next(entry for entry in profile["entries"] if entry["decision_id"] == "D021")
        target["status"] = "VERIFIED_MAIN"
        target["evidence"] = "research/decision-closure-ebd-v0.3"
        result = validate_canon_profile(profile, observed_main_sha=BASELINE)
        self.assertEqual(result["status"], "HOLD_PROFILE_INVALID")
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("non_main_evidence_promoted", codes)

    def test_entry_set_must_match_selected_decisions(self) -> None:
        profile = load_profile()
        profile = deepcopy(profile)
        profile["entries"] = profile["entries"][:-1]
        result = validate_canon_profile(profile, observed_main_sha=BASELINE)
        self.assertEqual(result["status"], "HOLD_PROFILE_INVALID")
        codes = {error["code"] for error in result["errors"]}
        self.assertIn("selection_entry_mismatch", codes)

    def test_known_research_and_gap_states_remain_non_authoritative(self) -> None:
        result = validate_canon_profile(load_profile(), observed_main_sha=BASELINE)
        self.assertEqual(result["status"], "PASS_CANON_PROFILE_READ_ONLY")
        self.assertIn("D129", result["research_only_or_partial"])
        self.assertIn("D134", result["gaps"])
        self.assertIn("D131", result["outside_triaxis_core"])
        self.assertEqual(result["authority"]["canon_promotion"], "DENY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
