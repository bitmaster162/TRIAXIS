from __future__ import annotations
import unittest
from validation.TRIAXIS_EXTERNAL_ANCHOR_REPLAY_TRIGGER_v2 import run_trigger


class V390ExternalAnchorReplayTriggerTests(unittest.TestCase):
    def test_trigger_closes_all_cases(self):
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], result["case_count"])
        self.assertTrue(any(row.get("positive_control") for row in result["rows"]))


if __name__ == "__main__":
    unittest.main()
