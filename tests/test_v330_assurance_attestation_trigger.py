from __future__ import annotations

import unittest

from validation.TRIAXIS_OPERATIONAL_ASSURANCE_ATTESTATION_TRIGGER_v1 import run_trigger


class V330AssuranceAttestationTriggerTests(unittest.TestCase):
    def test_trigger_closes_all_cases(self):
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], result["case_count"])
        self.assertGreaterEqual(result["case_count"], 6)
        self.assertTrue(any(row["positive_control"] for row in result["rows"]))


if __name__ == "__main__":
    unittest.main()
