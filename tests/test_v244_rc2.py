from __future__ import annotations

import unittest

from validation.provenance_trust.authority_checkpoint_scope_atomicity_trigger_v39 import run_trigger


class V244RC2ValidationTests(unittest.TestCase):
    def test_scope_atomicity_post_product_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)


if __name__ == "__main__":
    unittest.main()
