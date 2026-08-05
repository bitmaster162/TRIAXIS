from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from examples.build_authenticated_assurance_example import build


class V360AuthenticatedExampleTests(unittest.TestCase):
    def test_example_completes_without_writing_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = build(Path(tmp))
            self.assertEqual(summary["authorization"], "PASS")
            self.assertEqual(summary["token_outcome"], "ALLOW")
            self.assertEqual(summary["completed_state"], "COMPLETED")
            self.assertFalse(summary["private_keys_written"])
            for path in Path(tmp).glob("*.json"):
                self.assertNotIn("private_key_b64", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
