from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from triaxis.integrity import verify_sealed_mapping


class V318ConformanceSchemaTests(unittest.TestCase):
    def test_frozen_receipt_is_valid_and_explicitly_scoped(self):
        schema = json.loads(Path("schemas/triaxis_single_host_multiprocess_conformance_v1.schema.json").read_text())
        receipt = json.loads(Path("evidence/TRIAXIS_v3.18_SINGLE_HOST_MULTIPROCESS_CONFORMANCE.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(receipt)
        self.assertTrue(verify_sealed_mapping(receipt, "receipt_sha256"))
        self.assertEqual(receipt["status"], "PASS")
        self.assertIn("single-host", receipt["claim_scope"])
        self.assertEqual(receipt["conformance_level"], "SINGLE_HOST_MULTIPROCESS")
        self.assertFalse(receipt["physical_independence"])
        self.assertFalse(receipt["administrative_independence"])
        self.assertEqual(receipt["deploy_permission"], "DENY")


if __name__ == "__main__":
    unittest.main()
