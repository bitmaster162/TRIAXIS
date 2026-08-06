from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_27_external_execution_ledger import identities, make_intent, open_ledger
from triaxis.integrity import canonical_sha256


class ExternalExecutionLedgerSchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_reference_contracts(self):
        keys, _ = identities()
        ledger = open_ledger(":memory:", keys)
        try:
            intent = make_intent()
            self.validate("triaxis_execution_intent_v1.schema.json", intent)
            dispatch_id = canonical_sha256({"dispatch": 1})
            reserved = ledger.reserve(intent, attempt_id="attempt:1", dispatch_id=dispatch_id, now_tick=2)
            self.validate("triaxis_execution_ledger_event_v1.schema.json", reserved["signed_receipt"]["inner_contract"])
            head = ledger.head(now_tick=3)
            self.validate("triaxis_execution_ledger_head_v1.schema.json", head["inner_contract"])
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
