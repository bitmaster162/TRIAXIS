from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_26_durable_dispatch import D, E, F, queued
from triaxis.harness_durability_v3 import SQLiteDurableDispatchQueue, seal_provider_request_receipt


class DurableDispatchSchemaTests(unittest.TestCase):
    def validate(self, name: str, value: dict) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_reference_contracts(self):
        item = queued("q:1")
        self.validate("triaxis_queued_input_v1.schema.json", item)
        store = SQLiteDurableDispatchQueue()
        try:
            store.enqueue(item)
            claim = store.claim_next(thread_id="thread:1", thread_idle=True, claim_id="claim:1", now_tick=2)["claim"]
            self.validate("triaxis_dispatch_claim_v1.schema.json", claim)
            store.begin_dispatch("q:1", claim_id="claim:1", dispatch_id=claim["dispatch_id"], now_tick=3)
            self.validate("triaxis_dispatch_transition_v1.schema.json", store.events("q:1")[-1])
        finally:
            store.close()
        provider = seal_provider_request_receipt({
            "provider_id": "openai", "model_id": "model:x", "provider_request_id": "req_123",
            "run_id": "run:1", "trace_id": "trace:1", "internal_request_sha256": D,
            "provider_request_sha256": E, "provider_response_sha256": F,
            "started_at_tick": 1, "ended_at_tick": 2, "status": "PASS",
        })
        self.validate("triaxis_provider_request_receipt_v1.schema.json", provider)


if __name__ == "__main__":
    unittest.main()
