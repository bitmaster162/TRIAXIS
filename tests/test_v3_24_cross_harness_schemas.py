from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from triaxis.harness_governance_v2 import (
    SQLiteInterruptStore,
    evaluate_guardrail_pipeline,
    evaluate_tool_policy,
    make_filtered_handoff_context,
    seal_action_observation_event,
    seal_guardrail_result,
    seal_one_shot_permission_delta,
    seal_tool_policy_rule,
    seal_trace_span,
    validate_trace_chain,
)

D = "d" * 64
E = "e" * 64
F = "f" * 64


class CrossHarnessSchemaTests(unittest.TestCase):
    def validate(self, name: str, value) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_v324_reference_contracts(self) -> None:
        rule = seal_tool_policy_rule({
            "rule_id": "admin:deny-shell",
            "source_id": "managed:policy",
            "tier": "ADMIN",
            "priority": 100,
            "tool_ids": ["shell"],
            "capabilities": ["execute"],
            "modes": ["DEFAULT"],
            "mutating": True,
            "target_prefixes": ["workspace:"],
            "decision": "DENY",
        })
        self.validate("triaxis_tool_policy_rule_v1.schema.json", rule)
        decision = evaluate_tool_policy([rule], {
            "request_sha256": D,
            "tool_id": "shell",
            "capability": "execute",
            "target": "workspace:triaxis",
            "mutating": True,
        }, mode="DEFAULT")
        self.validate("triaxis_tool_policy_decision_v1.schema.json", decision)

        delta = seal_one_shot_permission_delta({
            "grant_id": "grant:1", "request_sha256": D, "approval_sha256": E,
            "nonce": "nonce:1", "scope": "ONCE", "additional_read_paths": ["cache"],
            "additional_write_paths": [], "network_destinations": ["pypi.org:443"],
            "issued_at_tick": 5, "expires_at_tick": 10,
        })
        self.validate("triaxis_one_shot_permission_delta_v1.schema.json", delta)

        guardrail = seal_guardrail_result({
            "phase": "PRE_APPROVAL", "guardrail_id": "guard:policy",
            "request_sha256": D, "outcome": "PASS", "observed_at_tick": 5,
            "replacement_output_sha256": None,
        })
        self.validate("triaxis_tool_guardrail_result_v1.schema.json", guardrail)
        pipeline = evaluate_guardrail_pipeline(
            request_sha256=D, mutating=False, approval_sha256=None,
            pre_approval_results=[], pre_execution_results=[], post_execution_results=[],
            execution_output_sha256=None, evaluation_tick=5,
        )
        self.validate("triaxis_tool_guardrail_pipeline_v1.schema.json", pipeline)

        handoff = make_filtered_handoff_context(
            source_session_id="session:1", destination_agent_id="agent:reviewer",
            source_context_manifest_sha256=D, allowed_artifact_ids=["file:a"],
            summary_sha256=E, include_tool_history=False, authority_checkpoint_sha256=F,
        )
        self.validate("triaxis_filtered_handoff_context_v1.schema.json", handoff)

        store = SQLiteInterruptStore()
        try:
            interrupt = store.create_interrupt(
                checkpoint_id="cp:1", thread_id="thread:1", run_id="run:1",
                parent_checkpoint_id=None, state={"step": 1},
                interrupt_payload={"question": "approve?"}, created_at=5,
            )
        finally:
            store.close()
        self.validate("triaxis_interrupt_checkpoint_v1.schema.json", interrupt)

        span = seal_trace_span({
            "trace_id": "trace:1", "span_id": "span:run", "parent_span_id": None,
            "previous_span_sha256": None, "span_type": "RUN", "name": "run",
            "started_at_tick": 1, "ended_at_tick": 2, "status": "PASS",
            "attributes": {"request_sha256": D}, "redacted_fields": ["api_key"],
        })
        self.validate("triaxis_trace_span_v1.schema.json", span)
        chain = validate_trace_chain([span])
        self.validate("triaxis_trace_chain_v1.schema.json", chain)

        event = seal_action_observation_event({
            "kind": "ACTION", "event_id": "event:1", "run_id": "run:1",
            "correlation_id": "corr:1", "action_event_id": None,
            "payload_sha256": D,
        })
        self.validate("triaxis_action_observation_event_v1.schema.json", event)


if __name__ == "__main__":
    unittest.main()
