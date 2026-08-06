from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_19_grok_harness_adoption import authority, config, context_manifest, context_materialization_receipt
from triaxis.harness_v1 import (
    PluginRegistry,
    SkillRegistry,
    build_subagent_contract,
    classify_harness_failure,
    make_acp_style_message,
    make_headless_event,
    materialize_context_receipt,
    seal_hook_result,
    seal_tool_request,
    seal_workflow_definition,
)

D = "d" * 64


class HarnessSchemaTests(unittest.TestCase):
    def validate(self, schema_name: str, value):
        schema = json.loads(Path("schemas", schema_name).read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_all_reference_contracts(self):
        cfg = config()
        self.validate("triaxis_harness_config_v1.schema.json", cfg)
        self.validate("triaxis_context_disclosure_manifest_v1.schema.json", context_manifest())
        materialized = context_materialization_receipt()
        self.validate("triaxis_context_materialization_receipt_v1.schema.json", materialized)

        skills = SkillRegistry()
        skill = skills.seal_skill(
            {
                "skill_id": "skill:review",
                "name": "Review",
                "description": "Read-only review",
                "version": 1,
                "required_inputs": ["diff"],
                "produced_outputs": ["report"],
                "requested_capabilities": ["read"],
                "allowed_tools": ["read_file"],
                "default_isolation": "none",
                "supersedes_skill_sha256": None,
            }
        )
        self.validate("triaxis_skill_capability_contract_v1.schema.json", skill)

        plugins = PluginRegistry([D])
        plugin = plugins.seal_manifest(
            {
                "plugin_id": "plugin:review",
                "version": "1.0.0",
                "source_sha256": D,
                "skills": ["skill:review"],
                "commands": ["review"],
                "agents": ["reviewer"],
                "hooks": ["PRE_TOOL"],
                "mcp_servers": ["docs"],
                "requested_capabilities": ["read"],
                "permission_mode": "default",
            }
        )
        self.validate("triaxis_plugin_manifest_v1.schema.json", plugin)

        hook = seal_hook_result(
            {
                "event": "PRE_TOOL",
                "hook_id": "hook:policy",
                "decision": "ALLOW",
                "authority_after": authority(),
                "reason": "pass",
            }
        )
        self.validate("triaxis_hook_result_v1.schema.json", hook)

        subagent = build_subagent_contract(
            {
                "session_id": "parent",
                "depth": 0,
                "active_child_count": 0,
                "capabilities": ["read"],
                "mcp_servers": ["docs"],
            },
            {
                "child_session_id": "child",
                "capability_mode": "read-only",
                "requested_capabilities": ["read"],
                "isolation": "none",
                "context_manifest_sha256": D,
                "mcp_inheritance": {"mode": "named", "names": ["docs"]},
            },
            cfg,
        )
        self.validate("triaxis_bounded_subagent_v1.schema.json", subagent)

        request = seal_tool_request(
            {
                "tool_id": "read_file",
                "target": "workspace:triaxis",
                "input_artifact_ids": ["file:readme"],
                "materialization_receipt_sha256": materialized["receipt_sha256"],
                "payload_sha256": D,
                "max_output_bytes": 100,
            }
        )
        self.validate("triaxis_tool_request_v1.schema.json", request)

        workflow = seal_workflow_definition(
            {
                "workflow_id": "workflow:review",
                "name": "Review",
                "max_rounds": 2,
                "steps": [
                    {"step_id": "plan", "kind": "PLAN", "depends_on": [], "capability_mode": "read-only"},
                    {"step_id": "review", "kind": "REVIEW", "depends_on": ["plan"], "capability_mode": "read-only"},
                ],
            }
        )
        self.validate("triaxis_host_workflow_definition_v1.schema.json", workflow)

        event = make_headless_event(session_id="s", turn_id="t", seq=1, event_type="SESSION_STARTED", payload={})
        self.validate("triaxis_headless_event_v1.schema.json", event)

        message = make_acp_style_message(protocol_version="0.1", request_id="r", method="initialize", session_id=None, params={})
        self.validate("triaxis_acp_style_message_v1.schema.json", message)

        retry = classify_harness_failure(error_kind="TRANSIENT_TRANSPORT", attempt=0, max_attempts=2, http_status=503)
        self.validate("triaxis_harness_retry_decision_v1.schema.json", retry)


if __name__ == "__main__":
    unittest.main()
