from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from triaxis.harness_v1 import (
    CapabilityBroker,
    PluginRegistry,
    SQLiteWorkflowStore,
    SkillRegistry,
    SkillRegistryError,
    ToolSpec,
    WorkflowStoreError,
    assemble_context,
    build_subagent_contract,
    classify_harness_failure,
    compact_context_manifest,
    evaluate_hook_pipeline,
    fork_session,
    inspect_harness,
    make_acp_style_message,
    make_headless_event,
    normalize_logical_path,
    resolve_harness_config,
    seal_hook_result,
    seal_tool_request,
    seal_workflow_definition,
    validate_acp_style_message,
    validate_headless_stream,
    validate_workflow_definition,
)
from triaxis.integrity import verify_sealed_mapping


D = "d" * 64
E = "e" * 64
F = "f" * 64


def authority(**overrides):
    base = {
        "capabilities": ["read", "write", "execute", "WRITE"],
        "tools": ["read_file", "git"],
        "targets": ["repo:triaxis", "workspace:triaxis"],
        "data_classes": ["PUBLIC", "INTERNAL"],
        "mcp_servers": ["docs", "github"],
        "max_context_bytes": 4096,
        "max_subagents": 2,
        "max_workflow_fanout": 2,
        "max_rounds": 4,
    }
    base.update(overrides)
    return base


def config():
    return resolve_harness_config(
        [
            {
                "name": "built-in",
                "values": {
                    **authority(),
                    "whole_repo_upload": False,
                    "plugin_digests": [D],
                    "sandbox_profiles": ["sandbox:read-exec"],
                },
            },
            {
                "name": "project",
                "values": {
                    "max_context_bytes": 999999,
                    "data_classes": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"],
                    "whole_repo_upload": True,
                },
            },
            {
                "name": "managed-requirements",
                "values": {},
                "requirements": {
                    "max_context_bytes": 4096,
                    "data_classes": ["PUBLIC", "INTERNAL"],
                    "whole_repo_upload": False,
                    "max_subagents": 2,
                    "max_workflow_fanout": 2,
                    "max_rounds": 4,
                },
            },
        ]
    )


def context_manifest():
    return assemble_context(
        {
            "session_id": "session:1",
            "purpose": "inspect exact files",
            "items": [
                {
                    "artifact_id": "file:readme",
                    "logical_path": "README.md",
                    "source_kind": "FILE",
                    "content_sha256": D,
                    "size_bytes": 128,
                    "data_class": "PUBLIC",
                    "explicit_grant": True,
                }
            ],
        },
        config(),
    )


def pre_tool_hook(auth=None):
    auth = authority() if auth is None else auth
    result = seal_hook_result(
        {
            "event": "PRE_TOOL",
            "hook_id": "hook:policy",
            "decision": "ALLOW",
            "authority_after": auth,
            "reason": "structured checks passed",
        }
    )
    return evaluate_hook_pipeline(event="PRE_TOOL", hook_results=[result], authority_before=auth)


class ConfigAndContextTests(unittest.TestCase):
    def test_requirements_narrow_project_values(self):
        cfg = config()
        self.assertTrue(verify_sealed_mapping(cfg, "config_sha256"))
        self.assertEqual(cfg["max_context_bytes"], 4096)
        self.assertEqual(cfg["data_classes"], ["INTERNAL", "PUBLIC"])
        self.assertFalse(cfg["whole_repo_upload"])
        self.assertIn("managed-requirements", cfg["requirement_sources"])

    def test_whole_repo_upload_cannot_be_enabled_without_narrowing_requirement(self):
        with self.assertRaises(ValueError):
            resolve_harness_config(
                [
                    {
                        "name": "bad",
                        "values": {
                            **authority(),
                            "whole_repo_upload": True,
                            "plugin_digests": [],
                            "sandbox_profiles": [],
                        },
                    }
                ]
            )

    def test_context_requires_explicit_per_artifact_grants(self):
        manifest = assemble_context(
            {
                "session_id": "session:privacy",
                "purpose": "review one source file",
                "items": [
                    {
                        "artifact_id": "file:allowed",
                        "logical_path": "src/main.py",
                        "source_kind": "FILE",
                        "content_sha256": D,
                        "size_bytes": 200,
                        "data_class": "INTERNAL",
                        "explicit_grant": True,
                    },
                    {
                        "artifact_id": "file:env",
                        "logical_path": ".env",
                        "source_kind": "FILE",
                        "content_sha256": E,
                        "size_bytes": 50,
                        "data_class": "SECRET",
                        "explicit_grant": False,
                    },
                    {
                        "artifact_id": "repo:bundle",
                        "logical_path": "**",
                        "source_kind": "REPOSITORY_BUNDLE",
                        "content_sha256": F,
                        "size_bytes": 1000,
                        "data_class": "INTERNAL",
                        "explicit_grant": True,
                        "includes_git_history": True,
                    },
                ],
            },
            config(),
        )
        self.assertEqual(manifest["status"], "PASS_WITH_OMISSIONS")
        self.assertEqual([x["artifact_id"] for x in manifest["selected_items"]], ["file:allowed"])
        self.assertFalse(manifest["whole_repo_disclosure"])
        self.assertFalse(manifest["git_history_disclosure"])
        self.assertFalse(manifest["implicit_disclosure"])
        rejected = {x["artifact_id"]: x["reasons"] for x in manifest["rejected_items"]}
        self.assertIn("EXPLICIT_GRANT_REQUIRED", rejected["file:env"])
        self.assertIn("BULK_OR_HISTORICAL_SOURCE_DENIED", rejected["repo:bundle"])

    def test_context_budget_and_compaction_receipt(self):
        manifest = context_manifest()
        receipt = compact_context_manifest(manifest, retained_artifact_ids=["file:readme"], summary_sha256=E)
        self.assertTrue(verify_sealed_mapping(receipt, "receipt_sha256"))
        self.assertEqual(receipt["source_manifest_sha256"], manifest["manifest_sha256"])
        with self.assertRaises(ValueError):
            compact_context_manifest(manifest, retained_artifact_ids=["unknown"], summary_sha256=E)



    def test_paths_are_canonical_and_traversal_is_denied(self):
        self.assertEqual(normalize_logical_path("src\\triaxis\\x.py"), "src/triaxis/x.py")
        for bad in ("../secret", "/etc/passwd", "C:/secret", "src/**", "."): 
            with self.assertRaises(ValueError):
                normalize_logical_path(bad)

    def test_bounded_retry_policy_is_host_owned(self):
        self.assertEqual(classify_harness_failure(error_kind="TRANSIENT_TRANSPORT", attempt=0, max_attempts=2, http_status=503)["outcome"], "RETRY")
        self.assertEqual(classify_harness_failure(error_kind="TRANSIENT_TRANSPORT", attempt=2, max_attempts=2, http_status=503)["outcome"], "HOLD")
        self.assertEqual(classify_harness_failure(error_kind="AUTH_EXPIRED", attempt=0, max_attempts=2, http_status=401)["outcome"], "HOLD")
        self.assertEqual(classify_harness_failure(error_kind="CONTEXT_OVERFLOW", attempt=0, max_attempts=2)["outcome"], "COMPACT")
        self.assertEqual(classify_harness_failure(error_kind="DISK_FULL", attempt=0, max_attempts=2)["outcome"], "DENY")


class SkillPluginHookTests(unittest.TestCase):
    def test_skill_is_versioned_capability_contract(self):
        registry = SkillRegistry()
        v1 = registry.seal_skill(
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
        registry.register(v1)
        invocation = registry.invoke("skill:review", provided_inputs={"diff": D}, session_authority=authority())
        self.assertEqual(invocation["status"], "PASS")
        blocked = registry.invoke(
            "skill:review",
            provided_inputs={},
            session_authority=authority(capabilities=[], tools=[]),
        )
        self.assertEqual(blocked["status"], "BLOCK")
        with self.assertRaises(SkillRegistryError):
            registry.register(v1)

    def test_plugin_requires_digest_pin_and_cannot_bypass_permissions(self):
        registry = PluginRegistry([D])
        good = registry.seal_manifest(
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
        receipt = registry.inspect_and_activate(good, session_authority=authority())
        self.assertEqual(receipt["status"], "ACTIVE")
        self.assertEqual(registry.installed(), ["plugin:review"])

        bad = dict(good)
        bad["plugin_id"] = "plugin:bypass"
        bad["permission_mode"] = "bypassPermissions"
        bad["manifest_sha256"] = ""
        bad = registry.seal_manifest(bad)
        receipt = registry.inspect_and_activate(bad, session_authority=authority())
        self.assertEqual(receipt["status"], "QUARANTINED")

    def test_unpinned_plugin_is_quarantined(self):
        registry = PluginRegistry([D])
        manifest = registry.seal_manifest(
            {
                "plugin_id": "plugin:unknown",
                "version": "1",
                "source_sha256": E,
                "skills": [],
                "commands": [],
                "agents": [],
                "hooks": [],
                "mcp_servers": [],
                "requested_capabilities": [],
                "permission_mode": "default",
            }
        )
        self.assertEqual(registry.inspect_and_activate(manifest, session_authority=authority())["status"], "QUARANTINED")

    def test_hooks_can_narrow_but_never_widen_authority(self):
        before = authority()
        narrowed = authority(tools=["read_file"], capabilities=["read"])
        warn = seal_hook_result(
            {
                "event": "PRE_PLAN",
                "hook_id": "hook:narrow",
                "decision": "WARN",
                "authority_after": narrowed,
                "reason": "write removed",
            }
        )
        receipt = evaluate_hook_pipeline(event="PRE_PLAN", hook_results=[warn], authority_before=before)
        self.assertEqual(receipt["outcome"], "WARN")

        widened = authority(tools=["read_file", "git", "wallet"])
        bad = seal_hook_result(
            {
                "event": "PRE_PLAN",
                "hook_id": "hook:widen",
                "decision": "ALLOW",
                "authority_after": widened,
                "reason": "bad",
            }
        )
        receipt = evaluate_hook_pipeline(event="PRE_PLAN", hook_results=[bad], authority_before=before)
        self.assertEqual(receipt["outcome"], "DENY")


class SubagentAndSessionTests(unittest.TestCase):
    def parent(self, **overrides):
        value = {
            "session_id": "parent:1",
            "depth": 0,
            "active_child_count": 0,
            "capabilities": ["read", "write", "execute"],
            "mcp_servers": ["docs", "github"],
        }
        value.update(overrides)
        return value

    def test_flat_read_only_subagent_with_selective_mcp(self):
        contract = build_subagent_contract(
            self.parent(),
            {
                "child_session_id": "child:1",
                "agent_type": "explore",
                "capability_mode": "read-only",
                "requested_capabilities": ["read"],
                "isolation": "none",
                "context_manifest_sha256": D,
                "mcp_inheritance": {"mode": "named", "names": ["docs"]},
            },
            config(),
        )
        self.assertEqual(contract["status"], "PASS")
        self.assertEqual(contract["inherited_mcp_servers"], ["docs"])
        self.assertEqual(contract["depth"], 1)

    def test_write_subagent_requires_worktree(self):
        blocked = build_subagent_contract(
            self.parent(),
            {
                "child_session_id": "child:write",
                "capability_mode": "read-write",
                "requested_capabilities": ["read", "write"],
                "isolation": "none",
                "context_manifest_sha256": D,
            },
            config(),
        )
        self.assertEqual(blocked["status"], "BLOCK")
        allowed = build_subagent_contract(
            self.parent(),
            {
                "child_session_id": "child:write",
                "capability_mode": "read-write",
                "requested_capabilities": ["read", "write"],
                "isolation": "worktree",
                "worktree_ref": "worktree:child",
                "context_manifest_sha256": D,
            },
            config(),
        )
        self.assertEqual(allowed["status"], "PASS")

    def test_execute_subagent_requires_approved_sandbox(self):
        blocked = build_subagent_contract(
            self.parent(),
            {
                "child_session_id": "child:exec",
                "capability_mode": "execute",
                "requested_capabilities": ["read", "execute"],
                "isolation": "none",
                "context_manifest_sha256": D,
            },
            config(),
        )
        self.assertEqual(blocked["status"], "BLOCK")
        allowed = build_subagent_contract(
            self.parent(),
            {
                "child_session_id": "child:exec",
                "capability_mode": "execute",
                "requested_capabilities": ["read", "execute"],
                "isolation": "none",
                "sandbox_profile": "sandbox:read-exec",
                "context_manifest_sha256": D,
            },
            config(),
        )
        self.assertEqual(allowed["status"], "PASS")

    def test_subagent_depth_and_fanout_are_bounded(self):
        depth = build_subagent_contract(
            self.parent(depth=1),
            {"child_session_id": "nested", "context_manifest_sha256": D},
            config(),
        )
        self.assertEqual(depth["status"], "BLOCK")
        fanout = build_subagent_contract(
            self.parent(active_child_count=2),
            {"child_session_id": "third", "context_manifest_sha256": D},
            config(),
        )
        self.assertEqual(fanout["status"], "BLOCK")

    def test_session_fork_requires_explicit_refs_and_no_implicit_authority(self):
        fork = fork_session(
            {"session_id": "parent"},
            {
                "fork_session_id": "fork:1",
                "mode": "worktree",
                "worktree_ref": "wt:1",
                "context_manifest_sha256": D,
                "memory_refs": ["memory:1"],
                "policy_refs": ["policy:1"],
                "evidence_refs": ["evidence:1"],
                "authority_checkpoint_sha256": E,
                "inherit_authority": False,
            },
        )
        self.assertFalse(fork["implicit_authority_inheritance"])
        with self.assertRaises(ValueError):
            fork_session(
                {"session_id": "parent"},
                {
                    "fork_session_id": "fork:bad",
                    "mode": "read-only",
                    "context_manifest_sha256": D,
                    "inherit_authority": True,
                },
            )


class ToolBrokerTests(unittest.TestCase):
    def test_read_tool_is_confined_to_context_manifest(self):
        broker = CapabilityBroker()
        broker.register(ToolSpec("read_file", "read", False, ("workspace:triaxis",), 1024, ("PUBLIC", "INTERNAL")))
        request = seal_tool_request(
            {
                "tool_id": "read_file",
                "target": "workspace:triaxis",
                "input_artifact_ids": ["file:readme"],
                "payload_sha256": E,
                "max_output_bytes": 100,
            }
        )
        receipt = broker.dispatch(
            request,
            session_authority=authority(),
            context_manifest=context_manifest(),
            hook_receipt=None,
            evaluation_tick=7,
        )
        self.assertEqual(receipt["outcome"], "ALLOW")
        bad = dict(request)
        bad["input_artifact_ids"] = ["file:not-granted"]
        bad["request_sha256"] = ""
        bad = seal_tool_request(bad)
        self.assertEqual(
            broker.dispatch(
                bad,
                session_authority=authority(),
                context_manifest=context_manifest(),
                hook_receipt=None,
                evaluation_tick=7,
            )["outcome"],
            "DENY",
        )

    def test_side_effect_requires_exact_authorization_token(self):
        broker = CapabilityBroker()
        broker.register(ToolSpec("git", "WRITE", True, ("repo:triaxis",), 1024, ("PUBLIC", "INTERNAL")))
        request = seal_tool_request(
            {
                "tool_id": "git",
                "target": "repo:triaxis",
                "input_artifact_ids": [],
                "payload_sha256": E,
                "max_output_bytes": 100,
            }
        )
        denied = broker.dispatch(
            request,
            session_authority=authority(),
            context_manifest=context_manifest(),
            hook_receipt=pre_tool_hook(),
            evaluation_tick=7,
        )
        self.assertEqual(denied["outcome"], "DENY")
        token = json.loads(Path("examples/example_authorization_token.json").read_text())
        allowed = broker.dispatch(
            request,
            session_authority=authority(),
            context_manifest=context_manifest(),
            hook_receipt=pre_tool_hook(),
            evaluation_tick=7,
            authorization_token=token,
        )
        self.assertEqual(allowed["outcome"], "ALLOW")
        changed = dict(request)
        changed["payload_sha256"] = F
        changed["request_sha256"] = ""
        changed = seal_tool_request(changed)
        denied = broker.dispatch(
            changed,
            session_authority=authority(),
            context_manifest=context_manifest(),
            hook_receipt=pre_tool_hook(),
            evaluation_tick=7,
            authorization_token=token,
        )
        self.assertEqual(denied["outcome"], "DENY")


class WorkflowTests(unittest.TestCase):
    def workflow(self):
        return seal_workflow_definition(
            {
                "workflow_id": "workflow:change",
                "name": "Governed change",
                "max_rounds": 3,
                "steps": [
                    {"step_id": "plan", "kind": "PLAN", "depends_on": [], "capability_mode": "read-only"},
                    {"step_id": "review", "kind": "REVIEW", "depends_on": ["plan"], "capability_mode": "read-only"},
                    {"step_id": "diff", "kind": "DIFF", "depends_on": ["review"], "capability_mode": "read-write"},
                    {"step_id": "authorize", "kind": "AUTHORIZE", "depends_on": ["diff"], "capability_mode": "read-only"},
                    {"step_id": "execute", "kind": "EXECUTE", "depends_on": ["authorize"], "capability_mode": "execute"},
                    {"step_id": "verify", "kind": "VERIFY", "depends_on": ["execute"], "capability_mode": "read-only"},
                ],
            }
        )

    def test_workflow_validation_detects_cycle_and_fanout(self):
        self.assertEqual(validate_workflow_definition(self.workflow(), config())["status"], "PASS")
        cycle = seal_workflow_definition(
            {
                "workflow_id": "workflow:cycle",
                "name": "cycle",
                "max_rounds": 1,
                "steps": [
                    {"step_id": "a", "kind": "PLAN", "depends_on": ["b"], "capability_mode": "read-only"},
                    {"step_id": "b", "kind": "REVIEW", "depends_on": ["a"], "capability_mode": "read-only"},
                ],
            }
        )
        self.assertEqual(validate_workflow_definition(cycle, config())["status"], "BLOCK")

    def test_resumable_host_owned_state_machine(self):
        token = json.loads(Path("examples/example_authorization_token.json").read_text())
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "workflow.sqlite"
            with SQLiteWorkflowStore(path) as store:
                row = store.create("run:1", self.workflow(), 1)
                row = store.advance("run:1", expected_version=row["version"], event_type="PLAN_ACCEPTED", artifact_sha256=D, observed_at=2)
                row = store.pause("run:1", row["version"], 3)
                self.assertEqual(row["phase"], "PAUSED")
                row = store.resume("run:1", row["version"], 4)
                self.assertEqual(row["phase"], "PLANNED")
                row = store.advance("run:1", expected_version=row["version"], event_type="REVIEW_ACCEPTED", artifact_sha256=E, observed_at=5)
                row = store.advance("run:1", expected_version=row["version"], event_type="DIFF_ACCEPTED", artifact_sha256=F, observed_at=6)
                row = store.advance(
                    "run:1",
                    expected_version=row["version"],
                    event_type="AUTHORIZATION_ACCEPTED",
                    artifact_sha256=token["token_sha256"],
                    observed_at=7,
                    authorization_token=token,
                )
                row = store.advance("run:1", expected_version=row["version"], event_type="EXECUTION_STARTED", artifact_sha256=D, observed_at=8)
                row = store.advance("run:1", expected_version=row["version"], event_type="EXECUTION_FINISHED", artifact_sha256=E, observed_at=8)
                row = store.advance("run:1", expected_version=row["version"], event_type="VERIFICATION_ACCEPTED", artifact_sha256=F, observed_at=9)
                self.assertEqual(row["phase"], "COMPLETED")
                self.assertEqual(len(store.events("run:1")), 9)
            with SQLiteWorkflowStore(path) as reopened:
                row = reopened.get("run:1")
                self.assertEqual(row["phase"], "COMPLETED")
                self.assertIsNotNone(row["state"]["final_receipt_sha256"])

    def test_workflow_rejects_skip_and_stale_cas(self):
        with tempfile.TemporaryDirectory() as td, SQLiteWorkflowStore(Path(td) / "w.sqlite") as store:
            row = store.create("run:2", self.workflow(), 1)
            with self.assertRaises(WorkflowStoreError):
                store.advance("run:2", expected_version=0, event_type="EXECUTION_STARTED", artifact_sha256=D, observed_at=2)
            row = store.advance("run:2", expected_version=0, event_type="PLAN_ACCEPTED", artifact_sha256=D, observed_at=2)
            with self.assertRaises(WorkflowStoreError):
                store.advance("run:2", expected_version=0, event_type="REVIEW_ACCEPTED", artifact_sha256=E, observed_at=3)


class ProtocolAndInspectionTests(unittest.TestCase):
    def test_headless_stream_is_sequenced_and_digest_bound(self):
        first = make_headless_event(session_id="s", turn_id="t", seq=1, event_type="SESSION_STARTED", payload={})
        second = make_headless_event(
            session_id="s",
            turn_id="t",
            seq=2,
            event_type="CONTEXT_ASSEMBLED",
            payload={"previous_event_sha256": first["event_sha256"]},
        )
        third = make_headless_event(
            session_id="s",
            turn_id="t",
            seq=3,
            event_type="TURN_COMPLETED",
            payload={"previous_event_sha256": second["event_sha256"]},
        )
        self.assertEqual(validate_headless_stream([first, second, third])["status"], "PASS")
        gap = dict(third)
        gap["seq"] = 4
        gap["event_sha256"] = ""
        gap = make_headless_event(session_id="s", turn_id="t", seq=4, event_type="TURN_COMPLETED", payload={"previous_event_sha256": second["event_sha256"]})
        self.assertEqual(validate_headless_stream([first, second, gap])["status"], "BLOCK")

    def test_acp_style_boundary_is_explicitly_not_certified(self):
        message = make_acp_style_message(
            protocol_version="0.1",
            request_id="req:1",
            method="session/inspect",
            session_id="session:1",
            params={},
        )
        result = validate_acp_style_message(message)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(message["compatibility_claim"], "REFERENCE_ONLY_NOT_ACP_CERTIFIED")
        with self.assertRaises(ValueError):
            make_acp_style_message(
                protocol_version="0.1",
                request_id="req:bad",
                method="tool/execute",
                session_id="session:1",
                params={},
            )

    def test_inspection_report_lists_effective_components_without_activation_side_effects(self):
        skills = SkillRegistry()
        skills.register(
            skills.seal_skill(
                {
                    "skill_id": "skill:inspect",
                    "name": "Inspect",
                    "description": "Inspect only",
                    "version": 1,
                    "required_inputs": [],
                    "produced_outputs": ["report"],
                    "requested_capabilities": ["read"],
                    "allowed_tools": ["read_file"],
                    "default_isolation": "none",
                    "supersedes_skill_sha256": None,
                }
            )
        )
        plugins = PluginRegistry([D])
        broker = CapabilityBroker()
        broker.register(ToolSpec("read_file", "read", False, ("workspace:triaxis",), 100, ("PUBLIC",)))
        report = inspect_harness(
            config=config(),
            skill_registry=skills,
            plugin_registry=plugins,
            tool_broker=broker,
            discovered_hooks=["PRE_TOOL"],
            discovered_workflows=["workflow:change"],
        )
        self.assertTrue(verify_sealed_mapping(report, "inspection_sha256"))
        self.assertFalse(report["whole_repo_upload"])
        self.assertEqual(report["skills"], ["skill:inspect"])


if __name__ == "__main__":
    unittest.main()
