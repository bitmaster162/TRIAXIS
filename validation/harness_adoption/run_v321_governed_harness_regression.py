from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
from typing import Any, Callable

from triaxis.harness_v1 import (
    CapabilityBroker,
    PluginRegistry,
    SQLiteWorkflowStore,
    ToolSpec,
    WorkflowStoreError,
    assemble_context,
    build_subagent_contract,
    evaluate_hook_pipeline,
    make_acp_style_message,
    materialize_context_receipt,
    materialize_plugin_package_receipt,
    normalize_logical_path,
    resolve_harness_config,
    seal_hook_result,
    seal_tool_request,
    seal_workflow_definition,
)
from triaxis.integrity import canonical_sha256, seal_mapping

D = "d" * 64
E = "e" * 64
CONTENT_BYTES = b"TRIAXIS trigger context\n"
CONTENT_SHA = hashlib.sha256(CONTENT_BYTES).hexdigest()
PLUGIN_BYTES = b"plugin regression skill\n"


def authority(**overrides: Any) -> dict[str, Any]:
    value = {
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
    value.update(overrides)
    return value


def safe_config() -> dict[str, Any]:
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
                "name": "managed",
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


def manifest() -> dict[str, Any]:
    return assemble_context(
        {
            "session_id": "session:trigger",
            "purpose": "read one public file",
            "items": [
                {
                    "artifact_id": "file:readme",
                    "logical_path": "README.md",
                    "source_kind": "FILE",
                    "content_sha256": CONTENT_SHA,
                    "size_bytes": len(CONTENT_BYTES),
                    "data_class": "PUBLIC",
                    "explicit_grant": True,
                }
            ],
        },
        safe_config(),
    )


def case(case_id: str, fn: Callable[[], tuple[bool, Any]]) -> dict[str, Any]:
    try:
        passed, observed = fn()
        return {"case_id": case_id, "status": "PASS" if passed else "FAIL", "observed": observed}
    except Exception as exc:  # frozen protocol reports failures rather than hiding them
        return {"case_id": case_id, "status": "FAIL", "observed": {"exception": type(exc).__name__, "message": str(exc)}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows: list[dict[str, Any]] = []

    def gh01():
        try:
            resolve_harness_config([
                {"name": "project", "values": {**authority(), "whole_repo_upload": True, "plugin_digests": [], "sandbox_profiles": []}}
            ])
        except ValueError as exc:
            return "whole_repo_upload" in str(exc), {"result": "BLOCK", "reason": str(exc)}
        return False, {"result": "UNEXPECTED_PASS"}
    rows.append(case("GH01", gh01))

    def gh02():
        result = assemble_context(
            {
                "session_id": "session:privacy",
                "purpose": "narrow review",
                "items": [
                    {"artifact_id": "file:allowed", "logical_path": "src/main.py", "source_kind": "FILE", "content_sha256": D, "size_bytes": 20, "data_class": "INTERNAL", "explicit_grant": True},
                    {"artifact_id": "file:env", "logical_path": ".env", "source_kind": "FILE", "content_sha256": E, "size_bytes": 20, "data_class": "SECRET", "explicit_grant": False},
                    {"artifact_id": "repo:history", "logical_path": "repo.bundle", "source_kind": "GIT_HISTORY", "content_sha256": E, "size_bytes": 20, "data_class": "INTERNAL", "explicit_grant": True, "includes_git_history": True},
                ],
            },
            safe_config(),
        )
        selected = [x["artifact_id"] for x in result["selected_items"]]
        return result["status"] == "PASS_WITH_OMISSIONS" and selected == ["file:allowed"], {"status": result["status"], "selected": selected, "rejected": result["rejected_items"]}
    rows.append(case("GH02", gh02))

    def gh03():
        blocked = []
        for path in ("../secret", "src/**", "/etc/passwd"):
            try:
                normalize_logical_path(path)
            except ValueError:
                blocked.append(path)
        return len(blocked) == 3, {"blocked": blocked}
    rows.append(case("GH03", gh03))

    def gh04():
        plugin = PluginRegistry.seal_manifest({
            "plugin_id": "plugin:unpinned", "version": "1.0.0", "source_sha256": "",
            "components": [{"component_type": "SKILL", "component_id": "skill:review", "logical_path": "skills/review.md", "content_sha256": hashlib.sha256(PLUGIN_BYTES).hexdigest(), "size_bytes": len(PLUGIN_BYTES)}],
            "skills": ["skill:review"], "commands": [], "agents": [], "hooks": [], "mcp_servers": [],
            "requested_capabilities": ["read"], "permission_mode": "default"
        })
        package = materialize_plugin_package_receipt(plugin, {"skill:review": PLUGIN_BYTES}, materializer_id="materializer:trigger", observed_at_tick=6)
        registry = PluginRegistry([E])
        receipt = registry.inspect_and_activate(plugin, session_authority=authority(), package_receipt=package, evaluation_tick=7)
        return receipt["status"] == "QUARANTINED", {"status": receipt["status"], "errors": receipt["errors"]}
    rows.append(case("GH04", gh04))

    def gh05():
        plugin = PluginRegistry.seal_manifest({
            "plugin_id": "plugin:bypass", "version": "1.0.0", "source_sha256": "",
            "components": [{"component_type": "SKILL", "component_id": "skill:review", "logical_path": "skills/review.md", "content_sha256": hashlib.sha256(PLUGIN_BYTES).hexdigest(), "size_bytes": len(PLUGIN_BYTES)}],
            "skills": ["skill:review"], "commands": [], "agents": [], "hooks": [], "mcp_servers": [],
            "requested_capabilities": ["read"], "permission_mode": "bypassPermissions"
        })
        package = materialize_plugin_package_receipt(plugin, {"skill:review": PLUGIN_BYTES}, materializer_id="materializer:trigger", observed_at_tick=6)
        registry = PluginRegistry([plugin["source_sha256"]])
        receipt = registry.inspect_and_activate(plugin, session_authority=authority(), package_receipt=package, evaluation_tick=7)
        return receipt["status"] != "ACTIVE", {"status": receipt["status"], "errors": receipt["errors"]}
    rows.append(case("GH05", gh05))

    def gh06():
        before = authority(capabilities=["read"], tools=["read_file"])
        after = authority(capabilities=["read", "execute"], tools=["read_file", "git"])
        hook = seal_hook_result({"event": "PRE_TOOL", "hook_id": "hook:bad", "decision": "ALLOW", "authority_after": after, "reason": "attempted escalation"})
        receipt = evaluate_hook_pipeline(event="PRE_TOOL", hook_results=[hook], authority_before=before)
        return receipt["outcome"] == "DENY", {"outcome": receipt["outcome"], "errors": receipt["errors"]}
    rows.append(case("GH06", gh06))

    def gh07():
        result = build_subagent_contract(
            {"session_id": "parent", "depth": 1, "active_child_count": 0, "capabilities": ["read"], "mcp_servers": []},
            {"child_session_id": "nested", "capability_mode": "read-only", "requested_capabilities": ["read"], "isolation": "none", "context_manifest_sha256": manifest()["manifest_sha256"]},
            safe_config(),
        )
        return result["status"] == "BLOCK", {"result": result["status"], "errors": result["errors"]}
    rows.append(case("GH07", gh07))

    def gh08():
        result = build_subagent_contract(
            {"session_id": "parent", "depth": 0, "active_child_count": 0, "capabilities": ["read", "write"], "mcp_servers": []},
            {"child_session_id": "writer", "capability_mode": "read-write", "requested_capabilities": ["read", "write"], "isolation": "none", "context_manifest_sha256": manifest()["manifest_sha256"]},
            safe_config(),
        )
        return result["status"] == "BLOCK", {"result": result["status"], "errors": result["errors"]}
    rows.append(case("GH08", gh08))

    def gh09():
        result = build_subagent_contract(
            {"session_id": "parent", "depth": 0, "active_child_count": 0, "capabilities": ["read", "execute"], "mcp_servers": []},
            {"child_session_id": "executor", "capability_mode": "execute", "requested_capabilities": ["read", "execute"], "isolation": "none", "sandbox_profile": "sandbox:not-approved", "context_manifest_sha256": manifest()["manifest_sha256"]},
            safe_config(),
        )
        return result["status"] == "BLOCK", {"result": result["status"], "errors": result["errors"]}
    rows.append(case("GH09", gh09))

    def gh10():
        broker = CapabilityBroker()
        broker.register(ToolSpec("git", "WRITE", True, ("repo:triaxis",), 1024, ("PUBLIC", "INTERNAL")))
        request = seal_tool_request({"tool_id": "git", "target": "repo:triaxis", "input_artifact_ids": [], "payload_sha256": E, "max_output_bytes": 100})
        hook = seal_hook_result({"event": "PRE_TOOL", "hook_id": "hook:policy", "decision": "ALLOW", "authority_after": authority(), "reason": "checks passed"})
        hook_receipt = evaluate_hook_pipeline(event="PRE_TOOL", hook_results=[hook], authority_before=authority())
        receipt = broker.dispatch(request, session_authority=authority(), context_manifest=manifest(), hook_receipt=hook_receipt, evaluation_tick=7)
        return receipt["outcome"] == "DENY", {"outcome": receipt["outcome"], "errors": receipt["errors"]}
    rows.append(case("GH10", gh10))

    def gh11():
        workflow = seal_workflow_definition({
            "workflow_id": "workflow:skip", "name": "skip", "max_rounds": 2,
            "steps": [
                {"step_id": "plan", "kind": "PLAN", "depends_on": [], "capability_mode": "read-only"},
                {"step_id": "execute", "kind": "EXECUTE", "depends_on": ["plan"], "capability_mode": "execute"},
            ],
        })
        with tempfile.TemporaryDirectory() as td, SQLiteWorkflowStore(Path(td) / "w.sqlite") as store:
            row = store.create("run:skip", workflow, 1)
            row = store.advance("run:skip", expected_version=row["version"], event_type="PLAN_ACCEPTED", artifact_sha256=D, observed_at=2)
            try:
                store.advance("run:skip", expected_version=row["version"], event_type="EXECUTION_STARTED", artifact_sha256=D, observed_at=3)
            except WorkflowStoreError as exc:
                return True, {"result": "BLOCK", "code": exc.code}
        return False, {"result": "UNEXPECTED_PASS"}
    rows.append(case("GH11", gh11))

    def gh12():
        try:
            make_acp_style_message(protocol_version="0.1", request_id="r", method="tool/execute", session_id="s", params={})
        except ValueError as exc:
            return True, {"result": "BLOCK", "reason": str(exc)}
        return False, {"result": "UNEXPECTED_PASS"}
    rows.append(case("GH12", gh12))

    def gh13():
        broker = CapabilityBroker()
        broker.register(ToolSpec("read_file", "read", False, ("workspace:triaxis",), 1024, ("PUBLIC", "INTERNAL")))
        context = manifest()
        materialized = materialize_context_receipt(context, {"file:readme": CONTENT_BYTES}, materializer_id="materializer:trigger", observed_at_tick=6)
        request = seal_tool_request({"tool_id": "read_file", "target": "workspace:triaxis", "input_artifact_ids": ["file:readme"], "materialization_receipt_sha256": materialized["receipt_sha256"], "payload_sha256": E, "max_output_bytes": 128})
        receipt = broker.dispatch(request, session_authority=authority(), context_manifest=context, materialization_receipt=materialized, hook_receipt=None, evaluation_tick=7)
        return receipt["outcome"] == "ALLOW", {"outcome": receipt["outcome"], "receipt_sha256": receipt["receipt_sha256"], "materialization_receipt_sha256": materialized["receipt_sha256"]}
    rows.append(case("GH13", gh13))

    passed = sum(row["status"] == "PASS" for row in rows)
    result = {
        "contract_id": "TRIAXIS_v3.21_GOVERNED_HARNESS_REGRESSION_v1",
        "source_upstream": "xai-org/grok-build@a5589e958437d79e13db026eedcb1720bffd4063",
        "scope": "clean-room governed harness adaptation; not upstream code conformance",
        "total": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "status": "PASS" if passed == len(rows) else "FAIL",
        "rows": rows,
        "rows_sha256": canonical_sha256(rows),
        "result_sha256": "",
    }
    result = seal_mapping(result, "result_sha256")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("status", "total", "passed", "failed", "rows_sha256", "result_sha256")}, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
