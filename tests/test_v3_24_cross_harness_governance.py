from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from triaxis.harness_governance_v2 import (
    InterruptStoreError,
    PermissionDeltaLedger,
    SQLiteInterruptStore,
    evaluate_guardrail_pipeline,
    evaluate_tool_policy,
    make_filtered_handoff_context,
    seal_action_observation_event,
    seal_guardrail_result,
    seal_one_shot_permission_delta,
    seal_tool_policy_rule,
    seal_trace_span,
    split_shell_segments,
    validate_action_observation_stream,
    validate_trace_chain,
)
from triaxis.integrity import verify_sealed_mapping

D = "d" * 64
E = "e" * 64
F = "f" * 64


def request(*, tool_id="shell", capability="execute", target="workspace:triaxis", mutating=True, digest=D):
    return {
        "request_sha256": digest,
        "tool_id": tool_id,
        "capability": capability,
        "target": target,
        "mutating": mutating,
    }


class PolicyEngineTests(unittest.TestCase):
    def test_admin_deny_overrides_user_allow_and_hides_global_tool(self):
        user = seal_tool_policy_rule({
            "rule_id": "user:allow-shell",
            "source_id": "user:settings",
            "tier": "USER",
            "priority": 100,
            "tool_ids": ["shell"],
            "capabilities": [],
            "modes": ["DEFAULT"],
            "mutating": None,
            "target_prefixes": [],
            "decision": "ALLOW",
        })
        admin = seal_tool_policy_rule({
            "rule_id": "admin:deny-shell",
            "source_id": "admin:managed",
            "tier": "ADMIN",
            "priority": 1,
            "tool_ids": ["shell"],
            "capabilities": [],
            "modes": ["DEFAULT"],
            "mutating": None,
            "target_prefixes": [],
            "decision": "DENY",
        })
        result = evaluate_tool_policy([user, admin], request(), mode="DEFAULT")
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["selected_rule_id"], "admin:deny-shell")
        self.assertEqual(result["model_visibility"], "HIDDEN")

    def test_extension_cannot_grant_allow_and_headless_ask_fails_closed(self):
        with self.assertRaises(ValueError):
            seal_tool_policy_rule({
                "rule_id": "extension:bad",
                "source_id": "plugin:x",
                "tier": "EXTENSION",
                "priority": 10,
                "decision": "ALLOW",
            })
        ask = seal_tool_policy_rule({
            "rule_id": "project:ask",
            "source_id": "project:policy",
            "tier": "PROJECT",
            "priority": 10,
            "tool_ids": ["shell"],
            "capabilities": ["execute"],
            "modes": ["HEADLESS"],
            "mutating": True,
            "target_prefixes": ["workspace:"],
            "decision": "ASK_USER",
        })
        result = evaluate_tool_policy([ask], request(), mode="HEADLESS")
        self.assertEqual(result["decision"], "DENY")

    def test_policy_matching_is_scoped(self):
        deny_delete = seal_tool_policy_rule({
            "rule_id": "deny:delete",
            "source_id": "admin",
            "tier": "ADMIN",
            "priority": 10,
            "tool_ids": ["delete"],
            "capabilities": ["write"],
            "modes": ["DEFAULT"],
            "mutating": True,
            "target_prefixes": ["prod:"],
            "decision": "DENY",
        })
        allowed = evaluate_tool_policy([deny_delete], request(tool_id="read", capability="read", mutating=False), mode="DEFAULT")
        self.assertEqual(allowed["decision"], "ASK_USER")


class EscalationTests(unittest.TestCase):
    def test_shell_segments_are_evaluated_independently(self):
        self.assertEqual(split_shell_segments("git pull | tee output.txt && cargo test"), [["git", "pull"], ["tee", "output.txt"], ["cargo", "test"]])
        for bad in ("cat $(whoami)", "echo hi > /tmp/x", "rm *.txt", "FOO=bar cmd"):
            with self.assertRaises(ValueError):
                split_shell_segments(bad)

    def test_permission_delta_is_single_use_and_exact_bound(self):
        delta = seal_one_shot_permission_delta({
            "grant_id": "grant:1",
            "request_sha256": D,
            "approval_sha256": E,
            "nonce": "nonce:1",
            "scope": "ONCE",
            "additional_read_paths": ["cache"],
            "additional_write_paths": [],
            "network_destinations": ["pypi.org:443"],
            "issued_at_tick": 5,
            "expires_at_tick": 10,
        })
        ledger = PermissionDeltaLedger()
        try:
            first = ledger.consume(delta, request_sha256=D, approval_sha256=E, evaluation_tick=6)
            second = ledger.consume(delta, request_sha256=D, approval_sha256=E, evaluation_tick=7)
            wrong = ledger.consume(delta, request_sha256=F, approval_sha256=E, evaluation_tick=6)
            self.assertEqual(first["status"], "PASS")
            self.assertEqual(second["status"], "BLOCK")
            self.assertIn("permission_delta_replay", {x["code"] for x in second["errors"]})
            self.assertEqual(wrong["status"], "BLOCK")
        finally:
            ledger.close()


class GuardrailTests(unittest.TestCase):
    def row(self, phase, outcome="PASS", tick=5, replacement=None):
        return seal_guardrail_result({
            "phase": phase,
            "guardrail_id": f"guard:{phase.lower()}",
            "request_sha256": D,
            "outcome": outcome,
            "observed_at_tick": tick,
            "replacement_output_sha256": replacement,
        })

    def test_mutating_tool_is_checked_before_and_after_approval_and_after_output(self):
        result = evaluate_guardrail_pipeline(
            request_sha256=D,
            mutating=True,
            approval_sha256=E,
            pre_approval_results=[self.row("PRE_APPROVAL", tick=5)],
            pre_execution_results=[self.row("PRE_EXECUTION", tick=6)],
            post_execution_results=[self.row("POST_EXECUTION", tick=7)],
            execution_output_sha256=F,
            evaluation_tick=7,
        )
        self.assertEqual(result["status"], "PASS", result["errors"])
        self.assertEqual(result["effective_output_sha256"], F)

    def test_missing_recheck_and_tripwire_block(self):
        result = evaluate_guardrail_pipeline(
            request_sha256=D,
            mutating=True,
            approval_sha256=E,
            pre_approval_results=[self.row("PRE_APPROVAL", outcome="TRIPWIRE")],
            pre_execution_results=[],
            post_execution_results=[],
            execution_output_sha256=None,
            evaluation_tick=6,
        )
        codes = {x["code"] for x in result["errors"]}
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("guardrail_tripwire", codes)
        self.assertIn("pre_execution_recheck_required", codes)

    def test_post_guardrail_can_rewrite_output(self):
        result = evaluate_guardrail_pipeline(
            request_sha256=D,
            mutating=False,
            approval_sha256=None,
            pre_approval_results=[],
            pre_execution_results=[],
            post_execution_results=[self.row("POST_EXECUTION", outcome="REWRITE", tick=7, replacement=E)],
            execution_output_sha256=F,
            evaluation_tick=7,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["effective_output_sha256"], E)


class HandoffAndDurabilityTests(unittest.TestCase):
    def test_handoff_filters_context_and_never_inherits_authority_implicitly(self):
        handoff = make_filtered_handoff_context(
            source_session_id="session:1",
            destination_agent_id="agent:reviewer",
            source_context_manifest_sha256=D,
            allowed_artifact_ids=["file:a", "file:b", "file:a"],
            summary_sha256=E,
            include_tool_history=False,
            authority_checkpoint_sha256=F,
        )
        self.assertTrue(verify_sealed_mapping(handoff, "handoff_sha256"))
        self.assertEqual(handoff["allowed_artifact_ids"], ["file:a", "file:b"])
        self.assertFalse(handoff["implicit_context_inheritance"])
        self.assertFalse(handoff["implicit_authority_inheritance"])

    def test_interrupt_resume_is_durable_single_use_and_cas_guarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "interrupts.sqlite")
            store = SQLiteInterruptStore(path)
            created = store.create_interrupt(
                checkpoint_id="cp:1",
                thread_id="thread:1",
                run_id="run:1",
                parent_checkpoint_id=None,
                state={"step": 2},
                interrupt_payload={"question": "approve?"},
                created_at=5,
            )
            self.assertEqual(created["status"], "WAITING")
            resumed = store.resume("cp:1", expected_version=1, resume_value={"answer": "yes"}, resumed_at=6)
            self.assertEqual(resumed["status"], "RESUMED")
            with self.assertRaises(InterruptStoreError) as ctx:
                store.resume("cp:1", expected_version=1, resume_value={"answer": "yes"}, resumed_at=7)
            self.assertIn(ctx.exception.code, {"interrupt_cas_conflict", "checkpoint_not_waiting"})
            store.close()
            reopened = SQLiteInterruptStore(path)
            self.assertEqual(reopened.get("cp:1")["status"], "RESUMED")
            reopened.close()

    def test_time_travel_fork_preserves_parent_ancestry(self):
        store = SQLiteInterruptStore()
        try:
            store.create_interrupt(
                checkpoint_id="cp:root", thread_id="thread:root", run_id="run:root",
                parent_checkpoint_id=None, state={"x": 1}, interrupt_payload={"why": "branch"}, created_at=1,
            )
            fork = store.fork("cp:root", new_checkpoint_id="cp:fork", new_thread_id="thread:fork", new_run_id="run:fork", created_at=2)
            self.assertEqual(fork["parent_checkpoint_id"], "cp:root")
            self.assertEqual(fork["thread_id"], "thread:fork")
        finally:
            store.close()


class TraceAndEventTests(unittest.TestCase):
    def test_trace_chain_is_parented_redacted_and_hash_chained(self):
        root = seal_trace_span({
            "trace_id": "trace:1", "span_id": "span:run", "parent_span_id": None,
            "previous_span_sha256": None, "span_type": "RUN", "name": "run",
            "started_at_tick": 1, "ended_at_tick": 1, "status": "PASS",
            "attributes": {"session": "session:1"}, "redacted_fields": ["api_key"],
        })
        tool = seal_trace_span({
            "trace_id": "trace:1", "span_id": "span:tool", "parent_span_id": "span:run",
            "previous_span_sha256": root["span_sha256"], "span_type": "TOOL", "name": "read",
            "started_at_tick": 2, "ended_at_tick": 3, "status": "PASS",
            "attributes": {"request_sha256": D}, "redacted_fields": [],
        })
        self.assertEqual(validate_trace_chain([root, tool])["status"], "PASS")
        broken = deepcopy(tool)
        broken["previous_span_sha256"] = E
        broken = seal_trace_span({k: v for k, v in broken.items() if k not in {"contract_id", "span_sha256"}})
        self.assertEqual(validate_trace_chain([root, broken])["status"], "BLOCK")

    def test_action_observation_stream_requires_exact_correlation(self):
        action = seal_action_observation_event({
            "kind": "ACTION", "event_id": "event:a", "run_id": "run:1",
            "correlation_id": "corr:1", "action_event_id": None, "payload_sha256": D,
        })
        observation = seal_action_observation_event({
            "kind": "OBSERVATION", "event_id": "event:o", "run_id": "run:1",
            "correlation_id": "corr:1", "action_event_id": "event:a", "payload_sha256": E,
        })
        self.assertEqual(validate_action_observation_stream([action, observation])["status"], "PASS")
        orphan = seal_action_observation_event({
            "kind": "OBSERVATION", "event_id": "event:x", "run_id": "run:1",
            "correlation_id": "corr:1", "action_event_id": "missing", "payload_sha256": F,
        })
        self.assertEqual(validate_action_observation_stream([orphan])["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
