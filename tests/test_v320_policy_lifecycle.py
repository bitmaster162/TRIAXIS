from __future__ import annotations

import unittest

from triaxis.policy_lifecycle import (
    POLICY_BUNDLE_CONTRACT_ID,
    PolicyRegistry,
    PolicyRegistryError,
    evaluate_policy,
    seal_policy,
    validate_policy_bundle,
)


def policy(
    sequence: int = 1,
    *,
    state: str = "ACTIVE",
    supersedes: str | None = None,
    minimum: int = 1,
    effective_from: int | None = 1,
    valid_until: int | None = 20,
    required_approvals: list[str] | None = None,
):
    return seal_policy(
        {
            "contract_id": POLICY_BUNDLE_CONTRACT_ID,
            "policy_id": "policy:repo-write",
            "subject_id": "subject:1",
            "issuer_id": "policy-engine:1",
            "sequence": sequence,
            "minimum_accepted_sequence": minimum,
            "state": state,
            "effective_from": effective_from,
            "valid_until": valid_until,
            "allowed_capabilities": ["READ", "WRITE"],
            "allowed_tools": ["git"],
            "allowed_targets": ["repo:triaxis"],
            "max_risk_class": "R3",
            "required_approval_types": [] if required_approvals is None else required_approvals,
            "supersedes_policy_sha256": supersedes,
            "policy_sha256": "",
        }
    )


def request(**updates):
    value = {
        "policy_id": "policy:repo-write",
        "policy_sequence": 1,
        "subject_id": "subject:1",
        "capability": "WRITE",
        "tool_id": "git",
        "execution_target": "repo:triaxis",
        "risk_class": "R2",
        "approval_types": [],
    }
    value.update(updates)
    return value


class PolicyLifecycleTests(unittest.TestCase):
    def test_valid_policy_and_request_allow(self):
        p = policy()
        self.assertEqual(validate_policy_bundle(p)["status"], "PASS")
        decision = evaluate_policy(p, request(), 5)
        self.assertEqual(decision["outcome"], "ALLOW", decision)

    def test_capability_tool_target_and_risk_are_enforced(self):
        cases = [
            request(capability="DELETE"),
            request(tool_id="shell"),
            request(execution_target="repo:other"),
            request(risk_class="R4"),
        ]
        for item in cases:
            with self.subTest(item=item):
                self.assertEqual(evaluate_policy(policy(), item, 5)["outcome"], "DENY")

    def test_required_approval_type_is_enforced(self):
        p = policy(required_approvals=["HUMAN"])
        self.assertEqual(evaluate_policy(p, request(), 5)["outcome"], "DENY")
        self.assertEqual(evaluate_policy(p, request(approval_types=["HUMAN"]), 5)["outcome"], "ALLOW")

    def test_expired_and_shadow_policy_deny(self):
        self.assertEqual(evaluate_policy(policy(valid_until=5), request(), 5)["outcome"], "DENY")
        self.assertEqual(evaluate_policy(policy(state="SHADOW"), request(), 5)["outcome"], "DENY")

    def test_registry_requires_monotonic_sequence_and_exact_lineage(self):
        registry = PolicyRegistry()
        p1 = registry.register(policy())
        p2 = policy(sequence=2, supersedes=p1["policy_sha256"], minimum=1)
        registry.register(p2)
        self.assertEqual(registry.head("policy:repo-write")["sequence"], 2)
        with self.assertRaisesRegex(PolicyRegistryError, "sequence"):
            registry.register(policy(sequence=2, supersedes=p2["policy_sha256"]))
        bad = policy(sequence=3, supersedes="f" * 64)
        with self.assertRaises(PolicyRegistryError) as ctx:
            registry.register(bad)
        self.assertEqual(ctx.exception.code, "policy_lineage_break")

    def test_registry_rejects_minimum_sequence_rollback(self):
        registry = PolicyRegistry()
        p1 = registry.register(policy(minimum=1))
        p2 = registry.register(policy(sequence=2, minimum=2, supersedes=p1["policy_sha256"]))
        with self.assertRaises(PolicyRegistryError) as ctx:
            registry.register(policy(sequence=3, minimum=1, supersedes=p2["policy_sha256"]))
        self.assertEqual(ctx.exception.code, "minimum_sequence_rollback")

    def test_registry_selects_only_current_active_policy(self):
        registry = PolicyRegistry()
        p1 = registry.register(policy())
        selected = registry.select_active("policy:repo-write", 5)
        self.assertEqual(selected["policy_sha256"], p1["policy_sha256"])
        registry.register(policy(sequence=2, state="REVOKED", supersedes=p1["policy_sha256"]))
        with self.assertRaises(PolicyRegistryError) as ctx:
            registry.select_active("policy:repo-write", 5)
        self.assertEqual(ctx.exception.code, "policy_not_active")

    def test_deterministic_replay_is_byte_identical(self):
        first = evaluate_policy(policy(), request(), 5)
        second = evaluate_policy(policy(), request(), 5)
        self.assertEqual(first, second)
        self.assertEqual(first["decision_sha256"], second["decision_sha256"])

    def test_tampered_policy_digest_blocks(self):
        p = policy()
        p["max_risk_class"] = "R4"
        self.assertEqual(validate_policy_bundle(p)["status"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
