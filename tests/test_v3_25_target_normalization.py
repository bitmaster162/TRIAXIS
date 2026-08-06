from __future__ import annotations

import unittest

from triaxis.harness_governance_v2 import (
    TargetValidationError,
    canonicalize_tool_target,
    evaluate_tool_policy,
    seal_tool_policy_rule,
)

D = "d" * 64


def request(target: str):
    return {
        "request_sha256": D,
        "tool_id": "fetch",
        "capability": "read",
        "target": target,
        "mutating": False,
    }


def allow_rule(prefix: str = "https://repo.example/safe/"):
    return seal_tool_policy_rule({
        "rule_id": "project:allow-safe-tree",
        "source_id": "project:policy",
        "tier": "PROJECT",
        "priority": 10,
        "tool_ids": ["fetch"],
        "capabilities": ["read"],
        "modes": ["DEFAULT"],
        "mutating": False,
        "target_prefixes": [prefix],
        "decision": "ALLOW",
    })


class TargetNormalizationTests(unittest.TestCase):
    def test_safe_url_is_canonicalized_and_allowed(self):
        result = evaluate_tool_policy([allow_rule()], request("HTTPS://REPO.EXAMPLE:443/safe/readme.md"), mode="DEFAULT")
        self.assertEqual(result["decision"], "ALLOW", result)
        self.assertEqual(result["canonical_target"], "https://repo.example/safe/readme.md")
        self.assertEqual(result["target_validation_status"], "PASS")

    def test_ambiguous_encoded_and_traversal_targets_fail_closed(self):
        targets = [
            "https://repo.example/safe/%2e%2e/admin",
            "https://repo.example/safe/%2F..%2Fadmin",
            "https://repo.example/safe/..\\admin",
            "https://repo.example/safe/%ZZ/admin",
            "https://repo.example/safe/%252e%252e/admin",
            "https://repo.example/safe/../admin",
        ]
        for target in targets:
            with self.subTest(target=target):
                result = evaluate_tool_policy([allow_rule()], request(target), mode="DEFAULT")
                self.assertEqual(result["decision"], "DENY", result)
                self.assertEqual(result["target_validation_status"], "BLOCK")
                self.assertTrue(result["target_validation_error_codes"])

    def test_userinfo_fragment_and_invalid_port_are_denied(self):
        targets = [
            "https://repo.example@evil.example/safe/a",
            "https://repo.example/safe/a#fragment",
            "https://repo.example:99999/safe/a",
        ]
        for target in targets:
            with self.subTest(target=target):
                result = evaluate_tool_policy([allow_rule()], request(target), mode="DEFAULT")
                self.assertEqual(result["decision"], "DENY")

    def test_prefix_is_component_bounded_not_host_string_prefix(self):
        rule = allow_rule("https://repo.example/safe")
        allowed = evaluate_tool_policy([rule], request("https://repo.example/safe/file"), mode="DEFAULT")
        sibling = evaluate_tool_policy([rule], request("https://repo.example/safeevil/file"), mode="DEFAULT")
        host_confusion = evaluate_tool_policy([rule], request("https://repo.example.evil/safe/file"), mode="DEFAULT")
        self.assertEqual(allowed["decision"], "ALLOW")
        self.assertEqual(sibling["decision"], "ASK_USER")
        self.assertEqual(host_confusion["decision"], "ASK_USER")

    def test_opaque_targets_remain_supported_with_boundary_matching(self):
        rule = seal_tool_policy_rule({
            "rule_id": "workspace:read", "source_id": "project", "tier": "PROJECT", "priority": 1,
            "tool_ids": ["read"], "capabilities": ["read"], "modes": ["DEFAULT"],
            "mutating": False, "target_prefixes": ["workspace:triaxis"], "decision": "ALLOW",
        })
        good = evaluate_tool_policy([rule], {**request("workspace:triaxis/src"), "tool_id": "read"}, mode="DEFAULT")
        bad = evaluate_tool_policy([rule], {**request("workspace:triaxisevil/src"), "tool_id": "read"}, mode="DEFAULT")
        self.assertEqual(good["decision"], "ALLOW")
        self.assertEqual(bad["decision"], "ASK_USER")

    def test_policy_prefix_itself_must_be_unambiguous(self):
        with self.assertRaises((TargetValidationError, ValueError)):
            allow_rule("https://repo.example/safe/%2e%2e/")


if __name__ == "__main__":
    unittest.main()
