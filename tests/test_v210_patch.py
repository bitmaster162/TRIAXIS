from __future__ import annotations

from copy import deepcopy
from itertools import permutations
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from triaxis.projection import evaluate_candidate, evaluate_ingress  # noqa: E402
from triaxis.semantic_ingress import (  # noqa: E402
    SEMANTIC_INGRESS_RULESET_V1,
    SEMANTIC_INGRESS_RULESET_V2,
    scan_control_surface,
)
from validation.composition_state.case_bank import templates as composition_templates  # noqa: E402
from validation.routing_semantics.template_bank import templates as routing_templates  # noqa: E402
from validation.semantic_ingress.case_bank import templates as semantic_templates  # noqa: E402


class V210PatchTests(unittest.TestCase):
    def test_trigger_failures_remain_reproducible_in_v29(self) -> None:
        by_name = {row["template_name"]: row for row in composition_templates()}
        for name in {
            "graph_reverse_order_allow",
            "quoted_delete_is_data",
            "message_as_noun",
            "open_position_is_trade",
        }:
            with self.subTest(template=name):
                decision = evaluate_ingress("2.9-RC1", by_name[name]["record"])
                self.assertNotEqual(
                    (decision["status"], decision["primary_reason"]),
                    (by_name[name]["expected_status"], by_name[name]["expected_reason"]),
                )

    def test_composition_state_full_bank_is_closed(self) -> None:
        for row in composition_templates():
            with self.subTest(template=row["template_name"]):
                decision = evaluate_ingress("2.10-RC1", row["record"])
                self.assertEqual(decision["status"], row["expected_status"])
                self.assertEqual(decision["primary_reason"], row["expected_reason"])

    def test_task_graph_is_invariant_to_all_three_node_permutations(self) -> None:
        row = next(r for r in composition_templates() if r["template_name"] == "graph_reverse_transitive_allow")
        record = row["record"]
        outcomes = set()
        node_orders = []
        for order in permutations(record["nodes"]):
            candidate = deepcopy(record)
            candidate["nodes"] = list(order)
            decision = evaluate_ingress("2.10-RC1", candidate)
            outcomes.add((decision["status"], decision["primary_reason"]))
            node_orders.append(tuple(item["node_id"] for item in decision["node_decisions"]))
        self.assertEqual(outcomes, {("ALLOW", "CONDITIONS_SATISFIED")})
        self.assertEqual(set(node_orders), {("N1", "N2", "N3")})

    def test_role_aware_scanner_excludes_quoted_and_external_data(self) -> None:
        row = next(r for r in composition_templates() if r["template_name"] == "quoted_delete_is_data")
        record = row["record"]
        old = scan_control_surface(record["source_text"], record["spans"], ruleset=SEMANTIC_INGRESS_RULESET_V1)
        new = scan_control_surface(record["source_text"], record["spans"], ruleset=SEMANTIC_INGRESS_RULESET_V2)
        self.assertIn("DELETE", old["actions"])
        self.assertEqual(new["actions"], ["ANALYZE"])

    def test_v210_preserves_v29_routing_and_semantic_positive_scope(self) -> None:
        for row in routing_templates():
            with self.subTest(bank="routing", template=row["template_name"]):
                decision = evaluate_candidate("2.10-RC1", row["scenario"])
                self.assertEqual((decision["status"], decision["primary_reason"]), (row["expected_status"], row["expected_reason"]))
        for row in semantic_templates():
            with self.subTest(bank="semantic", template=row["template_name"]):
                decision = evaluate_ingress("2.10-RC1", row["record"])
                self.assertEqual((decision["status"], decision["primary_reason"]), (row["expected_status"], row["expected_reason"]))


if __name__ == "__main__":
    unittest.main()
