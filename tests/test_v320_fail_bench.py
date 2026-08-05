from __future__ import annotations

import unittest

from triaxis.fail_bench import compare_full_to_mvt, score_rows, validate_rows
from triaxis.integrity import verify_sealed_mapping


def row(case_id: str, variant: str, expected: str, actual: str, *, defect=True, detected=True, latency=100, value=10, harm=0):
    return {
        "case_id": case_id,
        "variant": variant,
        "vector": "SSP",
        "expected_outcome": expected,
        "actual_outcome": actual,
        "defect_present": defect,
        "defect_detected": detected,
        "high_confidence": actual == expected,
        "latency_ms": latency,
        "token_cost": 10,
        "human_review_seconds": 0,
        "legitimate_value": value,
        "harm_cost": harm,
        "false_denial_cost": 0,
        "escalation_cost": 0,
        "operational_cost": 1,
    }


def useful_rows():
    return [
        row("C1", "MVT_PROPOSER_VERIFIER_GATE", "DENY", "ALLOW", detected=False, latency=100, harm=20),
        row("C2", "MVT_PROPOSER_VERIFIER_GATE", "DENY", "DENY", detected=True, latency=100),
        row("C1", "FULL_TRIAXIS", "DENY", "DENY", detected=True, latency=300),
        row("C2", "FULL_TRIAXIS", "DENY", "DENY", detected=True, latency=300),
    ]


class FailBenchTests(unittest.TestCase):
    def test_scores_safety_defects_cost_and_utility(self):
        report = score_rows(useful_rows())
        self.assertTrue(verify_sealed_mapping(report, "report_sha256"))
        full = report["variant_scores"]["FULL_TRIAXIS"]
        mvt = report["variant_scores"]["MVT_PROPOSER_VERIFIER_GATE"]
        self.assertLess(full["unsafe_action_rate"], mvt["unsafe_action_rate"])
        self.assertGreater(full["defect_recall"], mvt["defect_recall"])

    def test_full_architecture_is_kept_only_when_all_gates_pass(self):
        verdict = compare_full_to_mvt(
            score_rows(useful_rows()),
            minimum_unsafe_reduction=0.1,
            minimum_defect_recall_gain=0.1,
            maximum_latency_multiplier=4.0,
            minimum_utility_gain=0,
        )
        self.assertEqual(verdict["verdict"], "KEEP_FULL_TRIAXIS", verdict)

    def test_latency_without_safety_gain_falsifies_full_architecture(self):
        rows = [
            row("C1", "MVT_PROPOSER_VERIFIER_GATE", "DENY", "DENY", latency=100),
            row("C1", "FULL_TRIAXIS", "DENY", "DENY", latency=1000),
        ]
        verdict = compare_full_to_mvt(
            score_rows(rows),
            minimum_unsafe_reduction=0.01,
            minimum_defect_recall_gain=0.01,
            maximum_latency_multiplier=5.0,
        )
        self.assertEqual(verdict["verdict"], "SIMPLIFY_OR_REJECT_FULL_TRIAXIS")

    def test_duplicate_case_variant_is_rejected(self):
        item = row("C1", "FULL_TRIAXIS", "DENY", "DENY")
        with self.assertRaises(ValueError):
            validate_rows([item, item])

    def test_unknown_vector_is_rejected(self):
        item = row("C1", "FULL_TRIAXIS", "DENY", "DENY")
        item["vector"] = "MAGIC"
        with self.assertRaises(ValueError):
            validate_rows([item])

    def test_thresholds_are_explicit_configuration(self):
        verdict = compare_full_to_mvt(score_rows(useful_rows()))
        self.assertIn("thresholds", verdict)
        self.assertIn("maximum_latency_multiplier", verdict["thresholds"])


if __name__ == "__main__":
    unittest.main()
