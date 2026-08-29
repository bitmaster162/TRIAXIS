import unittest

from research.trading_shadow_p0.triaxis_trade_audit_p0 import (
    TradingShadowAuditError,
    build_trade_adjudication,
    sha256_obj,
    validate_trade_audit_request,
)


def request_fixture():
    body = {
        "schema": "triaxis.trade_audit_request.v1",
        "case_id": "trade-001",
        "case_sha256": "a" * 64,
        "thesis_sha256": "b" * 64,
        "candidate_action": "LONG",
        "evidence_refs": (
            {"source_id": "snapshot:001", "sha256": "c" * 64, "schema": "tradingos.market_snapshot.v1"},
            {"source_id": "vision:001", "sha256": "d" * 64, "schema": "tradingos.visual_market_evidence.v1"},
        ),
        "protocol": {
            "angel": "compatibility label",
            "devil": "compatibility label",
            "trialectic": "survivor synthesis",
            "evidence_audit": "bind claims",
        },
        "required_output": {
            "schema": "triaxis.trade_adjudication.v1",
            "verdict": ("HOLD", "PASS", "REJECT", "REVISE"),
            "fields": ("strongest_case", "falsifiers", "surviving_claims", "evidence_refs"),
        },
        "constraints": {
            "independent_audit": True,
            "no_execution": True,
            "no_order": True,
            "no_signal": True,
            "do_not_convert_prediction_to_permission": True,
        },
        "execution_authority": "NONE",
        "can_execute": False,
    }
    body["request_sha256"] = sha256_obj(body)
    return body


class TriaxisTradingShadowP0Tests(unittest.TestCase):
    def test_request_is_hash_bound_and_no_action(self):
        req = validate_trade_audit_request(request_fixture())
        self.assertEqual(req["execution_authority"], "NONE")
        self.assertFalse(req["can_execute"])

    def test_adjudication_uses_direct_falsification_and_countermodel_default_off(self):
        result = build_trade_adjudication(
            request_fixture(),
            verdict="HOLD",
            strongest_case=["trend supports long"],
            falsifiers=["liquidity rejection remains live"],
            surviving_claims=["trend survives, entry timing does not"],
            evidence_refs=["snapshot:001", "vision:001"],
            unsupported_claims=["exact fill probability"],
        )
        self.assertEqual(result["verdict"], "HOLD")
        self.assertEqual(result["mechanism"]["adversarial_stage"], "DIRECT_FALSIFICATION_FIRST")
        self.assertFalse(result["mechanism"]["countermodel_default"])
        self.assertFalse(result["mechanism"]["countermodel_triggered"])
        self.assertTrue(result["triaxis_is_contestant"])
        self.assertFalse(result["triaxis_is_oracle"])
        self.assertEqual(result["execution_authority"], "NONE")
        self.assertFalse(result["can_trade"])
        self.assertEqual(result["capital_permission"], "DENY")

    def test_countermodel_requires_explicit_trigger_reason(self):
        with self.assertRaisesRegex(TradingShadowAuditError, "countermodel_trigger_reason_required"):
            build_trade_adjudication(
                request_fixture(),
                verdict="REVISE",
                strongest_case=[],
                falsifiers=["uncertainty"],
                surviving_claims=[],
                evidence_refs=["snapshot:001"],
                countermodel_triggered=True,
            )

    def test_countermodel_can_be_explicitly_triggered_without_authority_gain(self):
        result = build_trade_adjudication(
            request_fixture(),
            verdict="REVISE",
            strongest_case=["support exists"],
            falsifiers=["direct evidence is ambiguous"],
            surviving_claims=[],
            evidence_refs=["snapshot:001"],
            countermodel_triggered=True,
            countermodel_trigger_reason="direct evidence leaves two live explanations",
        )
        self.assertTrue(result["mechanism"]["countermodel_triggered"])
        self.assertEqual(result["execution_authority"], "NONE")
        self.assertFalse(result["can_execute"])

    def test_tampered_request_fails_closed(self):
        req = request_fixture()
        req["candidate_action"] = "SHORT"
        with self.assertRaisesRegex(TradingShadowAuditError, "request_hash_mismatch"):
            validate_trade_audit_request(req)

    def test_widened_constraint_fails_closed(self):
        req = request_fixture()
        req["constraints"]["no_order"] = False
        req["request_sha256"] = sha256_obj({k: v for k, v in req.items() if k != "request_sha256"})
        with self.assertRaisesRegex(TradingShadowAuditError, "unsafe_constraint:no_order"):
            validate_trade_audit_request(req)


if __name__ == "__main__":
    unittest.main()
