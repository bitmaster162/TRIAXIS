from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

REQUEST_SCHEMA = "triaxis.trade_audit_request.v1"
ADJUDICATION_SCHEMA = "triaxis.trade_adjudication.v1"
ALLOWED_VERDICTS = {"PASS", "HOLD", "REJECT", "REVISE"}
COUNTERMODEL_DEFAULT = False


class TradingShadowAuditError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_obj(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TradingShadowAuditError(f"{field}_required")
    return value.strip()


def validate_trade_audit_request(request: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(request, Mapping) or request.get("schema") != REQUEST_SCHEMA:
        raise TradingShadowAuditError("wrong_trade_audit_request_schema")
    _text(request.get("case_id"), "case_id")
    _text(request.get("case_sha256"), "case_sha256")
    _text(request.get("thesis_sha256"), "thesis_sha256")
    _text(request.get("candidate_action"), "candidate_action")

    refs = request.get("evidence_refs")
    if not isinstance(refs, (list, tuple)) or not refs:
        raise TradingShadowAuditError("evidence_refs_required")
    for index, ref in enumerate(refs):
        if not isinstance(ref, Mapping):
            raise TradingShadowAuditError(f"evidence_ref_{index}_must_be_object")
        _text(ref.get("source_id"), f"evidence_ref_{index}.source_id")
        sha = _text(ref.get("sha256"), f"evidence_ref_{index}.sha256").lower()
        if len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
            raise TradingShadowAuditError(f"evidence_ref_{index}.sha256_invalid")
        _text(ref.get("schema"), f"evidence_ref_{index}.schema")

    constraints = request.get("constraints")
    required_constraints = {
        "independent_audit": True,
        "no_execution": True,
        "no_order": True,
        "no_signal": True,
        "do_not_convert_prediction_to_permission": True,
    }
    if not isinstance(constraints, Mapping):
        raise TradingShadowAuditError("constraints_required")
    for key, expected in required_constraints.items():
        if constraints.get(key) is not expected:
            raise TradingShadowAuditError(f"unsafe_constraint:{key}")

    if request.get("execution_authority") != "NONE" or request.get("can_execute") is not False:
        raise TradingShadowAuditError("unsafe_request_authority")

    expected_hash = sha256_obj({k: v for k, v in request.items() if k != "request_sha256"})
    if request.get("request_sha256") != expected_hash:
        raise TradingShadowAuditError("request_hash_mismatch")
    return dict(request)


def build_trade_adjudication(
    request: Mapping[str, Any],
    *,
    verdict: str,
    strongest_case: Sequence[str],
    falsifiers: Sequence[str],
    surviving_claims: Sequence[str],
    evidence_refs: Sequence[str],
    unsupported_claims: Sequence[str] = (),
    countermodel_triggered: bool = COUNTERMODEL_DEFAULT,
    countermodel_trigger_reason: str | None = None,
) -> dict[str, Any]:
    """Build a no-action adjudication from supplied audit work.

    This function does not call a model or tool and does not pretend to run independent agents.
    The old ANGEL/DEVIL labels are treated as a compatibility vocabulary only. The operational
    mechanism is evidence-first falsification. The countermodel/DEVIL research feature remains
    default-off; using it requires an explicit trigger reason in the input receipt.
    """
    req = validate_trade_audit_request(request)
    verdict_clean = _text(verdict, "verdict").upper()
    if verdict_clean not in ALLOWED_VERDICTS:
        raise TradingShadowAuditError("unsupported_verdict")
    if not isinstance(countermodel_triggered, bool):
        raise TradingShadowAuditError("countermodel_triggered_must_be_boolean")
    if countermodel_triggered and not isinstance(countermodel_trigger_reason, str):
        raise TradingShadowAuditError("countermodel_trigger_reason_required")
    if countermodel_triggered and not countermodel_trigger_reason.strip():
        raise TradingShadowAuditError("countermodel_trigger_reason_required")

    def clean_rows(rows: Sequence[str], field: str) -> tuple[str, ...]:
        if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
            raise TradingShadowAuditError(f"{field}_must_be_sequence")
        return tuple(str(row).strip() for row in rows if str(row).strip())

    body = {
        "schema": ADJUDICATION_SCHEMA,
        "case_id": req["case_id"],
        "request_sha256": req["request_sha256"],
        "verdict": verdict_clean,
        "strongest_case": clean_rows(strongest_case, "strongest_case"),
        "falsifiers": clean_rows(falsifiers, "falsifiers"),
        "surviving_claims": clean_rows(surviving_claims, "surviving_claims"),
        "evidence_refs": clean_rows(evidence_refs, "evidence_refs"),
        "unsupported_claims": clean_rows(unsupported_claims, "unsupported_claims"),
        "mechanism": {
            "strongest_case": "EVIDENCE_BOUND_SUPPORT",
            "adversarial_stage": "DIRECT_FALSIFICATION_FIRST",
            "countermodel_default": False,
            "countermodel_triggered": countermodel_triggered,
            "countermodel_trigger_reason": countermodel_trigger_reason.strip() if countermodel_triggered else None,
            "trialectic_closure": "SURVIVORS_ONLY_WITH_UNCERTAINTY",
            "evidence_audit": "UNSUPPORTED_MATERIAL_CLAIMS_EXPLICIT",
        },
        "triaxis_is_contestant": True,
        "triaxis_is_oracle": False,
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
    }
    body["adjudication_sha256"] = sha256_obj(body)
    return body
