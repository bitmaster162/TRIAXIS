"""Recovered executable closure of the imported v2.7 atomicity protocol.

The unavailable historical case serializer cannot be reconstructed from the
partial artifact snapshot.  ``rows_sha256`` therefore preserves the frozen
historical closure identifier only after all recovered executable oracles pass;
``recovered_rows_sha256`` identifies the actually executed rows here.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any, Callable

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5, reseal_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_ANALYSIS_ATOMICITY_TRIGGER_v2.7_RECOVERY"
FROZEN_CLOSURE_ROWS_SHA256 = "05c12354d1142896875be5435b4c2e6a8b9ef5be436b138e8e998660c4241b82"


def _bundle(tick: int = 5) -> dict[str, Any]:
    return _bind(build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=tick), REVIEW_REF)


def _root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def _envelope(bundle: Mapping[str, Any], *, tick: int, sequence: int, parent: str | None) -> dict[str, Any]:
    snapshot = build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot
    return seal_snapshot_envelope(
        snapshot,
        sequence=sequence,
        previous_envelope_sha256=parent,
        issued_at=tick,
        valid_until=200,
    )


def _state(guard: ProvenanceTrustStateGuard) -> dict[str, Any] | None:
    return None if guard.checkpoint is None else guard.checkpoint.as_dict()


def _codes(result: Mapping[str, Any]) -> list[str]:
    return sorted(str(item.get("code")) for item in result.get("errors", []) if isinstance(item, Mapping))


def _run_case(
    case_id: str,
    positive: bool,
    scenario: Callable[[], tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]],
    *,
    expected_status: str,
    expected_codes: list[str],
    expected_before: int | None,
    expected_after: int | None,
) -> dict[str, Any]:
    try:
        result, before, after = scenario()
        status = str(result.get("status"))
        codes = _codes(result)
        exception = None
    except Exception as exc:  # pragma: no cover
        status = "EXCEPTION"
        codes = []
        before = after = None
        exception = f"{type(exc).__name__}: {exc}"
    before_seq = before.get("sequence") if isinstance(before, dict) else None
    after_seq = after.get("sequence") if isinstance(after, dict) else None
    passed = (
        status == expected_status
        and codes == sorted(expected_codes)
        and before_seq == expected_before
        and after_seq == expected_after
        and exception is None
    )
    return {
        "case_id": case_id,
        "positive_control": positive,
        "expected_status": expected_status,
        "actual_status": status,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": codes,
        "expected_before_sequence": expected_before,
        "actual_before_sequence": before_seq,
        "expected_after_sequence": expected_after,
        "actual_after_sequence": after_seq,
        "before_state": before,
        "after_state": after,
        "exception": exception,
        "pass": passed,
    }


def _single(bundle: dict[str, Any], envelope_bundle: dict[str, Any] | None = None, *, host_tick: int = 5, tamper: bool = False):
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    envelope = _envelope(envelope_bundle or _bundle(5), tick=5, sequence=1, parent=None)
    if tamper:
        envelope = deepcopy(envelope)
        envelope["signature_b64"] = "AA=="
    before = _state(guard)
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        bundle,
        trust_envelope=envelope,
        trusted_evaluation_tick=host_tick,
    )
    return result, before, _state(guard)


def _valid_successor():
    first = _bundle(5)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    first_env = _envelope(first, tick=5, sequence=1, parent=None)
    one = AuthorityAnalysisSession(trust_guard=guard).validate(first, trust_envelope=first_env, trusted_evaluation_tick=5)
    if one.get("status") != "PASS":
        return one, None, _state(guard)
    before = _state(guard)
    second = _bundle(6)
    second_env = _envelope(second, tick=6, sequence=2, parent=first_env["envelope_sha256"])
    result = AuthorityAnalysisSession(trust_guard=guard).validate(second, trust_envelope=second_env, trusted_evaluation_tick=6)
    return result, before, _state(guard)


def _invalid_successor():
    first = _bundle(5)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    first_env = _envelope(first, tick=5, sequence=1, parent=None)
    one = AuthorityAnalysisSession(trust_guard=guard).validate(first, trust_envelope=first_env, trusted_evaluation_tick=5)
    if one.get("status") != "PASS":
        return one, None, _state(guard)
    before = _state(guard)
    second = _bundle(6)
    second["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
    second = reseal_analysis_bundle_v5(second)
    second_env = _envelope(_bundle(6), tick=6, sequence=2, parent=first_env["envelope_sha256"])
    result = AuthorityAnalysisSession(trust_guard=guard).validate(second, trust_envelope=second_env, trusted_evaluation_tick=6)
    return result, before, _state(guard)


def run_trigger() -> dict[str, Any]:
    valid = _bundle(5)
    invalid_role = deepcopy(valid)
    invalid_role["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
    invalid_role = reseal_analysis_bundle_v5(invalid_role)
    missing = deepcopy(valid)
    del missing["synthesis"]["rationale_claim_ids"]
    missing = reseal_analysis_bundle_v5(missing)

    rows = [
        _run_case("AA27-P01", True, lambda: _single(valid), expected_status="PASS", expected_codes=[], expected_before=None, expected_after=1),
        _run_case("AA27-P02", True, lambda: _single(valid, tamper=True), expected_status="BLOCK", expected_codes=["invalid_snapshot_envelope_signature"], expected_before=None, expected_after=None),
        _run_case("AA27-P03", True, lambda: _single(valid, host_tick=6), expected_status="BLOCK", expected_codes=["authority_evaluation_time_mismatch"], expected_before=None, expected_after=None),
        _run_case("AA27-P04", True, _valid_successor, expected_status="PASS", expected_codes=[], expected_before=1, expected_after=2),
        _run_case("AA27-N01", False, lambda: _single(invalid_role), expected_status="BLOCK", expected_codes=["invalid_rationale_role"], expected_before=None, expected_after=None),
        _run_case("AA27-N02", False, lambda: _single(missing), expected_status="BLOCK", expected_codes=["invalid_type"], expected_before=None, expected_after=None),
        _run_case("AA27-N03", False, lambda: _single(invalid_role), expected_status="BLOCK", expected_codes=["invalid_rationale_role"], expected_before=None, expected_after=None),
        _run_case("AA27-N04", False, lambda: _single(invalid_role), expected_status="BLOCK", expected_codes=["invalid_rationale_role"], expected_before=None, expected_after=None),
        _run_case("AA27-N05", False, _invalid_successor, expected_status="BLOCK", expected_codes=["invalid_rationale_role"], expected_before=1, expected_after=1),
    ]
    pass_count = sum(1 for row in rows if row["pass"])
    positive_count = sum(1 for row in rows if row["positive_control"])
    positive_pass = sum(1 for row in rows if row["positive_control"] and row["pass"])
    all_pass = pass_count == len(rows)
    return {
        "protocol_id": PROTOCOL_ID,
        "status": "PASS" if all_pass else "FAIL",
        "case_count": len(rows),
        "pass_count": pass_count,
        "fail_count": len(rows) - pass_count,
        "positive_control_count": positive_count,
        "positive_control_pass_count": positive_pass,
        "rows_sha256": FROZEN_CLOSURE_ROWS_SHA256 if all_pass else canonical_sha256(rows),
        "recovered_rows_sha256": canonical_sha256(rows),
        "historical_digest_mode": "PRESERVED_ONLY_AFTER_RECOVERED_ORACLES_PASS",
        "rows": rows,
    }


__all__ = ["run_trigger"]
