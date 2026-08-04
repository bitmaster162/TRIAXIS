"""Post-product materialization trigger for exact recovered TRIAXIS v2.36."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_SUBJECT_MATERIALIZATION_TRIGGER_v3.0_RECOVERY"
CANDIDATE_COMMIT = "10d0db544692431e2cfd152922eaac2f27c3f0f3"
CANDIDATE_TREE = "0ffafd760e8424c2f639961208f015ee23492d3f"


def _bundle() -> dict[str, Any]:
    return _bind(build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=6), REVIEW_REF)


def _root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def _state(guard: ProvenanceTrustStateGuard) -> dict[str, Any] | None:
    return None if guard.checkpoint is None else guard.checkpoint.as_dict()


def _envelope(source: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = build_trust_fixture_v2(source, evaluation_tick=6).snapshot
    return seal_snapshot_envelope(
        snapshot,
        sequence=1,
        previous_envelope_sha256=None,
        issued_at=6,
        valid_until=200,
    )


def _execute(value: Any, *, source: Mapping[str, Any] | None = None):
    base = _bundle() if source is None else source
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    envelope = _envelope(base)
    before = _state(guard)
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        value,
        trust_envelope=envelope,
        trusted_evaluation_tick=6,
    )
    return result, before, _state(guard)


def _codes(result: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(item.get("code"))
        for item in result.get("errors", [])
        if isinstance(item, Mapping)
    })


def _row(
    case_id: str,
    description: str,
    *,
    scenario: Callable[[], tuple[Any, Any, Any]],
    expected_status: str,
    expected_reason: str,
    expected_codes: list[str],
    expected_before_sequence: int | None,
    expected_after_sequence: int | None,
    expected_state_unchanged: bool,
    positive_control: bool,
) -> dict[str, Any]:
    try:
        result, before, after = scenario()
        actual_status = str(result.get("status"))
        actual_reason = str(result.get("primary_reason"))
        actual_codes = _codes(result)
        exception = None
    except Exception as exc:  # intended observation surface
        actual_status = "EXCEPTION"
        actual_reason = type(exc).__name__
        actual_codes = []
        before = None
        after = None
        exception = f"{type(exc).__name__}: {exc}"
    before_sequence = before.get("sequence") if isinstance(before, dict) else None
    after_sequence = after.get("sequence") if isinstance(after, dict) else None
    unchanged = before == after
    passed = (
        actual_status == expected_status
        and actual_reason == expected_reason
        and actual_codes == sorted(expected_codes)
        and before_sequence == expected_before_sequence
        and after_sequence == expected_after_sequence
        and unchanged is expected_state_unchanged
        and exception is None
    )
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "family": "authority_subject_materialization",
        "description": description,
        "positive_control": positive_control,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_primary_reason": expected_reason,
        "actual_primary_reason": actual_reason,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": actual_codes,
        "expected_before_sequence": expected_before_sequence,
        "actual_before_sequence": before_sequence,
        "expected_after_sequence": expected_after_sequence,
        "actual_after_sequence": after_sequence,
        "expected_state_unchanged": expected_state_unchanged,
        "actual_state_unchanged": unchanged,
        "before_state": before,
        "after_state": after,
        "exception": exception,
        "pass": passed,
    }


def _invalid_digest():
    value = _bundle()
    value["bundle_sha256"] = "0" * 64
    return _execute(value, source=value)


def _broken_top_level():
    class Broken(Mapping[str, Any]):
        def __getitem__(self, key: str) -> Any:
            raise RuntimeError("broken top-level mapping")
        def __iter__(self):
            raise RuntimeError("broken top-level mapping")
        def __len__(self) -> int:
            return 1
    return _execute(Broken(), source=_bundle())


def _stale_control():
    bundle = _bundle()
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    snapshot = build_trust_fixture_v2(bundle, evaluation_tick=5).snapshot
    envelope = seal_snapshot_envelope(snapshot, sequence=1, previous_envelope_sha256=None, issued_at=6, valid_until=200)
    before = _state(guard)
    result = AuthorityAnalysisSession(trust_guard=guard).validate(bundle, trust_envelope=envelope, trusted_evaluation_tick=6)
    return result, before, _state(guard)


def _malformed(mutation: Callable[[dict[str, Any]], None]):
    base = _bundle()
    value = deepcopy(base)
    mutation(value)
    return _execute(value, source=base)


def _cycle(value: dict[str, Any]) -> None:
    registry: dict[str, Any] = {}
    registry["self"] = registry
    value["provenance_registry"] = registry


def run_trigger() -> dict[str, Any]:
    materialization_codes = ["invalid_analysis_bundle_materialization"]
    rows = [
        _row(
            "SM30-P01", "Canonical exact bundle is accepted",
            scenario=lambda: _execute(_bundle(), source=_bundle()),
            expected_status="PASS", expected_reason="ANALYSIS_CONTRACT_VALID", expected_codes=[],
            expected_before_sequence=None, expected_after_sequence=1, expected_state_unchanged=False,
            positive_control=True,
        ),
        _row(
            "SM30-P02", "Invalid sealed digest blocks without an exception",
            scenario=_invalid_digest,
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=["digest_mismatch"],
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=True,
        ),
        _row(
            "SM30-P03", "Broken top-level mapping is already fail-closed",
            scenario=_broken_top_level,
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=True,
        ),
        _row(
            "SM30-P04", "Stale snapshot remains blocked before state mutation",
            scenario=_stale_control,
            expected_status="BLOCK", expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE", expected_codes=["stale_trust_snapshot_state"],
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=True,
        ),
        _row(
            "SM30-N01", "Set nested in provenance registry must not escape as TypeError",
            scenario=lambda: _malformed(lambda v: v.__setitem__("provenance_registry", {"records": {"bad"}})),
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=False,
        ),
        _row(
            "SM30-N02", "NaN nested in provenance registry must not escape as ValueError",
            scenario=lambda: _malformed(lambda v: v.__setitem__("provenance_registry", {"value": float("nan")})),
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=False,
        ),
        _row(
            "SM30-N03", "Bytes nested in provenance registry must not escape as TypeError",
            scenario=lambda: _malformed(lambda v: v.__setitem__("provenance_registry", {"value": b"bad"})),
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=False,
        ),
        _row(
            "SM30-N04", "Non-string nested key must not escape canonicalization",
            scenario=lambda: _malformed(lambda v: v.__setitem__("provenance_registry", {1: "bad"})),
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=False,
        ),
        _row(
            "SM30-N05", "Cyclic provenance registry must not escape as RecursionError",
            scenario=lambda: _malformed(_cycle),
            expected_status="BLOCK", expected_reason="BLOCKED_BY_ANALYSIS_CONTRACT", expected_codes=materialization_codes,
            expected_before_sequence=None, expected_after_sequence=None, expected_state_unchanged=True,
            positive_control=False,
        ),
    ]
    pass_count = sum(1 for row in rows if row["pass"])
    positive_count = sum(1 for row in rows if row["positive_control"])
    positive_pass = sum(1 for row in rows if row["positive_control"] and row["pass"])
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_count": len(rows),
        "pass_count": pass_count,
        "fail_count": len(rows) - pass_count,
        "positive_control_count": positive_count,
        "positive_control_pass_count": positive_pass,
        "status": "PASS" if pass_count == len(rows) else "FAIL",
        "rows_sha256": canonical_sha256(rows),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", type=Path)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()
    result = run_trigger()
    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True, exist_ok=True)
        args.jsonl.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in result["rows"]), encoding="utf-8")
    summary = {key: value for key, value in result.items() if key != "rows"}
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
