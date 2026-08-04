"""Post-product subject-binding trigger for exact recovered TRIAXIS v2.35."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import (
    build_valid_analysis_bundle_v5,
    reseal_analysis_bundle_v5,
)
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)

PROTOCOL_ID = "TRIAXIS_AUTHORITY_SNAPSHOT_SUBJECT_BINDING_TRIGGER_v2.9_RECOVERY"
CANDIDATE_COMMIT = "ca779fdd9a91808470a3a338e9e7f0ab5a0bb361"
CANDIDATE_TREE = "4c5c60a9fd8aa5a84b0c532a7257060876fbcd21"


def _bundle(tick: int, *, run_id: str = "analysis-v5-recovery-001", goal: str | None = None) -> dict[str, Any]:
    value = _bind(
        build_valid_analysis_bundle_v5(
            control_profile="A3",
            evaluation_tick=tick,
            run_id=run_id,
        ),
        REVIEW_REF,
    )
    if goal is not None:
        value["frame"]["goal"] = goal
        value = reseal_analysis_bundle_v5(value)
    return value


def _root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def _state(guard: ProvenanceTrustStateGuard) -> dict[str, Any] | None:
    checkpoint = guard.checkpoint
    return None if checkpoint is None else checkpoint.as_dict()


def _codes(result: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(item.get("code"))
        for item in result.get("errors", [])
        if isinstance(item, Mapping)
    })


def _snapshot(source: Mapping[str, Any], tick: int) -> dict[str, Any]:
    return build_trust_fixture_v2(source, evaluation_tick=tick).snapshot


def _envelope(
    snapshot: Mapping[str, Any],
    *,
    sequence: int = 1,
    parent: str | None = None,
    issued_at: int,
) -> dict[str, Any]:
    return seal_snapshot_envelope(
        snapshot,
        sequence=sequence,
        previous_envelope_sha256=parent,
        issued_at=issued_at,
        valid_until=200,
    )


def _single(
    bundle: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    *,
    host_tick: int,
    issued_at: int,
) -> tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    envelope = _envelope(snapshot, issued_at=issued_at)
    before = _state(guard)
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        bundle,
        trust_envelope=envelope,
        trusted_evaluation_tick=host_tick,
    )
    return result, before, _state(guard)


def _successor(
    second_bundle: Mapping[str, Any],
    second_snapshot: Mapping[str, Any],
    *,
    second_tick: int,
) -> tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    first_bundle = _bundle(5)
    first_snapshot = _snapshot(first_bundle, 5)
    first_envelope = _envelope(first_snapshot, issued_at=5)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    accepted = session.validate(
        first_bundle,
        trust_envelope=first_envelope,
        trusted_evaluation_tick=5,
    )
    if accepted.get("status") != "PASS":
        return accepted, None, _state(guard)
    before = _state(guard)
    second_envelope = _envelope(
        second_snapshot,
        sequence=2,
        parent=first_envelope["envelope_sha256"],
        issued_at=second_tick,
    )
    result = session.validate(
        second_bundle,
        trust_envelope=second_envelope,
        trusted_evaluation_tick=second_tick,
    )
    return result, before, _state(guard)


def _row(
    case_id: str,
    description: str,
    *,
    scenario: Callable[[], tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]],
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
    except Exception as exc:  # pragma: no cover
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
        "family": "authority_snapshot_subject_binding",
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


def run_trigger() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    bundle6 = _bundle(6)

    rows.append(_row(
        "SB29-P01",
        "Exact bundle and provenance snapshot is accepted at the exact tick",
        scenario=lambda: _single(bundle6, _snapshot(bundle6, 6), host_tick=6, issued_at=6),
        expected_status="PASS",
        expected_reason="ANALYSIS_CONTRACT_VALID",
        expected_codes=[],
        expected_before_sequence=None,
        expected_after_sequence=1,
        expected_state_unchanged=False,
        positive_control=True,
    ))
    rows.append(_row(
        "SB29-P02",
        "Exact successor bundle and provenance snapshot advances sequence two",
        scenario=lambda: _successor(bundle6, _snapshot(bundle6, 6), second_tick=6),
        expected_status="PASS",
        expected_reason="ANALYSIS_CONTRACT_VALID",
        expected_codes=[],
        expected_before_sequence=1,
        expected_after_sequence=2,
        expected_state_unchanged=False,
        positive_control=True,
    ))
    rows.append(_row(
        "SB29-P03",
        "Stale but otherwise exact snapshot remains blocked by v2.35 freshness",
        scenario=lambda: _single(bundle6, _snapshot(bundle6, 5), host_tick=6, issued_at=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["stale_trust_snapshot_state"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=True,
    ))

    def signature_tamper():
        guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
        envelope = _envelope(_snapshot(bundle6, 6), issued_at=6)
        envelope["signature_b64"] = "AAAA"
        before = _state(guard)
        result = AuthorityAnalysisSession(trust_guard=guard).validate(
            bundle6,
            trust_envelope=envelope,
            trusted_evaluation_tick=6,
        )
        return result, before, _state(guard)

    rows.append(_row(
        "SB29-P04",
        "Signature tamper remains blocked without state mutation",
        scenario=signature_tamper,
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["invalid_snapshot_envelope_signature"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=True,
    ))

    other_run = _bundle(6, run_id="different-analysis-run")
    rows.append(_row(
        "SB29-N01",
        "Current-time snapshot from a different run cannot authorize this bundle",
        scenario=lambda: _single(bundle6, _snapshot(other_run, 6), host_tick=6, issued_at=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["trust_snapshot_bundle_binding_mismatch"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))

    original = _bundle(6)
    changed = _bundle(6, goal="Semantically changed decision object")
    rows.append(_row(
        "SB29-N02",
        "Snapshot issued before a valid semantic bundle mutation cannot be replayed",
        scenario=lambda: _single(changed, _snapshot(original, 6), host_tick=6, issued_at=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["trust_snapshot_bundle_binding_mismatch"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))

    arbitrary = deepcopy(_snapshot(bundle6, 6))
    arbitrary["source_bundle_sha256"] = "0" * 64
    rows.append(_row(
        "SB29-N03",
        "A correctly signed arbitrary source bundle digest is not sufficient",
        scenario=lambda: _single(bundle6, arbitrary, host_tick=6, issued_at=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["trust_snapshot_bundle_binding_mismatch"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))

    first_as_current = _snapshot(_bundle(5), 6)
    rows.append(_row(
        "SB29-N04",
        "A current-time successor snapshot cannot reuse the first bundle subject",
        scenario=lambda: _successor(bundle6, first_as_current, second_tick=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["trust_snapshot_bundle_binding_mismatch"],
        expected_before_sequence=1,
        expected_after_sequence=1,
        expected_state_unchanged=True,
        positive_control=False,
    ))

    wrong_registry = deepcopy(_snapshot(bundle6, 6))
    wrong_registry["trust_records_sha256"] = canonical_sha256({"records": []})
    rows.append(_row(
        "SB29-N05",
        "A snapshot bound to the bundle digest but a different provenance registry is rejected",
        scenario=lambda: _single(bundle6, wrong_registry, host_tick=6, issued_at=6),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["trust_snapshot_provenance_binding_mismatch"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))

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
        args.jsonl.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in result["rows"]),
            encoding="utf-8",
        )
    summary = {key: value for key, value in result.items() if key != "rows"}
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
