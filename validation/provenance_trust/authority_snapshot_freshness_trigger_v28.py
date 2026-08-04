"""Post-commit snapshot-freshness trigger for exact TRIAXIS v2.34.

A host-anchored authority decision at tick T must not be authorized by a trust
snapshot whose own evaluation point is older than T.  Re-signing or keeping an
old snapshot envelope valid does not make omitted revocations/current trust
state observable.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)

PROTOCOL_ID = "TRIAXIS_AUTHORITY_SNAPSHOT_FRESHNESS_TRIGGER_v2.8_RECOVERY"
CANDIDATE_COMMIT = "fc364c61a8d7f8483b29fbb5bb82be3b80be7b29"
CANDIDATE_TREE = "303a85faae969cf48fbd1b4f1c45c537fb1e59b7"


def _bundle(tick: int) -> dict[str, Any]:
    return _bind(
        build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=tick),
        REVIEW_REF,
    )


def _state(guard: ProvenanceTrustStateGuard) -> dict[str, Any] | None:
    checkpoint = guard.checkpoint
    return None if checkpoint is None else checkpoint.as_dict()


def _codes(result: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(item.get("code"))
        for item in result.get("errors", [])
        if isinstance(item, Mapping)
    })


def _root():
    return build_snapshot_authority_root(valid_until=200)


def _envelope(
    snapshot_source: Mapping[str, Any],
    *,
    snapshot_tick: int,
    sequence: int,
    parent: str | None,
    issued_at: int,
) -> dict[str, Any]:
    snapshot = build_trust_fixture_v2(
        snapshot_source,
        evaluation_tick=snapshot_tick,
    ).snapshot
    return seal_snapshot_envelope(
        snapshot,
        sequence=sequence,
        previous_envelope_sha256=parent,
        issued_at=issued_at,
        valid_until=200,
    )


def _single(
    analysis_bundle: Mapping[str, Any],
    snapshot_source: Mapping[str, Any],
    *,
    snapshot_tick: int,
    issued_at: int,
    host_tick: int,
) -> tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    envelope = _envelope(
        snapshot_source,
        snapshot_tick=snapshot_tick,
        sequence=1,
        parent=None,
        issued_at=issued_at,
    )
    before = _state(guard)
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        analysis_bundle,
        trust_envelope=envelope,
        trusted_evaluation_tick=host_tick,
    )
    return result, before, _state(guard)


def _successor(
    second_bundle: Mapping[str, Any],
    second_snapshot_source: Mapping[str, Any],
    *,
    second_snapshot_tick: int,
    second_issued_at: int,
    second_host_tick: int,
) -> tuple[Mapping[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    first_bundle = _bundle(5)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    first = _envelope(
        first_bundle,
        snapshot_tick=5,
        sequence=1,
        parent=None,
        issued_at=5,
    )
    first_result = AuthorityAnalysisSession(trust_guard=guard).validate(
        first_bundle,
        trust_envelope=first,
        trusted_evaluation_tick=5,
    )
    if first_result.get("status") != "PASS":
        return first_result, None, _state(guard)
    before = _state(guard)
    second = _envelope(
        second_snapshot_source,
        snapshot_tick=second_snapshot_tick,
        sequence=2,
        parent=first["envelope_sha256"],
        issued_at=second_issued_at,
    )
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        second_bundle,
        trust_envelope=second,
        trusted_evaluation_tick=second_host_tick,
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
        status = str(result.get("status"))
        reason = str(result.get("primary_reason"))
        codes = _codes(result)
        exception = None
    except Exception as exc:  # pragma: no cover
        status = "EXCEPTION"
        reason = type(exc).__name__
        codes = []
        before = None
        after = None
        exception = f"{type(exc).__name__}: {exc}"
    before_sequence = before.get("sequence") if isinstance(before, dict) else None
    after_sequence = after.get("sequence") if isinstance(after, dict) else None
    unchanged = before == after
    passed = (
        status == expected_status
        and reason == expected_reason
        and codes == sorted(expected_codes)
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
        "family": "authority_snapshot_freshness",
        "description": description,
        "positive_control": positive_control,
        "expected_status": expected_status,
        "actual_status": status,
        "expected_primary_reason": expected_reason,
        "actual_primary_reason": reason,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": codes,
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
    bundle5 = _bundle(5)
    bundle6 = _bundle(6)
    bundle10 = _bundle(10)

    rows.append(_row(
        "SF28-P01",
        "A genesis snapshot evaluated at the exact host/bundle tick is accepted",
        scenario=lambda: _single(
            bundle5, bundle5, snapshot_tick=5, issued_at=5, host_tick=5,
        ),
        expected_status="PASS",
        expected_reason="ANALYSIS_CONTRACT_VALID",
        expected_codes=[],
        expected_before_sequence=None,
        expected_after_sequence=1,
        expected_state_unchanged=False,
        positive_control=True,
    ))
    rows.append(_row(
        "SF28-P02",
        "A successor snapshot evaluated at the exact new host/bundle tick is accepted",
        scenario=lambda: _successor(
            bundle6,
            bundle6,
            second_snapshot_tick=6,
            second_issued_at=6,
            second_host_tick=6,
        ),
        expected_status="PASS",
        expected_reason="ANALYSIS_CONTRACT_VALID",
        expected_codes=[],
        expected_before_sequence=1,
        expected_after_sequence=2,
        expected_state_unchanged=False,
        positive_control=True,
    ))
    rows.append(_row(
        "SF28-P03",
        "A snapshot evaluated after envelope issuance is rejected without state mutation",
        scenario=lambda: _single(
            bundle6, bundle6, snapshot_tick=7, issued_at=6, host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=["future_trust_snapshot_state"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=True,
    ))
    rows.append(_row(
        "SF28-P04",
        "A bundle/host tick mismatch is rejected before trust-state commitment",
        scenario=lambda: _single(
            bundle5, bundle5, snapshot_tick=5, issued_at=5, host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_AUTHORITY_TIME",
        expected_codes=["authority_evaluation_time_mismatch"],
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=True,
    ))

    stale_codes = ["stale_trust_snapshot_state"]
    rows.append(_row(
        "SF28-N01",
        "Re-signing a tick-5 snapshot at tick 6 must not authorize a tick-6 decision",
        scenario=lambda: _single(
            bundle6, bundle5, snapshot_tick=5, issued_at=6, host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=stale_codes,
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))
    rows.append(_row(
        "SF28-N02",
        "A still-valid old envelope cannot make a tick-5 snapshot current at tick 6",
        scenario=lambda: _single(
            bundle6, bundle5, snapshot_tick=5, issued_at=5, host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=stale_codes,
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))
    rows.append(_row(
        "SF28-N03",
        "A large host-time advance cannot reuse a tick-5 trust snapshot",
        scenario=lambda: _single(
            bundle10, bundle5, snapshot_tick=5, issued_at=10, host_tick=10,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=stale_codes,
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))
    rows.append(_row(
        "SF28-N04",
        "Even records generated from the tick-6 bundle are stale when snapshot time is tick 5",
        scenario=lambda: _single(
            bundle6, bundle6, snapshot_tick=5, issued_at=6, host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=stale_codes,
        expected_before_sequence=None,
        expected_after_sequence=None,
        expected_state_unchanged=True,
        positive_control=False,
    ))
    rows.append(_row(
        "SF28-N05",
        "A stale successor snapshot must not advance an accepted sequence-one checkpoint",
        scenario=lambda: _successor(
            bundle6,
            bundle6,
            second_snapshot_tick=5,
            second_issued_at=6,
            second_host_tick=6,
        ),
        expected_status="BLOCK",
        expected_reason="BLOCKED_BY_TRUST_SNAPSHOT_STATE",
        expected_codes=stale_codes,
        expected_before_sequence=1,
        expected_after_sequence=1,
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
