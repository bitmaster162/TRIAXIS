"""Post-product checkpoint restore trigger for exact TRIAXIS v2.38.

The trigger distinguishes a self-verifying receipt from authenticated restart
continuity.  A new process must bind the receipt to the exact signed envelope
and to a host-controlled expected-head digest before rehydrating monotonic state.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession, validate_checkpoint_receipt
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import (
    ProvenanceTrustStateGuard,
    TrustSnapshotStateError,
)
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_RESTORE_TRIGGER_v3.2_RECOVERY"
CANDIDATE_COMMIT = "c6f31e1d0797b2c2d067f80241011d4808e067f4"
CANDIDATE_TREE = "893cb92e8071d863a4b541f9c645c95e257798a3"


def _bundle(tick: int, *, run_id: str = "restore-run") -> dict[str, Any]:
    return _bind(
        build_valid_analysis_bundle_v5(
            control_profile="A3",
            evaluation_tick=tick,
            run_id=f"{run_id}-{tick}",
        ),
        REVIEW_REF,
    )


def _root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def _envelope(
    bundle: Mapping[str, Any],
    *,
    tick: int,
    sequence: int,
    parent: str | None,
) -> dict[str, Any]:
    snapshot = build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot
    return seal_snapshot_envelope(
        snapshot,
        sequence=sequence,
        previous_envelope_sha256=parent,
        issued_at=tick,
        valid_until=200,
    )


def _accepted_chain():
    first = _bundle(5)
    first_envelope = _envelope(first, tick=5, sequence=1, parent=None)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    first_result = session.validate(
        first,
        trust_envelope=first_envelope,
        trusted_evaluation_tick=5,
    )
    if first_result.get("status") != "PASS":
        raise AssertionError(first_result)
    first_receipt = guard.checkpoint.as_dict()

    second = _bundle(6)
    second_envelope = _envelope(
        second,
        tick=6,
        sequence=2,
        parent=first_envelope["envelope_sha256"],
    )
    second_result = session.validate(
        second,
        trust_envelope=second_envelope,
        trusted_evaluation_tick=6,
    )
    if second_result.get("status") != "PASS":
        raise AssertionError(second_result)
    second_receipt = guard.checkpoint.as_dict()
    return {
        "first_bundle": first,
        "first_envelope": first_envelope,
        "first_receipt": first_receipt,
        "second_bundle": second,
        "second_envelope": second_envelope,
        "second_receipt": second_receipt,
    }


def _codes(result: Mapping[str, Any]) -> list[str]:
    return sorted({
        str(item.get("code"))
        for item in result.get("errors", [])
        if isinstance(item, Mapping)
    })


def _restore(
    *,
    receipt: Mapping[str, Any],
    envelope: Mapping[str, Any],
    expected_head: str,
):
    method = getattr(ProvenanceTrustStateGuard, "from_checkpoint", None)
    if not callable(method):
        return "MISSING", ["checkpoint_restore_api_missing"], None
    try:
        guard = method(
            authority_roots=[_root()],
            checkpoint_receipt=receipt,
            trust_envelope=envelope,
            expected_checkpoint_sha256=expected_head,
        )
    except TrustSnapshotStateError as exc:
        return "BLOCK", [exc.code], None
    except Exception as exc:  # fail visibly; not a conformant block
        return "EXCEPTION", [type(exc).__name__], None
    return "PASS", [], guard


def _direct_replay_blocks(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    first = chain["first_bundle"]
    envelope = chain["first_envelope"]
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    accepted = session.validate(first, trust_envelope=envelope, trusted_evaluation_tick=5)
    if accepted.get("status") != "PASS":
        return "FAIL", ["genesis_not_accepted"]
    before = guard.checkpoint.as_dict()
    try:
        guard.accept(
            envelope,
            evaluation_tick=5,
            expected_bundle_sha256=first["bundle_sha256"],
            expected_trust_records_sha256=canonical_sha256(first["provenance_registry"]),
        )
    except TrustSnapshotStateError as exc:
        if guard.checkpoint.as_dict() != before:
            return "FAIL", ["replay_mutated_checkpoint"]
        return "BLOCK", [exc.code]
    return "PASS", []


def _restored_replay(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, codes, guard = _restore(
        receipt=chain["first_receipt"],
        envelope=chain["first_envelope"],
        expected_head=chain["first_receipt"]["checkpoint_sha256"],
    )
    if status != "PASS":
        return status, codes
    before = guard.checkpoint.as_dict()
    first = chain["first_bundle"]
    try:
        guard.accept(
            chain["first_envelope"],
            evaluation_tick=5,
            expected_bundle_sha256=first["bundle_sha256"],
            expected_trust_records_sha256=canonical_sha256(first["provenance_registry"]),
        )
    except TrustSnapshotStateError as exc:
        if guard.checkpoint.as_dict() != before:
            return "FAIL", ["restored_replay_mutated_checkpoint"]
        return "BLOCK", [exc.code]
    return "PASS", []


def _restored_successor(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    status, codes, guard = _restore(
        receipt=chain["first_receipt"],
        envelope=chain["first_envelope"],
        expected_head=chain["first_receipt"]["checkpoint_sha256"],
    )
    if status != "PASS":
        return status, codes
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        chain["second_bundle"],
        trust_envelope=chain["second_envelope"],
        trusted_evaluation_tick=6,
    )
    if result.get("status") != "PASS":
        return str(result.get("status")), _codes(result)
    if guard.checkpoint.as_dict() != chain["second_receipt"]:
        return "FAIL", ["restored_successor_receipt_mismatch"]
    return "PASS", []


def _row(
    case_id: str,
    description: str,
    *,
    check: Callable[[], tuple[str, list[str]]],
    expected_status: str,
    expected_codes: list[str],
    positive_control: bool,
) -> dict[str, Any]:
    try:
        actual_status, actual_codes = check()
        exception = None
    except Exception as exc:  # pragma: no cover
        actual_status = "EXCEPTION"
        actual_codes = []
        exception = f"{type(exc).__name__}: {exc}"
    passed = (
        actual_status == expected_status
        and sorted(actual_codes) == sorted(expected_codes)
        and exception is None
    )
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "family": "authority_checkpoint_restore",
        "description": description,
        "positive_control": positive_control,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": sorted(actual_codes),
        "exception": exception,
        "pass": passed,
    }


def _bool(value: bool, code: str) -> tuple[str, list[str]]:
    return ("PASS", []) if value else ("FAIL", [code])


def run_trigger() -> dict[str, Any]:
    chain = _accepted_chain()
    first_receipt = chain["first_receipt"]

    def exact_restore():
        status, codes, guard = _restore(
            receipt=first_receipt,
            envelope=chain["first_envelope"],
            expected_head=first_receipt["checkpoint_sha256"],
        )
        if status != "PASS":
            return status, codes
        return _bool(guard.checkpoint.as_dict() == first_receipt, "restored_checkpoint_mismatch")

    def tampered_receipt():
        receipt = deepcopy(first_receipt)
        receipt["sequence"] = 2
        status, codes, _ = _restore(
            receipt=receipt,
            envelope=chain["first_envelope"],
            expected_head=first_receipt["checkpoint_sha256"],
        )
        return status, codes

    def mismatched_envelope():
        alternate = _bundle(5, run_id="alternate-restore")
        alternate_envelope = _envelope(alternate, tick=5, sequence=1, parent=None)
        status, codes, _ = _restore(
            receipt=first_receipt,
            envelope=alternate_envelope,
            expected_head=first_receipt["checkpoint_sha256"],
        )
        return status, codes

    def stale_external_head():
        status, codes, _ = _restore(
            receipt=first_receipt,
            envelope=chain["first_envelope"],
            expected_head=chain["second_receipt"]["checkpoint_sha256"],
        )
        return status, codes

    rows = [
        _row(
            "RR32-P01", "In-process genesis commits an exact v3 checkpoint receipt",
            check=lambda: _bool(first_receipt["sequence"] == 1, "genesis_receipt_invalid"),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "RR32-P02", "In-process successor commits an exact parent-bound v3 receipt",
            check=lambda: _bool(
                chain["second_receipt"]["previous_envelope_sha256"]
                == chain["first_envelope"]["envelope_sha256"],
                "successor_receipt_parent_invalid",
            ),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "RR32-P03", "Untouched v3 receipt remains self-verifying",
            check=lambda: (
                str(validate_checkpoint_receipt(first_receipt).get("status")),
                _codes(validate_checkpoint_receipt(first_receipt)),
            ),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "RR32-P04", "Same-process replay remains blocked without checkpoint mutation",
            check=lambda: _direct_replay_blocks(chain),
            expected_status="BLOCK", expected_codes=["trust_snapshot_sequence_mismatch"], positive_control=True,
        ),
        _row(
            "RR32-N01", "Exact receipt, exact signed envelope and exact external head restore genesis",
            check=exact_restore,
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "RR32-N02", "A restored guard blocks replay of the restored head",
            check=lambda: _restored_replay(chain),
            expected_status="BLOCK", expected_codes=["trust_snapshot_sequence_mismatch"], positive_control=False,
        ),
        _row(
            "RR32-N03", "A restored guard accepts the exact authenticated successor",
            check=lambda: _restored_successor(chain),
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "RR32-N04", "Restore rejects a tampered receipt before state hydration",
            check=tampered_receipt,
            expected_status="BLOCK", expected_codes=["checkpoint_receipt_digest_mismatch"], positive_control=False,
        ),
        _row(
            "RR32-N05", "Restore rejects a valid receipt paired with another valid envelope",
            check=mismatched_envelope,
            expected_status="BLOCK", expected_codes=["checkpoint_restore_envelope_mismatch"], positive_control=False,
        ),
        _row(
            "RR32-N06", "A newer external expected-head anchor rejects rollback to an older valid pair",
            check=stale_external_head,
            expected_status="BLOCK", expected_codes=["checkpoint_restore_head_mismatch"], positive_control=False,
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
