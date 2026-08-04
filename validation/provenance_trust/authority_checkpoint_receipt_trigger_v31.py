"""Post-product checkpoint-receipt trigger for exact recovered v2.37."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession
from triaxis.integrity import canonical_sha256
import triaxis.provenance_trust_state as trust_state
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5, reseal_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_RECEIPT_TRIGGER_v3.1_RECOVERY"
CANDIDATE_COMMIT = "1bbc5b7d5861856eee030544c44ee3ba2cf9fe78"
CANDIDATE_TREE = "dc1fb2ca3b5ed81cf3937df819dc676e19a4db9c"


def _bundle(tick: int) -> dict[str, Any]:
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


def _accepted_genesis():
    bundle = _bundle(5)
    envelope = _envelope(bundle, tick=5, sequence=1, parent=None)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        bundle, trust_envelope=envelope, trusted_evaluation_tick=5,
    )
    if result.get("status") != "PASS":
        raise AssertionError(result)
    return guard.checkpoint, envelope


def _accepted_successor():
    first = _bundle(5)
    first_envelope = _envelope(first, tick=5, sequence=1, parent=None)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    first_result = session.validate(first, trust_envelope=first_envelope, trusted_evaluation_tick=5)
    if first_result.get("status") != "PASS":
        raise AssertionError(first_result)
    second = _bundle(6)
    second_envelope = _envelope(
        second,
        tick=6,
        sequence=2,
        parent=first_envelope["envelope_sha256"],
    )
    second_result = session.validate(second, trust_envelope=second_envelope, trusted_evaluation_tick=6)
    if second_result.get("status") != "PASS":
        raise AssertionError(second_result)
    return guard.checkpoint, first_envelope, second_envelope


def _rejected_successor_preserves_receipt() -> bool:
    first = _bundle(5)
    first_envelope = _envelope(first, tick=5, sequence=1, parent=None)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    accepted = session.validate(first, trust_envelope=first_envelope, trusted_evaluation_tick=5)
    if accepted.get("status") != "PASS":
        return False
    before = guard.checkpoint.as_dict()
    invalid = _bundle(6)
    invalid["synthesis"]["rationale_claim_ids"] = ["D_ACTION_RISK"]
    invalid = reseal_analysis_bundle_v5(invalid)
    invalid_envelope = _envelope(
        invalid,
        tick=6,
        sequence=2,
        parent=first_envelope["envelope_sha256"],
    )
    rejected = session.validate(invalid, trust_envelope=invalid_envelope, trusted_evaluation_tick=6)
    return rejected.get("status") == "BLOCK" and guard.checkpoint.as_dict() == before


def _validator_result(receipt: Mapping[str, Any]) -> tuple[str, list[str]]:
    validator = getattr(trust_state, "validate_checkpoint_receipt", None)
    if not callable(validator):
        return "MISSING", ["checkpoint_receipt_validator_missing"]
    result = validator(receipt)
    codes = sorted({
        str(item.get("code"))
        for item in result.get("errors", [])
        if isinstance(item, Mapping)
    })
    return str(result.get("status")), codes


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
        and actual_codes == sorted(expected_codes)
        and exception is None
    )
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "family": "authority_checkpoint_receipt",
        "description": description,
        "positive_control": positive_control,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": actual_codes,
        "exception": exception,
        "pass": passed,
    }


def _bool_check(value: bool, code: str) -> tuple[str, list[str]]:
    return ("PASS", []) if value else ("FAIL", [code])


def run_trigger() -> dict[str, Any]:
    genesis, genesis_envelope = _accepted_genesis()
    successor, first_envelope, second_envelope = _accepted_successor()
    genesis_receipt = genesis.as_dict()
    successor_receipt = successor.as_dict()

    def untouched_validator():
        return _validator_result(genesis_receipt)

    def tampered_validator():
        tampered = deepcopy(genesis_receipt)
        tampered["sequence"] = 2
        return _validator_result(tampered)

    rows = [
        _row(
            "CR31-P01", "Genesis internal checkpoint retains sequence one and null parent",
            check=lambda: _bool_check(genesis.sequence == 1 and genesis.previous_envelope_sha256 is None, "internal_genesis_state_invalid"),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "CR31-P02", "Successor internal checkpoint retains the exact parent envelope digest",
            check=lambda: _bool_check(successor.sequence == 2 and successor.previous_envelope_sha256 == first_envelope["envelope_sha256"], "internal_parent_state_invalid"),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "CR31-P03", "Serialized receipt retains exact envelope and snapshot digests",
            check=lambda: _bool_check(
                genesis_receipt.get("envelope_sha256") == genesis_envelope["envelope_sha256"]
                and genesis_receipt.get("snapshot_sha256") == genesis_envelope["snapshot_sha256"],
                "serialized_digest_fields_invalid",
            ),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "CR31-P04", "Rejected successor preserves the exact prior serialized receipt",
            check=lambda: _bool_check(_rejected_successor_preserves_receipt(), "rejection_mutated_receipt"),
            expected_status="PASS", expected_codes=[], positive_control=True,
        ),
        _row(
            "CR31-N01", "Genesis receipt explicitly serializes null previous_envelope_sha256",
            check=lambda: _bool_check(
                "previous_envelope_sha256" in genesis_receipt and genesis_receipt["previous_envelope_sha256"] is None,
                "checkpoint_parent_missing",
            ),
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "CR31-N02", "Successor receipt serializes its exact parent envelope digest",
            check=lambda: _bool_check(
                successor_receipt.get("previous_envelope_sha256") == first_envelope["envelope_sha256"],
                "checkpoint_parent_missing",
            ),
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "CR31-N03", "Receipt carries a canonical 64-hex checkpoint_sha256",
            check=lambda: _bool_check(
                isinstance(genesis_receipt.get("checkpoint_sha256"), str)
                and len(genesis_receipt["checkpoint_sha256"]) == 64,
                "checkpoint_digest_missing",
            ),
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "CR31-N04", "Untouched receipt passes the exported receipt validator",
            check=untouched_validator,
            expected_status="PASS", expected_codes=[], positive_control=False,
        ),
        _row(
            "CR31-N05", "Tampering a receipt under the old digest is rejected",
            check=tampered_validator,
            expected_status="BLOCK", expected_codes=["checkpoint_receipt_digest_mismatch"], positive_control=False,
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
