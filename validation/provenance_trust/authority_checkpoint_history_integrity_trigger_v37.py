"""Post-product immutable-history trigger for exact TRIAXIS v2.42-RC1."""
from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Callable

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_json_bytes, canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_HISTORY_INTEGRITY_TRIGGER_v3.7_RECOVERY"
CANDIDATE_COMMIT = "a85bd5cfd9268922f0cf1f9ef3bebff51dc490a4"
CANDIDATE_TREE = "796704b37cc4c6bf5b448146701eb4c055bdc4a9"
NAMESPACE = "tenant:history"


def root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def chain(label: str, ticks: tuple[int, ...] = (5, 6, 7)) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    guard = ProvenanceTrustStateGuard(authority_roots=[root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    parent = None
    for sequence, tick in enumerate(ticks, 1):
        bundle = _bind(
            build_valid_analysis_bundle_v5(
                run_id=f"history-{label}-{tick}",
                control_profile="A3",
                evaluation_tick=tick,
            ),
            REVIEW_REF,
        )
        envelope = seal_snapshot_envelope(
            build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot,
            sequence=sequence,
            previous_envelope_sha256=parent,
            issued_at=tick,
            valid_until=200,
        )
        outcome = session.validate(bundle, trust_envelope=envelope, trusted_evaluation_tick=tick)
        if outcome.get("status") != "PASS" or guard.checkpoint is None:
            raise AssertionError(outcome)
        result.append((guard.checkpoint.as_dict(), envelope))
        parent = envelope["envelope_sha256"]
    return result


def populate(path: Path, items: list[tuple[dict[str, Any], dict[str, Any]]], namespace: str = NAMESPACE) -> str:
    previous = None
    with SQLiteCheckpointStore(path, namespace=namespace) as store:
        for receipt, envelope in items:
            previous = store.commit(
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                authority_roots=[root()],
                expected_previous_head=previous,
            )
    if previous is None:
        raise AssertionError("empty chain")
    return previous


def load(path: Path, expected: str, namespace: str = NAMESPACE) -> tuple[str, list[str]]:
    try:
        with SQLiteCheckpointStore(path, namespace=namespace) as store:
            store.load_guard(authority_roots=[root()], expected_checkpoint_sha256=expected)
    except CheckpointStoreError as exc:
        return "BLOCK", [exc.code]
    return "PASS", []


def positive_intact_restore() -> tuple[str, list[str]]:
    items = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        head = populate(path, items)
        return load(path, head)


def positive_exact_history() -> tuple[str, list[str]]:
    items = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        populate(path, items)
        with SQLiteCheckpointStore(path, namespace=NAMESPACE) as store:
            observed = [row["receipt"]["sequence"] for row in store.history()]
        return ("PASS", []) if observed == [1, 2, 3] else ("FAIL", ["history_order_mismatch"])


def positive_exact_retry() -> tuple[str, list[str]]:
    items = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        head = populate(path, items)
        receipt, envelope = items[-1]
        with SQLiteCheckpointStore(path, namespace=NAMESPACE) as store:
            retried = store.commit(
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                authority_roots=[root()],
                expected_previous_head=items[-2][0]["checkpoint_sha256"],
            )
            count = len(store.history())
        return ("PASS", []) if retried == head and count == 3 else ("FAIL", ["exact_retry_changed_history"])


def positive_distinct_namespaces() -> tuple[str, list[str]]:
    left = chain("A", (5, 6))
    right = chain("B", (8, 9))
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        left_head = populate(path, left, "tenant:A")
        right_head = populate(path, right, "tenant:B")
        left_status, _ = load(path, left_head, "tenant:A")
        right_status, _ = load(path, right_head, "tenant:B")
        return ("PASS", []) if (left_status, right_status) == ("PASS", "PASS") else ("FAIL", ["distinct_history_restore_failed"])


def _delete_sequence(sequence: int) -> tuple[str, list[str]]:
    items = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        head = populate(path, items)
        conn = sqlite3.connect(path)
        conn.execute(
            "DELETE FROM checkpoint_history WHERE namespace = ? AND sequence = ?",
            (NAMESPACE, sequence),
        )
        conn.commit()
        conn.close()
        return load(path, head)


def negative_missing_genesis() -> tuple[str, list[str]]:
    return _delete_sequence(1)


def negative_missing_middle() -> tuple[str, list[str]]:
    return _delete_sequence(2)


def negative_missing_tip() -> tuple[str, list[str]]:
    return _delete_sequence(3)


def negative_current_behind_history() -> tuple[str, list[str]]:
    items = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        populate(path, items)
        receipt, envelope = items[1]
        conn = sqlite3.connect(path)
        conn.execute(
            "UPDATE checkpoint_current SET head_sha256 = ?, sequence = ?, receipt_json = ?, envelope_json = ? "
            "WHERE namespace = ?",
            (
                receipt["checkpoint_sha256"],
                receipt["sequence"],
                canonical_json_bytes(receipt),
                canonical_json_bytes(envelope),
                NAMESPACE,
            ),
        )
        conn.commit()
        conn.close()
        return load(path, receipt["checkpoint_sha256"])


def negative_parent_replacement() -> tuple[str, list[str]]:
    original = chain("A")
    alternate = chain("B")
    with tempfile.TemporaryDirectory(prefix="triaxis-hi37-") as td:
        path = Path(td) / "state.sqlite3"
        head = populate(path, original)
        replacement_receipt, replacement_envelope = alternate[1]
        original_middle = original[1][0]
        conn = sqlite3.connect(path)
        conn.execute(
            "DELETE FROM checkpoint_ownership WHERE checkpoint_sha256 = ?",
            (original_middle["checkpoint_sha256"],),
        )
        conn.execute(
            "UPDATE checkpoint_history SET checkpoint_sha256 = ?, receipt_json = ?, envelope_json = ? "
            "WHERE namespace = ? AND sequence = 2",
            (
                replacement_receipt["checkpoint_sha256"],
                canonical_json_bytes(replacement_receipt),
                canonical_json_bytes(replacement_envelope),
                NAMESPACE,
            ),
        )
        conn.execute(
            "INSERT INTO checkpoint_ownership(checkpoint_sha256, envelope_sha256, namespace, sequence) "
            "VALUES (?, ?, ?, ?)",
            (
                replacement_receipt["checkpoint_sha256"],
                replacement_receipt["envelope_sha256"],
                NAMESPACE,
                2,
            ),
        )
        conn.commit()
        conn.close()
        return load(path, head)


def row(
    case_id: str,
    description: str,
    fn: Callable[[], tuple[str, list[str]]],
    expected_status: str,
    expected_codes: list[str],
    positive_control: bool,
) -> dict[str, Any]:
    try:
        actual_status, actual_codes = fn()
        exception = None
    except Exception as exc:  # pragma: no cover
        actual_status, actual_codes = "EXCEPTION", []
        exception = f"{type(exc).__name__}: {exc}"
    result = {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "family": "checkpoint_history_integrity",
        "description": description,
        "positive_control": positive_control,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_error_codes": sorted(expected_codes),
        "actual_error_codes": sorted(actual_codes),
        "exception": exception,
    }
    result["pass"] = (
        actual_status == expected_status
        and sorted(actual_codes) == sorted(expected_codes)
        and exception is None
    )
    return result


def run_trigger() -> dict[str, Any]:
    rows = [
        row("HI37-P01", "Intact three-checkpoint history restores", positive_intact_restore, "PASS", [], True),
        row("HI37-P02", "Intact history exposes exact contiguous order", positive_exact_history, "PASS", [], True),
        row("HI37-P03", "Exact tip retry preserves three history rows", positive_exact_retry, "PASS", [], True),
        row("HI37-P04", "Distinct namespaces retain independent intact histories", positive_distinct_namespaces, "PASS", [], True),
        row("HI37-N01", "Missing genesis blocks restore", negative_missing_genesis, "BLOCK", ["checkpoint_store_history_incomplete"], False),
        row("HI37-N02", "Missing middle sequence blocks restore", negative_missing_middle, "BLOCK", ["checkpoint_store_history_incomplete"], False),
        row("HI37-N03", "Missing current-tip history row blocks restore", negative_missing_tip, "BLOCK", ["checkpoint_store_history_incomplete"], False),
        row("HI37-N04", "Current state behind retained history tip blocks restore", negative_current_behind_history, "BLOCK", ["checkpoint_store_current_not_history_tip"], False),
        row("HI37-N05", "Individually valid but foreign middle parent blocks restore", negative_parent_replacement, "BLOCK", ["checkpoint_store_history_chain_mismatch"], False),
    ]
    passed = sum(item["pass"] for item in rows)
    positive_count = sum(item["positive_control"] for item in rows)
    positive_passed = sum(item["positive_control"] and item["pass"] for item in rows)
    return {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_count": len(rows),
        "pass_count": passed,
        "fail_count": len(rows) - passed,
        "positive_control_count": positive_count,
        "positive_control_pass_count": positive_passed,
        "status": "PASS" if passed == len(rows) else "FAIL",
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
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in result["rows"]),
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
