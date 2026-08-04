"""Post-product namespace-confinement trigger for exact TRIAXIS v2.41-RC2."""
from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_json_bytes, canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_NAMESPACE_CONFINEMENT_TRIGGER_v3.6_RECOVERY"
CANDIDATE_COMMIT = "113fc24457cdd70b6db5bb792509d09c4e039b36"
CANDIDATE_TREE = "0932cd6982cdace65728790004f9833f68ac6648"
ERROR = "checkpoint_store_namespace_replay"


def root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def chain(label: str, tick: int = 5) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _bind(
        build_valid_analysis_bundle_v5(
            run_id=f"namespace-{label}-{tick}",
            control_profile="A3",
            evaluation_tick=tick,
        ),
        REVIEW_REF,
    )
    envelope = seal_snapshot_envelope(
        build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot,
        sequence=1,
        previous_envelope_sha256=None,
        issued_at=tick,
        valid_until=200,
    )
    guard = ProvenanceTrustStateGuard(authority_roots=[root()])
    result = AuthorityAnalysisSession(trust_guard=guard).validate(
        bundle,
        trust_envelope=envelope,
        trusted_evaluation_tick=tick,
    )
    if result.get("status") != "PASS" or guard.checkpoint is None:
        raise AssertionError(result)
    return guard.checkpoint.as_dict(), envelope


def commit(path: Path, namespace: str, receipt: dict[str, Any], envelope: dict[str, Any]) -> str:
    with SQLiteCheckpointStore(path, namespace=namespace) as store:
        return store.commit(
            checkpoint_receipt=receipt,
            trust_envelope=envelope,
            authority_roots=[root()],
            expected_previous_head=None,
        )


def positive_single_namespace() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        head = commit(Path(td) / "state.sqlite3", "tenant:A", receipt, envelope)
        return ("PASS", []) if head == receipt["checkpoint_sha256"] else ("FAIL", ["head_mismatch"])


def positive_distinct_namespaces() -> tuple[str, list[str]]:
    left_receipt, left_envelope = chain("A")
    right_receipt, right_envelope = chain("B")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        left = commit(path, "tenant:A", left_receipt, left_envelope)
        right = commit(path, "tenant:B", right_receipt, right_envelope)
        ok = left != right
        return ("PASS", []) if ok else ("FAIL", ["distinct_namespace_heads_collided"])


def positive_exact_retry() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        first = commit(path, "tenant:A", receipt, envelope)
        second = commit(path, "tenant:A", receipt, envelope)
        with SQLiteCheckpointStore(path, namespace="tenant:A") as store:
            ok = first == second and len(store.history()) == 1
        return ("PASS", []) if ok else ("FAIL", ["same_namespace_retry_failed"])


def positive_read_isolation() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        commit(path, "tenant:A", receipt, envelope)
        with SQLiteCheckpointStore(path, namespace="tenant:B") as store:
            ok = store.get_current() is None and store.history() == []
        return ("PASS", []) if ok else ("FAIL", ["namespace_read_isolation_failed"])


def negative_replay_commit() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        commit(path, "tenant:A", receipt, envelope)
        try:
            commit(path, "tenant:B", receipt, envelope)
        except CheckpointStoreError as exc:
            return "BLOCK", [exc.code]
        return "PASS", []


def negative_concurrent_first_writer() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        barrier = threading.Barrier(2)
        outcomes: list[tuple[str, str | None]] = []
        lock = threading.Lock()

        def worker(namespace: str) -> None:
            try:
                barrier.wait(timeout=5)
                commit(path, namespace, receipt, envelope)
                outcome = ("PASS", None)
            except CheckpointStoreError as exc:
                outcome = ("BLOCK", exc.code)
            except Exception as exc:  # pragma: no cover - evidence capture
                outcome = ("EXCEPTION", type(exc).__name__)
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=worker, args=("tenant:A",)),
            threading.Thread(target=worker, args=("tenant:B",)),
        ]
        for item in threads:
            item.start()
        for item in threads:
            item.join(timeout=10)
        if len(outcomes) != 2:
            return "FAIL", ["concurrent_workers_incomplete"]
        passes = sum(status == "PASS" for status, _ in outcomes)
        blocks = [code for status, code in outcomes if status == "BLOCK"]
        if passes == 1 and blocks == [ERROR]:
            return "BLOCK", [ERROR]
        return "PASS", []


def _raw_copy(path: Path, *, include_history: bool) -> None:
    conn = sqlite3.connect(path)
    if include_history:
        conn.execute(
            "INSERT INTO checkpoint_history(namespace, sequence, checkpoint_sha256, receipt_json, envelope_json) "
            "SELECT ?, sequence, checkpoint_sha256, receipt_json, envelope_json "
            "FROM checkpoint_history WHERE namespace = ?",
            ("tenant:B", "tenant:A"),
        )
    conn.execute(
        "INSERT INTO checkpoint_current(namespace, head_sha256, sequence, receipt_json, envelope_json) "
        "SELECT ?, head_sha256, sequence, receipt_json, envelope_json "
        "FROM checkpoint_current WHERE namespace = ?",
        ("tenant:B", "tenant:A"),
    )
    conn.commit()
    conn.close()


def negative_raw_copy_current_and_history() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        commit(path, "tenant:A", receipt, envelope)
        _raw_copy(path, include_history=True)
        try:
            with SQLiteCheckpointStore(path, namespace="tenant:B") as store:
                store.get_current()
        except CheckpointStoreError as exc:
            return "BLOCK", [exc.code]
        return "PASS", []


def negative_raw_copy_current_only() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        commit(path, "tenant:A", receipt, envelope)
        _raw_copy(path, include_history=False)
        try:
            with SQLiteCheckpointStore(path, namespace="tenant:B") as store:
                store.get_current()
        except CheckpointStoreError as exc:
            return "BLOCK", [exc.code]
        return "PASS", []


def negative_ambiguous_legacy_database() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-ns36-") as td:
        path = Path(td) / "state.sqlite3"
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE checkpoint_current(namespace TEXT PRIMARY KEY, head_sha256 TEXT NOT NULL, "
            "sequence INTEGER NOT NULL, receipt_json BLOB NOT NULL, envelope_json BLOB NOT NULL) WITHOUT ROWID"
        )
        conn.execute(
            "CREATE TABLE checkpoint_history(namespace TEXT NOT NULL, sequence INTEGER NOT NULL, "
            "checkpoint_sha256 TEXT NOT NULL, receipt_json BLOB NOT NULL, envelope_json BLOB NOT NULL, "
            "PRIMARY KEY(namespace, sequence), UNIQUE(namespace, checkpoint_sha256)) WITHOUT ROWID"
        )
        conn.execute("PRAGMA user_version = 1")
        rb = canonical_json_bytes(receipt)
        eb = canonical_json_bytes(envelope)
        for namespace in ("tenant:A", "tenant:B"):
            conn.execute(
                "INSERT INTO checkpoint_current VALUES (?, ?, ?, ?, ?)",
                (namespace, receipt["checkpoint_sha256"], 1, rb, eb),
            )
            conn.execute(
                "INSERT INTO checkpoint_history VALUES (?, ?, ?, ?, ?)",
                (namespace, 1, receipt["checkpoint_sha256"], rb, eb),
            )
        conn.commit()
        conn.close()
        try:
            with SQLiteCheckpointStore(path, namespace="tenant:A"):
                pass
        except CheckpointStoreError as exc:
            return "BLOCK", [exc.code]
        return "PASS", []


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
    except Exception as exc:  # pragma: no cover - evidence capture
        actual_status, actual_codes = "EXCEPTION", []
        exception = f"{type(exc).__name__}: {exc}"
    result = {
        "protocol_id": PROTOCOL_ID,
        "candidate_commit": CANDIDATE_COMMIT,
        "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id,
        "family": "checkpoint_namespace_confinement",
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
        row("NS36-P01", "One checkpoint commits to its first namespace", positive_single_namespace, "PASS", [], True),
        row("NS36-P02", "Distinct checkpoint identities may occupy distinct namespaces", positive_distinct_namespaces, "PASS", [], True),
        row("NS36-P03", "Exact retry inside the same namespace stays idempotent", positive_exact_retry, "PASS", [], True),
        row("NS36-P04", "An unused namespace remains empty", positive_read_isolation, "PASS", [], True),
        row("NS36-N01", "Exact authenticated genesis cannot be replayed into another namespace", negative_replay_commit, "BLOCK", [ERROR], False),
        row("NS36-N02", "Concurrent cross-namespace first writers produce exactly one owner", negative_concurrent_first_writer, "BLOCK", [ERROR], False),
        row("NS36-N03", "Raw copied current and history rows are rejected on read", negative_raw_copy_current_and_history, "BLOCK", [ERROR], False),
        row("NS36-N04", "Raw copied current row is rejected on read", negative_raw_copy_current_only, "BLOCK", [ERROR], False),
        row("NS36-N05", "Ambiguous vulnerable schema cannot migrate silently", negative_ambiguous_legacy_database, "BLOCK", [ERROR], False),
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
