"""Post-product scope/history/current crash-atomicity trigger for exact v2.44."""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_sha256
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_scope_binding_trigger_v38 import seal_scope
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_SCOPE_ATOMICITY_TRIGGER_v3.9_RECOVERY"
CANDIDATE_COMMIT = "fe465aabde921b6c0b94d449114cf202cc0b24da"
CANDIDATE_TREE = "03a396c877e03be87a56ea2442f9e9a15a37d7f7"
NAMESPACE = "tenant:scope-atomicity"
EXIT_BY_POINT = {
    "after_scope": 81,
    "after_history": 82,
    "after_current": 83,
    "after_commit": 84,
}


def root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def chain() -> dict[str, Any]:
    guard = ProvenanceTrustStateGuard(authority_roots=[root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    result: dict[str, Any] = {}
    parent = None
    for sequence, tick in ((1, 5), (2, 6)):
        bundle = _bind(
            build_valid_analysis_bundle_v5(
                run_id=f"scope-atomicity-{sequence}",
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
        outcome = session.validate(
            bundle,
            trust_envelope=envelope,
            trusted_evaluation_tick=tick,
        )
        if outcome.get("status") != "PASS" or guard.checkpoint is None:
            raise AssertionError(outcome)
        receipt = guard.checkpoint.as_dict()
        scope = seal_scope(
            namespace=NAMESPACE,
            receipt=receipt,
            envelope=envelope,
            issued_at=tick,
            valid_until=200,
        )
        result[f"c{sequence}"] = receipt
        result[f"e{sequence}"] = envelope
        result[f"s{sequence}"] = scope
        parent = envelope["envelope_sha256"]
    return result


def commit_scoped(
    store: SQLiteCheckpointStore,
    receipt: dict[str, Any],
    envelope: dict[str, Any],
    scope: dict[str, Any],
    previous: str | None,
) -> str:
    return store.commit_scoped(
        checkpoint_receipt=receipt,
        trust_envelope=envelope,
        checkpoint_scope_envelope=scope,
        authority_roots=[root()],
        expected_previous_head=previous,
        trusted_evaluation_tick=int(receipt["evaluation_tick"]),
    )


class CrashProxy:
    def __init__(self, inner: sqlite3.Connection, point: str) -> None:
        self.inner = inner
        self.point = point

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        result = self.inner.execute(sql, params)
        normalized = " ".join(str(sql).split()).upper()
        hit = (
            (self.point == "after_scope" and normalized.startswith("INSERT INTO CHECKPOINT_SCOPE"))
            or (self.point == "after_history" and normalized.startswith("INSERT INTO CHECKPOINT_HISTORY"))
            or (
                self.point == "after_current"
                and (
                    normalized.startswith("INSERT INTO CHECKPOINT_CURRENT")
                    or normalized.startswith("UPDATE CHECKPOINT_CURRENT")
                )
            )
            or (self.point == "after_commit" and normalized == "COMMIT")
        )
        if hit:
            os._exit(EXIT_BY_POINT[self.point])
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)


def worker(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.chain).read_text(encoding="utf-8"))
    store = SQLiteCheckpointStore(args.database, namespace=NAMESPACE)
    store._conn = CrashProxy(store._conn, args.point)  # validation-only fault injection
    if args.mode == "genesis":
        commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
    else:
        commit_scoped(
            store,
            data["c2"],
            data["e2"],
            data["s2"],
            data["c1"]["checkpoint_sha256"],
        )
    return 99


def spawn(path: Path, chain_path: Path, mode: str, point: str) -> tuple[int, str, str]:
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            "--database",
            str(path),
            "--chain",
            str(chain_path),
            "--mode",
            mode,
            "--point",
            point,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH", "src:.")},
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def inspect_state(path: Path) -> dict[str, Any]:
    with SQLiteCheckpointStore(path, namespace=NAMESPACE) as store:
        current = store.get_current()
        history = store.history()
    conn = sqlite3.connect(path)
    scope_rows = conn.execute(
        "SELECT checkpoint_sha256, namespace, scope_envelope_sha256 "
        "FROM checkpoint_scope ORDER BY checkpoint_sha256"
    ).fetchall()
    conn.close()
    return {
        "current_sequence": None if current is None else current["receipt"]["sequence"],
        "history_sequences": [item["receipt"]["sequence"] for item in history],
        "scope_checkpoints": sorted(str(row[0]) for row in scope_rows),
        "scope_namespaces": sorted(str(row[1]) for row in scope_rows),
    }


def expected_state(data: dict[str, Any], level: str) -> dict[str, Any]:
    if level == "empty":
        return {
            "current_sequence": None,
            "history_sequences": [],
            "scope_checkpoints": [],
            "scope_namespaces": [],
        }
    if level == "genesis":
        return {
            "current_sequence": 1,
            "history_sequences": [1],
            "scope_checkpoints": [data["c1"]["checkpoint_sha256"]],
            "scope_namespaces": [NAMESPACE],
        }
    return {
        "current_sequence": 2,
        "history_sequences": [1, 2],
        "scope_checkpoints": sorted(
            [data["c1"]["checkpoint_sha256"], data["c2"]["checkpoint_sha256"]]
        ),
        "scope_namespaces": [NAMESPACE, NAMESPACE],
    }


def crash_case(mode: str, point: str, expected: str) -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        root_dir = Path(td)
        database = root_dir / "state.sqlite3"
        data = chain()
        chain_path = root_dir / "chain.json"
        chain_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        if mode == "successor":
            with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
                commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
        returncode, _, _ = spawn(database, chain_path, mode, point)
        if returncode != EXIT_BY_POINT[point]:
            return "FAIL", [f"unexpected_worker_exit_{returncode}"]
        observed = inspect_state(database)
        return (
            ("PASS", [])
            if observed == expected_state(data, expected)
            else ("FAIL", ["checkpoint_scope_atomicity_mixed_state"])
        )


def positive_normal_chain() -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        database = Path(td) / "state.sqlite3"
        data = chain()
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            first = commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
            second = commit_scoped(store, data["c2"], data["e2"], data["s2"], first)
        return ("PASS", []) if inspect_state(database) == expected_state(data, "successor") else ("FAIL", ["normal_scoped_chain_failed"])


def positive_restore() -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        database = Path(td) / "state.sqlite3"
        data = chain()
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            head = commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            guard = store.load_guard_scoped(
                authority_roots=[root()],
                expected_checkpoint_sha256=head,
                trusted_evaluation_tick=5,
            )
        return ("PASS", []) if guard.checkpoint.as_dict() == data["c1"] else ("FAIL", ["scoped_restore_failed"])


def positive_exact_retry() -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        database = Path(td) / "state.sqlite3"
        data = chain()
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            first = commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
            second = commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
        return ("PASS", []) if first == second and inspect_state(database) == expected_state(data, "genesis") else ("FAIL", ["scoped_retry_failed"])


def positive_expiry_block() -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        database = Path(td) / "state.sqlite3"
        data = chain()
        expired = dict(data["s1"])
        # Use the v3.8 sealing helper to produce a genuinely signed expired scope.
        expired = seal_scope(
            namespace=NAMESPACE,
            receipt=data["c1"],
            envelope=data["e1"],
            issued_at=5,
            valid_until=5,
        )
        try:
            with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
                store.commit_scoped(
                    checkpoint_receipt=data["c1"],
                    trust_envelope=data["e1"],
                    checkpoint_scope_envelope=expired,
                    authority_roots=[root()],
                    expected_previous_head=None,
                    trusted_evaluation_tick=6,
                )
        except CheckpointStoreError as exc:
            state = inspect_state(database)
            if exc.code == "expired_checkpoint_scope_envelope" and state == expected_state(data, "empty"):
                return "BLOCK", [exc.code]
            return "BLOCK", [exc.code, "expiry_block_mutated_state"]
        return "PASS", []


def after_commit_retry() -> tuple[str, list[str]]:
    with tempfile.TemporaryDirectory(prefix="triaxis-scope-atomicity-") as td:
        root_dir = Path(td)
        database = root_dir / "state.sqlite3"
        data = chain()
        chain_path = root_dir / "chain.json"
        chain_path.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            commit_scoped(store, data["c1"], data["e1"], data["s1"], None)
        returncode, _, _ = spawn(database, chain_path, "successor", "after_commit")
        if returncode != EXIT_BY_POINT["after_commit"]:
            return "FAIL", [f"unexpected_worker_exit_{returncode}"]
        with SQLiteCheckpointStore(database, namespace=NAMESPACE) as store:
            head = commit_scoped(
                store,
                data["c2"],
                data["e2"],
                data["s2"],
                data["c1"]["checkpoint_sha256"],
            )
        ok = head == data["c2"]["checkpoint_sha256"] and inspect_state(database) == expected_state(data, "successor")
        return ("PASS", []) if ok else ("FAIL", ["post_commit_scoped_retry_failed"])


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
        "family": "checkpoint_scope_atomicity",
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
        row("SA39-P01", "Normal scoped genesis and successor persist all three surfaces", positive_normal_chain, "PASS", [], True),
        row("SA39-P02", "Clean reopen authenticates scoped genesis", positive_restore, "PASS", [], True),
        row("SA39-P03", "Exact scoped retry remains idempotent", positive_exact_retry, "PASS", [], True),
        row("SA39-P04", "Expired scope blocks without durable mutation", positive_expiry_block, "BLOCK", ["expired_checkpoint_scope_envelope"], True),
        row("SA39-N01", "Genesis crash after scope insert recovers empty state", lambda: crash_case("genesis", "after_scope", "empty"), "PASS", [], False),
        row("SA39-N02", "Successor crash after scope insert recovers exact genesis", lambda: crash_case("successor", "after_scope", "genesis"), "PASS", [], False),
        row("SA39-N03", "Successor crash after history insert recovers exact genesis", lambda: crash_case("successor", "after_history", "genesis"), "PASS", [], False),
        row("SA39-N04", "Successor crash after current update recovers exact genesis", lambda: crash_case("successor", "after_current", "genesis"), "PASS", [], False),
        row("SA39-N05", "After-COMMIT loss reconciles exact scoped retry", after_commit_retry, "PASS", [], False),
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
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--database", type=Path)
    parser.add_argument("--chain", type=Path)
    parser.add_argument("--mode", choices=["genesis", "successor"])
    parser.add_argument("--point", choices=sorted(EXIT_BY_POINT))
    args = parser.parse_args()
    if args.worker:
        return worker(args)
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
