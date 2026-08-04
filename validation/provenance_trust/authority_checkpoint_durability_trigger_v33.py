"""Post-product durable checkpoint trigger for exact TRIAXIS v2.39."""

from __future__ import annotations

import argparse
import importlib
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession
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

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_DURABILITY_TRIGGER_v3.3_RECOVERY"
CANDIDATE_COMMIT = "3ae20af5e735128d3ea8e219e11d4d2c6e1893da"
CANDIDATE_TREE = "04a5e2458e010a92301e318d35f854ab38983219"
NAMESPACE = "triaxis:test:durability"


def _bundle(tick: int, *, run_id: str = "durability") -> dict[str, Any]:
    return _bind(
        build_valid_analysis_bundle_v5(
            run_id=f"{run_id}-{tick}",
            control_profile="A3",
            evaluation_tick=tick,
        ),
        REVIEW_REF,
    )


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


def _chain() -> dict[str, Any]:
    first = _bundle(5)
    e1 = _envelope(first, tick=5, sequence=1, parent=None)
    guard = ProvenanceTrustStateGuard(authority_roots=[_root()])
    session = AuthorityAnalysisSession(trust_guard=guard)
    r1 = session.validate(first, trust_envelope=e1, trusted_evaluation_tick=5)
    if r1.get("status") != "PASS":
        raise AssertionError(r1)
    c1 = guard.checkpoint.as_dict()

    second = _bundle(6)
    e2 = _envelope(second, tick=6, sequence=2, parent=e1["envelope_sha256"])
    r2 = session.validate(second, trust_envelope=e2, trusted_evaluation_tick=6)
    if r2.get("status") != "PASS":
        raise AssertionError(r2)
    c2 = guard.checkpoint.as_dict()
    return {"b1": first, "e1": e1, "c1": c1, "b2": second, "e2": e2, "c2": c2}


def _store_api():
    try:
        module = importlib.import_module("triaxis.checkpoint_store")
    except ModuleNotFoundError:
        return None, None
    return getattr(module, "SQLiteCheckpointStore", None), getattr(module, "CheckpointStoreError", None)


def _store_missing():
    return "MISSING", ["checkpoint_store_api_missing"]


def _store_error(exc: Exception, error_type: Any) -> tuple[str, list[str]]:
    if error_type is not None and isinstance(exc, error_type):
        return "BLOCK", [str(getattr(exc, "code", type(exc).__name__))]
    return "EXCEPTION", [type(exc).__name__]


def _commit(store: Any, chain: Mapping[str, Any], which: int, expected_previous_head: str | None):
    return store.commit(
        checkpoint_receipt=chain[f"c{which}"],
        trust_envelope=chain[f"e{which}"],
        authority_roots=[_root()],
        expected_previous_head=expected_previous_head,
    )


def _case_atomic_genesis(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, _ = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        store = store_cls(Path(td) / "state.sqlite3", namespace=NAMESPACE)
        head = _commit(store, chain, 1, None)
        current = store.get_current()
        ok = head == chain["c1"]["checkpoint_sha256"] and current["receipt"] == chain["c1"] and current["envelope"] == chain["e1"]
        return ("PASS", []) if ok else ("FAIL", ["durable_genesis_mismatch"])


def _case_reopen(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, _ = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        path = Path(td) / "state.sqlite3"
        first = store_cls(path, namespace=NAMESPACE)
        _commit(first, chain, 1, None)
        first.close()
        reopened = store_cls(path, namespace=NAMESPACE)
        guard = reopened.load_guard(
            authority_roots=[_root()],
            expected_checkpoint_sha256=chain["c1"]["checkpoint_sha256"],
        )
        return ("PASS", []) if guard.checkpoint.as_dict() == chain["c1"] else ("FAIL", ["durable_reopen_mismatch"])


def _case_stale_cas(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, error_type = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        path = Path(td) / "state.sqlite3"
        store = store_cls(path, namespace=NAMESPACE)
        _commit(store, chain, 1, None)
        before = store.get_current()
        try:
            _commit(store, chain, 2, "0" * 64)
        except Exception as exc:
            status, codes = _store_error(exc, error_type)
            after = store.get_current()
            if after != before: return "FAIL", ["stale_cas_mutated_state"]
            return status, codes
        return "PASS", []


def _case_successor_history(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, _ = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        store = store_cls(Path(td) / "state.sqlite3", namespace=NAMESPACE)
        _commit(store, chain, 1, None)
        head = _commit(store, chain, 2, chain["c1"]["checkpoint_sha256"])
        history = store.history()
        ok = head == chain["c2"]["checkpoint_sha256"] and [x["receipt"]["sequence"] for x in history] == [1, 2]
        return ("PASS", []) if ok else ("FAIL", ["durable_successor_history_mismatch"])


def _case_invalid_pair_state_neutral(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, error_type = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        store = store_cls(Path(td) / "state.sqlite3", namespace=NAMESPACE)
        _commit(store, chain, 1, None)
        before = store.get_current()
        history_before = store.history()
        tampered = deepcopy(chain["c2"])
        tampered["sequence"] = 3
        try:
            store.commit(
                checkpoint_receipt=tampered,
                trust_envelope=chain["e2"],
                authority_roots=[_root()],
                expected_previous_head=chain["c1"]["checkpoint_sha256"],
            )
        except Exception as exc:
            status, codes = _store_error(exc, error_type)
            if store.get_current() != before or store.history() != history_before:
                return "FAIL", ["invalid_pair_mutated_durable_state"]
            return status, codes
        return "PASS", []


def _case_load_anchor_mismatch(chain: Mapping[str, Any]) -> tuple[str, list[str]]:
    store_cls, error_type = _store_api()
    if not callable(store_cls): return _store_missing()
    with tempfile.TemporaryDirectory(prefix="triaxis-v33-") as td:
        store = store_cls(Path(td) / "state.sqlite3", namespace=NAMESPACE)
        _commit(store, chain, 1, None)
        try:
            store.load_guard(authority_roots=[_root()], expected_checkpoint_sha256="f" * 64)
        except Exception as exc:
            return _store_error(exc, error_type)
        return "PASS", []


def _row(case_id: str, description: str, *, check: Callable[[], tuple[str, list[str]]], expected_status: str, expected_codes: list[str], positive_control: bool) -> dict[str, Any]:
    try:
        actual_status, actual_codes = check(); exception = None
    except Exception as exc:  # pragma: no cover
        actual_status, actual_codes, exception = "EXCEPTION", [], f"{type(exc).__name__}: {exc}"
    passed = actual_status == expected_status and sorted(actual_codes) == sorted(expected_codes) and exception is None
    return {
        "protocol_id": PROTOCOL_ID, "candidate_commit": CANDIDATE_COMMIT, "candidate_tree": CANDIDATE_TREE,
        "case_id": case_id, "family": "authority_checkpoint_durability", "description": description,
        "positive_control": positive_control, "expected_status": expected_status, "actual_status": actual_status,
        "expected_error_codes": sorted(expected_codes), "actual_error_codes": sorted(actual_codes),
        "exception": exception, "pass": passed,
    }


def _bool(value: bool, code: str) -> tuple[str, list[str]]:
    return ("PASS", []) if value else ("FAIL", [code])


def run_trigger() -> dict[str, Any]:
    chain = _chain()
    def restore_ok():
        guard = ProvenanceTrustStateGuard.from_checkpoint(
            authority_roots=[_root()], checkpoint_receipt=chain["c1"], trust_envelope=chain["e1"],
            expected_checkpoint_sha256=chain["c1"]["checkpoint_sha256"],
        )
        return _bool(guard.checkpoint.as_dict() == chain["c1"], "restore_control_failed")
    def rollback_blocks():
        try:
            ProvenanceTrustStateGuard.from_checkpoint(
                authority_roots=[_root()], checkpoint_receipt=chain["c1"], trust_envelope=chain["e1"],
                expected_checkpoint_sha256=chain["c2"]["checkpoint_sha256"],
            )
        except TrustSnapshotStateError as exc:
            return "BLOCK", [exc.code]
        return "PASS", []
    rows = [
        _row("DS33-P01", "v2.39 exact checkpoint restore remains valid", check=restore_ok, expected_status="PASS", expected_codes=[], positive_control=True),
        _row("DS33-P02", "v2.39 external head mismatch remains blocked", check=rollback_blocks, expected_status="BLOCK", expected_codes=["checkpoint_restore_head_mismatch"], positive_control=True),
        _row("DS33-P03", "v2.39 genesis receipt remains sequence one", check=lambda: _bool(chain["c1"]["sequence"] == 1, "genesis_control_failed"), expected_status="PASS", expected_codes=[], positive_control=True),
        _row("DS33-P04", "v2.39 successor receipt retains the exact parent", check=lambda: _bool(chain["c2"]["previous_envelope_sha256"] == chain["e1"]["envelope_sha256"], "parent_control_failed"), expected_status="PASS", expected_codes=[], positive_control=True),
        _row("DS33-N01", "Genesis receipt, envelope and head commit atomically", check=lambda: _case_atomic_genesis(chain), expected_status="PASS", expected_codes=[], positive_control=False),
        _row("DS33-N02", "A clean reopen restores the exact durable head", check=lambda: _case_reopen(chain), expected_status="PASS", expected_codes=[], positive_control=False),
        _row("DS33-N03", "A stale compare-and-swap writer is rejected state-neutrally", check=lambda: _case_stale_cas(chain), expected_status="BLOCK", expected_codes=["checkpoint_store_cas_mismatch"], positive_control=False),
        _row("DS33-N04", "Exact successor commit appends immutable ordered history", check=lambda: _case_successor_history(chain), expected_status="PASS", expected_codes=[], positive_control=False),
        _row("DS33-N05", "Invalid pair rejection leaves head and history unchanged", check=lambda: _case_invalid_pair_state_neutral(chain), expected_status="BLOCK", expected_codes=["checkpoint_receipt_digest_mismatch"], positive_control=False),
        _row("DS33-N06", "Load requires the host expected-head anchor", check=lambda: _case_load_anchor_mismatch(chain), expected_status="BLOCK", expected_codes=["checkpoint_store_head_mismatch"], positive_control=False),
    ]
    passed=sum(1 for r in rows if r["pass"]); pc=sum(1 for r in rows if r["positive_control"]); pp=sum(1 for r in rows if r["positive_control"] and r["pass"])
    from triaxis.integrity import canonical_sha256
    return {"protocol_id":PROTOCOL_ID,"candidate_commit":CANDIDATE_COMMIT,"candidate_tree":CANDIDATE_TREE,"case_count":len(rows),"pass_count":passed,"fail_count":len(rows)-passed,"positive_control_count":pc,"positive_control_pass_count":pp,"status":"PASS" if passed==len(rows) else "FAIL","rows_sha256":canonical_sha256(rows),"rows":rows}


def main() -> int:
    ap=argparse.ArgumentParser();ap.add_argument("--jsonl",type=Path);ap.add_argument("--summary",type=Path);args=ap.parse_args();result=run_trigger()
    if args.jsonl:
        args.jsonl.parent.mkdir(parents=True,exist_ok=True);args.jsonl.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in result["rows"]),encoding="utf-8")
    summary={k:v for k,v in result.items() if k!="rows"}
    if args.summary:
        args.summary.parent.mkdir(parents=True,exist_ok=True);args.summary.write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps(summary,indent=2,sort_keys=True));return 0 if result["status"]=="PASS" else 1


if __name__ == "__main__": raise SystemExit(main())
