"""Post-product cross-database scope-binding trigger for exact v2.43-RC1."""
from __future__ import annotations

import argparse
import base64
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Mapping

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.integrity import canonical_json_bytes, canonical_sha256, materialize_json
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import (
    _AUTHORITY_ID,
    _KEY_ID,
    _PRIVATE_KEY,
    build_snapshot_authority_root,
    seal_snapshot_envelope,
)

PROTOCOL_ID = "TRIAXIS_AUTHORITY_CHECKPOINT_SCOPE_BINDING_TRIGGER_v3.8_RECOVERY"
CANDIDATE_COMMIT = "d231fc7303538a2e3138b6f422eb8da40671a4ee"
CANDIDATE_TREE = "24610f441e643a4229a0247e111a79d4d8b1eade"
SCOPE_CONTRACT = "TRIAXIS_CHECKPOINT_SCOPE_ENVELOPE_v1"
NAMESPACE_CONTRACT = "TRIAXIS_CHECKPOINT_NAMESPACE_v1"


def root() -> dict[str, Any]:
    return build_snapshot_authority_root(valid_until=200)


def namespace_sha256(namespace: str) -> str:
    return canonical_sha256({"contract_id": NAMESPACE_CONTRACT, "namespace": namespace})


def chain(label: str, tick: int = 5) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = _bind(
        build_valid_analysis_bundle_v5(
            run_id=f"scope-{label}-{tick}",
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


def seal_scope(
    *,
    namespace: str,
    receipt: Mapping[str, Any],
    envelope: Mapping[str, Any],
    issued_at: int = 5,
    valid_until: int = 200,
) -> dict[str, Any]:
    payload = {
        "contract_id": SCOPE_CONTRACT,
        "authority_id": _AUTHORITY_ID,
        "key_id": _KEY_ID,
        "namespace_sha256": namespace_sha256(namespace),
        "checkpoint_sha256": str(receipt["checkpoint_sha256"]),
        "envelope_sha256": str(envelope["envelope_sha256"]),
        "issued_at": issued_at,
        "valid_until": valid_until,
    }
    signature = _PRIVATE_KEY.sign(canonical_json_bytes(payload))
    return {
        **payload,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "scope_envelope_sha256": canonical_sha256(payload),
    }


def _commit_scoped(
    path: Path,
    namespace: str,
    receipt: dict[str, Any],
    envelope: dict[str, Any],
    scope_envelope: Mapping[str, Any] | None,
    *,
    expected_previous_head: str | None = None,
    tick: int = 5,
) -> str:
    with SQLiteCheckpointStore(path, namespace=namespace) as store:
        method = getattr(store, "commit_scoped", None)
        if callable(method):
            return method(
                checkpoint_receipt=receipt,
                trust_envelope=envelope,
                checkpoint_scope_envelope=scope_envelope,
                authority_roots=[root()],
                expected_previous_head=expected_previous_head,
                trusted_evaluation_tick=tick,
            )
        # Exact v2.43 fallback deliberately exposes absence of scoped enforcement.
        return store.commit(
            checkpoint_receipt=receipt,
            trust_envelope=envelope,
            authority_roots=[root()],
            expected_previous_head=expected_previous_head,
        )


def positive_valid_scope() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        head = _commit_scoped(Path(td) / "a.sqlite3", "tenant:A", receipt, envelope, scope)
        return ("PASS", []) if head == receipt["checkpoint_sha256"] else ("FAIL", ["head_mismatch"])


def positive_same_scope_two_databases() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        left = _commit_scoped(Path(td) / "left.sqlite3", "tenant:A", receipt, envelope, scope)
        right = _commit_scoped(Path(td) / "right.sqlite3", "tenant:A", receipt, envelope, scope)
        return ("PASS", []) if left == right else ("FAIL", ["same_scope_replica_mismatch"])


def positive_exact_retry() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        path = Path(td) / "a.sqlite3"
        first = _commit_scoped(path, "tenant:A", receipt, envelope, scope)
        second = _commit_scoped(path, "tenant:A", receipt, envelope, scope)
        return ("PASS", []) if first == second else ("FAIL", ["scoped_retry_failed"])


def positive_distinct_scopes() -> tuple[str, list[str]]:
    left_receipt, left_envelope = chain("A")
    right_receipt, right_envelope = chain("B")
    left_scope = seal_scope(namespace="tenant:A", receipt=left_receipt, envelope=left_envelope)
    right_scope = seal_scope(namespace="tenant:B", receipt=right_receipt, envelope=right_envelope)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        left = _commit_scoped(Path(td) / "left.sqlite3", "tenant:A", left_receipt, left_envelope, left_scope)
        right = _commit_scoped(Path(td) / "right.sqlite3", "tenant:B", right_receipt, right_envelope, right_scope)
        return ("PASS", []) if left != right else ("FAIL", ["distinct_scope_collision"])


def _capture(fn: Callable[[], Any]) -> tuple[str, list[str]]:
    try:
        fn()
    except CheckpointStoreError as exc:
        return "BLOCK", [exc.code]
    return "PASS", []


def negative_wrong_namespace() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        return _capture(lambda: _commit_scoped(Path(td) / "fresh.sqlite3", "tenant:B", receipt, envelope, scope))


def negative_subject_mismatch() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    other_receipt, _ = chain("B")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    scope = deepcopy(scope)
    scope["checkpoint_sha256"] = other_receipt["checkpoint_sha256"]
    payload = materialize_json(scope)
    payload.pop("signature_b64", None)
    payload.pop("scope_envelope_sha256", None)
    scope["scope_envelope_sha256"] = canonical_sha256(payload)
    scope["signature_b64"] = base64.b64encode(_PRIVATE_KEY.sign(canonical_json_bytes(payload))).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        return _capture(lambda: _commit_scoped(Path(td) / "fresh.sqlite3", "tenant:A", receipt, envelope, scope))


def negative_signature() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope)
    scope = deepcopy(scope)
    signature = bytearray(base64.b64decode(scope["signature_b64"]))
    signature[0] ^= 1
    scope["signature_b64"] = base64.b64encode(bytes(signature)).decode("ascii")
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        return _capture(lambda: _commit_scoped(Path(td) / "fresh.sqlite3", "tenant:A", receipt, envelope, scope))


def negative_expired() -> tuple[str, list[str]]:
    receipt, envelope = chain("A", tick=5)
    scope = seal_scope(namespace="tenant:A", receipt=receipt, envelope=envelope, issued_at=5, valid_until=5)
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        return _capture(lambda: _commit_scoped(Path(td) / "fresh.sqlite3", "tenant:A", receipt, envelope, scope, tick=6))


def negative_missing_scope() -> tuple[str, list[str]]:
    receipt, envelope = chain("A")
    with tempfile.TemporaryDirectory(prefix="triaxis-sb38-") as td:
        return _capture(lambda: _commit_scoped(Path(td) / "fresh.sqlite3", "tenant:A", receipt, envelope, None))


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
        "family": "checkpoint_scope_binding",
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
        row("SB38-P01", "Valid signed scope commits in its intended namespace", positive_valid_scope, "PASS", [], True),
        row("SB38-P02", "The same signed scope may be replicated under the same namespace", positive_same_scope_two_databases, "PASS", [], True),
        row("SB38-P03", "Exact scoped retry remains idempotent", positive_exact_retry, "PASS", [], True),
        row("SB38-P04", "Distinct checkpoints and scopes remain independent", positive_distinct_scopes, "PASS", [], True),
        row("SB38-N01", "A scope signed for tenant A cannot commit under tenant B", negative_wrong_namespace, "BLOCK", ["checkpoint_scope_namespace_mismatch"], False),
        row("SB38-N02", "Scope checkpoint subject must match the exact receipt", negative_subject_mismatch, "BLOCK", ["checkpoint_scope_subject_mismatch"], False),
        row("SB38-N03", "Tampered scope signature is rejected", negative_signature, "BLOCK", ["invalid_checkpoint_scope_signature"], False),
        row("SB38-N04", "Expired scope authorization is rejected at host time", negative_expired, "BLOCK", ["expired_checkpoint_scope_envelope"], False),
        row("SB38-N05", "Scoped ingress requires a scope envelope", negative_missing_scope, "BLOCK", ["checkpoint_scope_envelope_required"], False),
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
