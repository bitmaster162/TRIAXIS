from __future__ import annotations

import sqlite3
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from triaxis import AuthorityAnalysisSession, CheckpointStoreError, SQLiteCheckpointStore
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.authority_checkpoint_durability_trigger_v33 import run_trigger
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V240CheckpointStoreTests(unittest.TestCase):
    @staticmethod
    def _root() -> dict:
        return build_snapshot_authority_root(valid_until=200)

    @staticmethod
    def _bundle(tick: int, namespace: str = "unit") -> dict:
        return _bind(
            build_valid_analysis_bundle_v5(
                run_id=f"store-{namespace}-{tick}",
                control_profile="A3",
                evaluation_tick=tick,
            ),
            REVIEW_REF,
        )

    @classmethod
    def _envelope(cls, bundle: dict, tick: int, sequence: int, parent=None) -> dict:
        return seal_snapshot_envelope(
            build_trust_fixture_v2(bundle, evaluation_tick=tick).snapshot,
            sequence=sequence,
            previous_envelope_sha256=parent,
            issued_at=tick,
            valid_until=200,
        )

    @classmethod
    def _chain(cls):
        b1 = cls._bundle(5)
        e1 = cls._envelope(b1, 5, 1)
        guard = ProvenanceTrustStateGuard(authority_roots=[cls._root()])
        session = AuthorityAnalysisSession(trust_guard=guard)
        self_result = session.validate(b1, trust_envelope=e1, trusted_evaluation_tick=5)
        if self_result.get("status") != "PASS":
            raise AssertionError(self_result)
        c1 = guard.checkpoint.as_dict()
        b2 = cls._bundle(6)
        e2 = cls._envelope(b2, 6, 2, e1["envelope_sha256"])
        second_result = session.validate(b2, trust_envelope=e2, trusted_evaluation_tick=6)
        if second_result.get("status") != "PASS":
            raise AssertionError(second_result)
        return (c1, e1, guard.checkpoint.as_dict(), e2)

    def test_frozen_v33_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 10, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_namespace_isolation(self) -> None:
        c1, e1, _, _ = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            with SQLiteCheckpointStore(path, namespace="A") as left:
                left.commit(
                    checkpoint_receipt=c1,
                    trust_envelope=e1,
                    authority_roots=[self._root()],
                    expected_previous_head=None,
                )
            with SQLiteCheckpointStore(path, namespace="B") as right:
                self.assertIsNone(right.get_current())

    def test_invalid_pair_is_transactionally_state_neutral(self) -> None:
        c1, e1, c2, e2 = self._chain()
        with tempfile.TemporaryDirectory() as td, SQLiteCheckpointStore(Path(td) / "state.sqlite3", namespace="A") as store:
            store.commit(checkpoint_receipt=c1, trust_envelope=e1, authority_roots=[self._root()], expected_previous_head=None)
            before = store.get_current(); history_before = store.history()
            bad = deepcopy(c2); bad["sequence"] = 7
            with self.assertRaises(CheckpointStoreError) as caught:
                store.commit(checkpoint_receipt=bad, trust_envelope=e2, authority_roots=[self._root()], expected_previous_head=c1["checkpoint_sha256"])
            self.assertEqual(caught.exception.code, "checkpoint_receipt_digest_mismatch")
            self.assertEqual(store.get_current(), before)
            self.assertEqual(store.history(), history_before)

    def test_corrupt_canonical_bytes_are_detected(self) -> None:
        c1, e1, _, _ = self._chain()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state.sqlite3"
            store = SQLiteCheckpointStore(path, namespace="A")
            store.commit(checkpoint_receipt=c1, trust_envelope=e1, authority_roots=[self._root()], expected_previous_head=None)
            store.close()
            conn = sqlite3.connect(path)
            conn.execute("UPDATE checkpoint_current SET receipt_json = ? WHERE namespace = ?", (b'{"bad": true}', "A"))
            conn.commit(); conn.close()
            reopened = SQLiteCheckpointStore(path, namespace="A")
            with self.assertRaises(CheckpointStoreError) as caught:
                reopened.get_current()
            self.assertEqual(caught.exception.code, "checkpoint_store_corrupt_state")
            reopened.close()

    def test_closed_store_fails_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = SQLiteCheckpointStore(Path(td) / "state.sqlite3", namespace="A")
            store.close()
            with self.assertRaises(CheckpointStoreError) as caught:
                store.get_current()
            self.assertEqual(caught.exception.code, "checkpoint_store_closed")


if __name__ == "__main__":
    unittest.main()
